package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/larrykoo711/rax-cli/internal/azure"
)

const maxRetainedLogFiles = 30

// LogEntry is a single secret-redacted NDJSON telemetry record written to the local rax-cli run log.
type LogEntry struct {
	Timestamp         string `json:"ts"`
	Level             string `json:"level"` // "info" | "warn" | "error"
	RunID             string `json:"runId"`
	Command           string `json:"command"`
	Version           string `json:"version,omitempty"`
	Commit            string `json:"commit,omitempty"`
	Event             string `json:"event"`
	Step              string `json:"step,omitempty"`
	Completed         int    `json:"completed,omitempty"`
	Total             int    `json:"total,omitempty"`
	Pending           int    `json:"pending,omitempty"`
	Attempt           int    `json:"attempt,omitempty"`
	MaxAttempts       int    `json:"maxAttempts,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RetryAfterSeconds int    `json:"retryAfterSeconds,omitempty"`
	ErrorCode         string `json:"errorCode,omitempty"`
	TimeoutKind       string `json:"timeoutKind,omitempty"`
	SecretCreated     *bool  `json:"secretCreated,omitempty"`
	ExitCode          *int   `json:"exitCode,omitempty"`
	DurationMs        int64  `json:"durationMs,omitempty"`
	Message           string `json:"message,omitempty"`
}

// RunLogSummary summarizes a recorded run file for `rax logs list`.
type RunLogSummary struct {
	RunID      string `json:"runId"`
	Path       string `json:"path"`
	Command    string `json:"command"`
	Version    string `json:"version"`
	StartedAt  string `json:"startedAt"`
	Status     string `json:"status"` // "ok" | "failed" | "incomplete"
	ExitCode   int    `json:"exitCode"`
	ErrorCode  string `json:"errorCode,omitempty"`
	DurationMs int64  `json:"durationMs,omitempty"`
	Events     int    `json:"events"`
}

// RunRecorder appends redacted NDJSON diagnostic events to a per-run file (0600).
type RunRecorder struct {
	mu        sync.Mutex
	runID     string
	command   string
	version   string
	commit    string
	path      string
	file      *os.File
	startedAt time.Time
}

var (
	reBearer      = regexp.MustCompile(`(?i)Bearer\s+[A-Za-z0-9\-._~+/]+=*`)
	reJWT         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	reSecretKV    = regexp.MustCompile(`(?i)(client_secret|clientSecret|secretText|access_token|refresh_token|id_token|device_code|user_code|password)["']?\s*[:=]\s*["']?[^\s"',&}]+`)
	reEmail       = regexp.MustCompile(`([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})`)
	reSubPathGUID = regexp.MustCompile(`(?i)(/subscriptions/)([0-9a-f]{8})-([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`)
)

// RedactSensitive scrubs bearer tokens, JWTs, OAuth/client secrets, and local-parts of emails
// so diagnostic logs can be safely shared with maintainers without leaking credentials.
func RedactSensitive(raw string) string {
	s := reBearer.ReplaceAllString(raw, "Bearer <REDACTED>")
	s = reJWT.ReplaceAllString(s, "<REDACTED_JWT>")
	s = reSecretKV.ReplaceAllString(s, "$1=<REDACTED>")
	s = reEmail.ReplaceAllString(s, "***@$2")
	s = reSubPathGUID.ReplaceAllString(s, "${1}${2}-****")
	return s
}

// LogsDir returns the canonical per-user directory for rax-cli diagnostic run logs.
func LogsDir() string {
	if custom := strings.TrimSpace(os.Getenv("RAX_LOG_DIR")); custom != "" {
		return custom
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		if runtime.GOOS == "darwin" {
			return filepath.Join(home, "Library", "Logs", "rax-cli")
		}
		if xdg := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); xdg != "" {
			return filepath.Join(xdg, "rax-cli", "logs")
		}
		return filepath.Join(home, ".local", "state", "rax-cli", "logs")
	}
	return filepath.Join(os.TempDir(), "rax-cli-logs")
}

// StartRunRecorder creates a chmod-0600 per-run log file and prunes older runs beyond maxRetainedLogFiles.
func (a App) StartRunRecorder(command string) *RunRecorder {
	if flag.Lookup("test.v") != nil && strings.TrimSpace(os.Getenv("RAX_LOG_DIR")) == "" {
		// Avoid polluting the developer's home log directory during `go test`.
		return nil
	}
	now := time.Now().UTC()
	dir := LogsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil
	}
	safeCmd := strings.NewReplacer(" ", "-", "/", "-", ":", "-").Replace(strings.TrimSpace(command))
	if safeCmd == "" {
		safeCmd = "run"
	}
	runID := fmt.Sprintf("%s-%s", now.Format("20060102-150405"), safeCmd)
	logPath := filepath.Join(dir, "run-"+runID+".jsonl")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil
	}
	_ = os.Chmod(logPath, 0o600)
	pruneOldLogs(dir, maxRetainedLogFiles)

	rec := &RunRecorder{
		runID:     runID,
		command:   command,
		version:   strings.TrimPrefix(a.Version, "v"),
		commit:    a.Commit,
		path:      logPath,
		file:      f,
		startedAt: now,
	}
	rec.Record(LogEntry{
		Level:   "info",
		Event:   "start",
		Message: fmt.Sprintf("rax %s (%s, %s/%s) started %s", rec.version, rec.commit, runtime.GOOS, runtime.GOARCH, command),
	})
	return rec
}

func (r *RunRecorder) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

func (r *RunRecorder) Record(entry LogEntry) {
	if r == nil || r.file == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if entry.Level == "" {
		entry.Level = "info"
	}
	entry.RunID = r.runID
	entry.Command = r.command
	entry.Version = r.version
	entry.Commit = r.commit
	entry.Message = RedactSensitive(entry.Message)
	entry.Reason = RedactSensitive(entry.Reason)

	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = r.file.Write(append(raw, '\n'))
}

func (r *RunRecorder) Finish(exitCode int, errorCode, timeoutKind, message string, completed, total, pending int, secretCreated *bool) {
	if r == nil || r.file == nil {
		return
	}
	level := "info"
	if exitCode != 0 {
		level = "error"
	}
	ec := exitCode
	r.Record(LogEntry{
		Level:         level,
		Event:         "finish",
		Completed:     completed,
		Total:         total,
		Pending:       pending,
		ErrorCode:     errorCode,
		TimeoutKind:   timeoutKind,
		SecretCreated: secretCreated,
		ExitCode:      &ec,
		DurationMs:    time.Since(r.startedAt).Milliseconds(),
		Message:       message,
	})
	r.mu.Lock()
	_ = r.file.Close()
	r.file = nil
	r.mu.Unlock()
}

func pruneOldLogs(dir string, keep int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "run-") && strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, e.Name())
		}
	}
	if len(files) <= keep {
		return
	}
	sort.Strings(files)
	for _, old := range files[:len(files)-keep] {
		_ = os.Remove(filepath.Join(dir, old))
	}
}

func listRunLogs(dir string) ([]RunLogSummary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []RunLogSummary{}, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "run-") && strings.HasSuffix(e.Name(), ".jsonl") {
			names = append(names, e.Name())
		}
	}
	// Newest first
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	out := make([]RunLogSummary, 0, len(names))
	for _, name := range names {
		full := filepath.Join(dir, name)
		entries, err := readRunLogEntries(full)
		if err != nil || len(entries) == 0 {
			continue
		}
		first := entries[0]
		sum := RunLogSummary{
			RunID:     first.RunID,
			Path:      full,
			Command:   first.Command,
			Version:   first.Version,
			StartedAt: first.Timestamp,
			Status:    "incomplete",
			Events:    len(entries),
		}
		last := entries[len(entries)-1]
		if last.ExitCode != nil {
			sum.ExitCode = *last.ExitCode
			sum.DurationMs = last.DurationMs
			sum.ErrorCode = last.ErrorCode
			if *last.ExitCode == 0 {
				sum.Status = "ok"
			} else {
				sum.Status = "failed"
			}
		}
		out = append(out, sum)
	}
	return out, nil
}

func readRunLogEntries(path string) ([]LogEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []LogEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err == nil {
			out = append(out, entry)
		}
	}
	return out, scanner.Err()
}

func (a App) runLogs(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(a.Stdout, `Usage:
  rax logs <subcommand> [flags]

Subcommands:
  path      Print local diagnostic log directory and latest run log path
  list      List recent redacted rax-cli runs
  show      Display redacted timeline entries from the latest (or specified) run
  bundle    Package recent redacted logs + network preflight into a shareable ~/Downloads/rax-cli/ report
`)
		return ExitOK
	}

	switch args[0] {
	case "path":
		return a.runLogsPath(args[1:])
	case "list":
		return a.runLogsList(args[1:])
	case "show":
		return a.runLogsShow(args[1:])
	case "bundle", "export":
		return a.runLogsBundle(ctx, args[1:])
	default:
		fmt.Fprintf(a.Stderr, "Error: unknown logs subcommand %q\n", args[0])
		return ExitInvalidArg
	}
}

func (a App) runLogsPath(args []string) int {
	asJSON := false
	for _, arg := range args {
		if arg == "--json" || arg == "--agent" {
			asJSON = true
		}
	}
	dir := LogsDir()
	runs, _ := listRunLogs(dir)
	latest := ""
	if len(runs) > 0 {
		latest = runs[0].Path
	}
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":     true,
			"dir":    dir,
			"latest": latest,
			"count":  len(runs),
		})
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "Log dir: %s\n", dir)
	if latest != "" {
		fmt.Fprintf(a.Stdout, "Latest:  %s\n", latest)
	}
	return ExitOK
}

func (a App) runLogsList(args []string) int {
	fs := flag.NewFlagSet("rax logs list", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var (
		limit  int
		asJSON bool
	)
	fs.IntVar(&limit, "limit", 15, "Maximum runs to list")
	fs.BoolVar(&asJSON, "json", os.Getenv("RAX_AGENT") == "1", "Print JSON output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}
	runs, err := listRunLogs(LogsDir())
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error: list logs: %v\n", err)
		return ExitError
	}
	if limit > 0 && len(runs) > limit {
		runs = runs[:limit]
	}
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":   true,
			"dir":  LogsDir(),
			"runs": runs,
		})
		return ExitOK
	}
	if len(runs) == 0 {
		fmt.Fprintf(a.Stdout, "No diagnostic run logs found in %s\n", LogsDir())
		return ExitOK
	}
	for _, r := range runs {
		fmt.Fprintf(a.Stdout, "%-28s  %-10s  %-14s  %6dms  %s\n", r.RunID, r.Status, r.Command, r.DurationMs, r.ErrorCode)
	}
	return ExitOK
}

func (a App) runLogsShow(args []string) int {
	fs := flag.NewFlagSet("rax logs show", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var (
		runID  string
		tail   int
		asJSON bool
	)
	fs.StringVar(&runID, "run", "", "Specific run ID (defaults to latest)")
	fs.IntVar(&tail, "tail", 100, "Maximum trailing entries to print")
	fs.BoolVar(&asJSON, "json", os.Getenv("RAX_AGENT") == "1", "Print JSON output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}
	runs, err := listRunLogs(LogsDir())
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error: read logs: %v\n", err)
		return ExitError
	}
	if len(runs) == 0 {
		if asJSON {
			_ = json.NewEncoder(a.Stdout).Encode(map[string]any{"ok": true, "entries": []LogEntry{}})
		} else {
			fmt.Fprintf(a.Stdout, "No run logs found.\n")
		}
		return ExitOK
	}
	target := runs[0]
	if strings.TrimSpace(runID) != "" {
		found := false
		for _, r := range runs {
			if r.RunID == strings.TrimSpace(runID) {
				target = r
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(a.Stderr, "Error: run %q not found\n", runID)
			return ExitInvalidArg
		}
	}
	entries, err := readRunLogEntries(target.Path)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error: read %s: %v\n", target.Path, err)
		return ExitError
	}
	if tail > 0 && len(entries) > tail {
		entries = entries[len(entries)-tail:]
	}
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":      true,
			"run":     target,
			"entries": entries,
		})
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "Run %s (%s, status=%s)\n", target.RunID, target.Command, target.Status)
	for _, e := range entries {
		fmt.Fprintf(a.Stdout, "  %s [%-5s] %-10s %s\n", e.Timestamp, e.Level, e.Event, e.Message)
	}
	return ExitOK
}

func (a App) runLogsBundle(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax logs bundle", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var (
		outPath  string
		maxRuns  int
		noDoctor bool
		asJSON   bool
	)
	fs.StringVar(&outPath, "output", "", "Optional output path (defaults to ~/Downloads/rax-cli/rax-diagnostic-<timestamp>.log)")
	fs.IntVar(&maxRuns, "runs", 3, "Number of most recent runs to include")
	fs.BoolVar(&noDoctor, "no-doctor", false, "Skip live Microsoft endpoint reachability probes")
	fs.BoolVar(&asJSON, "json", os.Getenv("RAX_AGENT") == "1", "Print JSON output")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}
	if maxRuns <= 0 {
		maxRuns = 3
	}

	now := time.Now().UTC()
	runs, _ := listRunLogs(LogsDir())
	if len(runs) > maxRuns {
		runs = runs[:maxRuns]
	}

	type doctorCheck struct {
		Name      string `json:"name"`
		OK        bool   `json:"ok"`
		Status    int    `json:"status,omitempty"`
		LatencyMs int64  `json:"latencyMs"`
		Error     string `json:"error,omitempty"`
	}
	var checks []doctorCheck
	doctorOK := true
	if !noDoctor {
		endpoints := []struct {
			Name string
			URL  string
		}{
			{"entra_login", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"},
			{"microsoft_graph", "https://graph.microsoft.com/v1.0/$metadata"},
			{"azure_arm", "https://management.azure.com/metadata/endpoints?api-version=2022-09-01"},
		}
		client := &http.Client{Timeout: 8 * time.Second}
		for _, ep := range endpoints {
			start := time.Now()
			req, _ := http.NewRequestWithContext(ctx, http.MethodHead, ep.URL, nil)
			resp, err := client.Do(req)
			if err != nil {
				reqGet, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
				resp, err = client.Do(reqGet)
			}
			lat := time.Since(start).Milliseconds()
			if err != nil {
				doctorOK = false
				checks = append(checks, doctorCheck{Name: ep.Name, OK: false, LatencyMs: lat, Error: RedactSensitive(err.Error())})
				continue
			}
			resp.Body.Close()
			ok := resp.StatusCode >= 200 && resp.StatusCode < 500
			if !ok {
				doctorOK = false
			}
			checks = append(checks, doctorCheck{Name: ep.Name, OK: ok, Status: resp.StatusCode, LatencyMs: lat})
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Rax CLI Diagnostic Bundle (redacted — zero secrets/tokens/device codes)\n")
	fmt.Fprintf(&b, "Generated: %s\n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "CLI:       rax %s (%s, %s, %s/%s)\n", strings.TrimPrefix(a.Version, "v"), a.Commit, a.Date, runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "Log Dir:   %s\n\n", LogsDir())

	if !noDoctor {
		fmt.Fprintf(&b, "CONNECTIVITY PROBES (ok=%v)\n", doctorOK)
		for _, c := range checks {
			status := "OK"
			if !c.OK {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "  [%s] %-16s HTTP=%d (%dms)", status, c.Name, c.Status, c.LatencyMs)
			if c.Error != "" {
				fmt.Fprintf(&b, " err=%s", c.Error)
			}
			b.WriteByte('\n')
		}
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "RECENT RUNS (%d included)\n", len(runs))
	if len(runs) == 0 {
		fmt.Fprintf(&b, "  (no local run logs recorded yet)\n")
	}
	for _, r := range runs {
		fmt.Fprintf(&b, "\n--- RUN %s | cmd=%s | status=%s | exit=%d | duration=%dms | err=%s ---\n",
			r.RunID, r.Command, r.Status, r.ExitCode, r.DurationMs, r.ErrorCode)
		entries, _ := readRunLogEntries(r.Path)
		for _, e := range entries {
			extra := ""
			if e.Total > 0 {
				extra += fmt.Sprintf(" progress=%d/%d", e.Completed, e.Total)
			}
			if e.Attempt > 0 {
				extra += fmt.Sprintf(" retry=%d/%d(%s)", e.Attempt, e.MaxAttempts, e.Reason)
			}
			if e.TimeoutKind != "" {
				extra += fmt.Sprintf(" timeout=%s", e.TimeoutKind)
			}
			if e.SecretCreated != nil {
				extra += fmt.Sprintf(" secretCreated=%v", *e.SecretCreated)
			}
			fmt.Fprintf(&b, "  %s [%-5s] %-9s %-4s%s %s\n", e.Timestamp, e.Level, e.Event, e.Step, extra, RedactSensitive(e.Message))
		}
	}

	dest := strings.TrimSpace(outPath)
	if dest == "" {
		dest = filepath.Join(azure.DefaultBundleDir(), fmt.Sprintf("rax-diagnostic-%s.log", now.Format("20060102-150405")))
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		fmt.Fprintf(a.Stderr, "Error: create diagnostic directory: %v\n", err)
		return ExitError
	}
	if err := os.WriteFile(dest, []byte(b.String()), 0o600); err != nil {
		fmt.Fprintf(a.Stderr, "Error: write diagnostic bundle: %v\n", err)
		return ExitError
	}
	_ = os.Chmod(dest, 0o600)

	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":           true,
			"bundlePath":   dest,
			"runsIncluded": len(runs),
			"doctorOk":     doctorOK,
			"redacted":     true,
		})
		return ExitOK
	}
	fmt.Fprintf(a.Stdout, "Redacted diagnostic bundle saved to:\n  %s\n\nYou can safely share this file with the Rax team (contains zero secrets, tokens, or device codes).\n", dest)
	return ExitOK
}
