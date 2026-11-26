package cli

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	releaseRepo         = "larrykoo711/rax-cli"
	autoUpdateCheckTTL  = 6 * time.Hour
	autoUpdateCheckWait = 2 * time.Second
)

type ghRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

type updateCheckCache struct {
	CheckedAt     time.Time `json:"checkedAt"`
	LatestVersion string    `json:"latestVersion"`
}

// isNewerSemver returns true iff candidate > current (comparing dotted numeric versions).
func isNewerSemver(candidate, current string) bool {
	cParts := parseSemverParts(candidate)
	curParts := parseSemverParts(current)
	if len(cParts) == 0 || len(curParts) == 0 {
		return false
	}
	for i := 0; i < 3; i++ {
		if cParts[i] != curParts[i] {
			return cParts[i] > curParts[i]
		}
	}
	return false
}

func parseSemverParts(v string) []int {
	clean := strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if clean == "" || strings.EqualFold(clean, "dev") {
		return nil
	}
	if idx := strings.IndexAny(clean, "-+"); idx > 0 {
		clean = clean[:idx]
	}
	raw := strings.Split(clean, ".")
	parts := make([]int, 3)
	for i := 0; i < 3 && i < len(raw); i++ {
		n, err := strconv.Atoi(raw[i])
		if err != nil {
			return nil
		}
		parts[i] = n
	}
	return parts
}

func updateCachePath() string {
	base, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(base) == "" {
		return ""
	}
	return filepath.Join(base, "rax", "update-check.json")
}

func readUpdateCache(path string) *updateCheckCache {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var c updateCheckCache
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}
	return &c
}

func writeUpdateCache(path string, latest string, now time.Time) {
	if path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	raw, err := json.Marshal(updateCheckCache{CheckedAt: now.UTC(), LatestVersion: latest})
	if err != nil {
		return
	}
	_ = os.WriteFile(path, raw, 0o600)
}

// maybeAutoUpdate performs a fast, fail-open self-update check before executing operational commands.
// If a newer release exists, it upgrades in place (Homebrew or standalone binary) and re-execs the
// upgraded binary transparently so users never have to run a manual upgrade step.
func (a App) maybeAutoUpdate(ctx context.Context, args []string) {
	if os.Getenv("RAX_NO_AUTO_UPDATE") == "1" || os.Getenv("RAX_AUTO_UPDATED") == "1" || flag.Lookup("test.v") != nil {
		return
	}
	current := strings.TrimPrefix(strings.TrimSpace(a.Version), "v")
	if current == "" || strings.EqualFold(current, "dev") {
		return
	}
	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "help" || arg == "--no-auto-update" {
			return
		}
	}

	agentMode := os.Getenv("RAX_AGENT") == "1"
	for _, arg := range args {
		if arg == "--agent" {
			agentMode = true
			break
		}
	}

	now := time.Now().UTC()
	cachePath := updateCachePath()
	if cached := readUpdateCache(cachePath); cached != nil && now.Sub(cached.CheckedAt) < autoUpdateCheckTTL {
		if !isNewerSemver(cached.LatestVersion, current) {
			return
		}
	}

	checkCtx, cancel := context.WithTimeout(ctx, autoUpdateCheckWait)
	defer cancel()
	rel, err := fetchLatestRelease(checkCtx, &http.Client{Timeout: autoUpdateCheckWait})
	if err != nil {
		// Offline or GitHub rate-limited: fail open silently.
		return
	}
	latest := strings.TrimPrefix(rel.TagName, "v")
	writeUpdateCache(cachePath, latest, now)
	if !isNewerSemver(latest, current) {
		return
	}

	if !agentMode {
		fmt.Fprintf(a.Stderr, "Updating rax %s -> %s...\n", current, latest)
	}

	upgradeCtx, upgradeCancel := context.WithTimeout(ctx, 45*time.Second)
	defer upgradeCancel()
	if err := a.performUpgrade(upgradeCtx, rel, true); err != nil {
		// Fail open: keep running current binary if auto-upgrade fails.
		return
	}

	if agentMode {
		raw, _ := json.Marshal(map[string]any{
			"event":   "step",
			"step":    "0/5",
			"message": fmt.Sprintf("Auto-upgraded rax %s -> %s", current, latest),
		})
		_, _ = fmt.Fprintln(a.Stdout, string(raw))
	} else {
		fmt.Fprintf(a.Stderr, "Updated rax to %s.\n", latest)
	}

	// Re-exec the upgraded binary transparently with the exact same arguments.
	exePath, err := os.Executable()
	if err != nil {
		return
	}
	if lp, err := exec.LookPath("rax"); err == nil && lp != "" {
		exePath = lp
	}
	env := append(os.Environ(), "RAX_AUTO_UPDATED=1")
	_ = syscall.Exec(exePath, os.Args, env)
}

func (a App) runUpgrade(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax upgrade", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)
	var checkOnly bool
	fs.BoolVar(&checkOnly, "check", false, "Only check if a newer version is available")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}

	client := &http.Client{Timeout: 30 * time.Second}
	rel, err := fetchLatestRelease(ctx, client)
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error checking latest release: %v\n", err)
		return ExitError
	}

	current := strings.TrimPrefix(a.Version, "v")
	latest := strings.TrimPrefix(rel.TagName, "v")
	writeUpdateCache(updateCachePath(), latest, time.Now().UTC())
	if !isNewerSemver(latest, current) {
		fmt.Fprintf(a.Stdout, "rax %s is already up to date.\n", current)
		return ExitOK
	}

	fmt.Fprintf(a.Stdout, "New version available: %s -> %s (%s)\n", current, latest, rel.HTMLURL)
	if checkOnly {
		return ExitOK
	}

	if err := a.performUpgrade(ctx, rel, false); err != nil {
		fmt.Fprintf(a.Stderr, "Error upgrading rax: %v\n", err)
		return ExitError
	}

	fmt.Fprintf(a.Stdout, "Upgraded rax to %s.\n", latest)
	return ExitOK
}

func (a App) performUpgrade(ctx context.Context, rel *ghRelease, quiet bool) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate current binary: %w", err)
	}
	resolvedExe, _ := filepath.EvalSymlinks(exePath)
	if resolvedExe == "" {
		resolvedExe = exePath
	}

	if isHomebrewPath(resolvedExe) {
		brewBin, err := exec.LookPath("brew")
		if err != nil {
			return errors.New("Homebrew binary not found in PATH")
		}
		cmd := exec.CommandContext(ctx, brewBin, "upgrade", "larrykoo711/tap/rax")
		cmd.Env = append(os.Environ(), "HOMEBREW_NO_ENV_HINTS=1")
		if !quiet {
			cmd.Stdout = a.Stderr
			cmd.Stderr = a.Stderr
		}
		return cmd.Run()
	}

	client := &http.Client{Timeout: 30 * time.Second}
	assetName := fmt.Sprintf("rax-%s-%s-%s.tar.gz", rel.TagName, runtime.GOOS, runtime.GOARCH)
	var tarballURL, checksumsURL string
	for _, asset := range rel.Assets {
		if asset.Name == assetName {
			tarballURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumsURL = asset.BrowserDownloadURL
		}
	}
	if tarballURL == "" || checksumsURL == "" {
		return fmt.Errorf("release %s is missing asset %s or checksums.txt", rel.TagName, assetName)
	}

	if !quiet {
		fmt.Fprintf(a.Stderr, "Downloading %s...\n", assetName)
	}
	tarBytes, err := downloadBytes(ctx, client, tarballURL)
	if err != nil {
		return fmt.Errorf("download tarball: %w", err)
	}
	checksumBytes, err := downloadBytes(ctx, client, checksumsURL)
	if err != nil {
		return fmt.Errorf("download checksums: %w", err)
	}

	expectedHex, err := findChecksum(checksumBytes, assetName)
	if err != nil {
		return fmt.Errorf("verify checksum: %w", err)
	}
	actualSum := sha256.Sum256(tarBytes)
	actualHex := hex.EncodeToString(actualSum[:])
	if !strings.EqualFold(actualHex, expectedHex) {
		return fmt.Errorf("SHA-256 mismatch (expected %s, got %s)", expectedHex, actualHex)
	}

	binBytes, err := extractBinaryFromTarGz(tarBytes, "rax")
	if err != nil {
		return fmt.Errorf("extract binary: %w", err)
	}

	tmpPath := resolvedExe + ".upgrade.tmp"
	if err := os.WriteFile(tmpPath, binBytes, 0o755); err != nil {
		return fmt.Errorf("write upgraded binary in %s: %w", filepath.Dir(resolvedExe), err)
	}
	if err := os.Rename(tmpPath, resolvedExe); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace binary: %w", err)
	}
	return nil
}

func isHomebrewPath(p string) bool {
	return strings.Contains(p, "/Cellar/") || strings.Contains(p, "/homebrew/") || strings.Contains(p, "/linuxbrew/")
}

func fetchLatestRelease(ctx context.Context, client *http.Client) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", releaseRepo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "rax-cli")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API HTTP %d", resp.StatusCode)
	}
	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}
	if rel.TagName == "" {
		return nil, errors.New("empty release tag")
	}
	return &rel, nil
}

func downloadBytes(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "rax-cli")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 50<<20))
}

func findChecksum(raw []byte, filename string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 2 && strings.TrimPrefix(fields[1], "*") == filename {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksum entry for %s not found", filename)
}

func extractBinaryFromTarGz(raw []byte, target string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if filepath.Base(hdr.Name) == target && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 50<<20))
		}
	}
	return nil, fmt.Errorf("binary %q not found in archive", target)
}
