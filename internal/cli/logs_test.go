package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactSensitiveScrubsSecretsTokensAndEmails(t *testing.T) {
	in := `Authorization: Bearer secret-tok-12345 eyJhbGciOiJIUzI1NiJ9.eyJ0aWQiOiIxMjM0NTY3OCJ9.sig client_secret="top-secret-999" user_code=ABCD-1234 admin.ops@hailiang01.onmicrosoft.com /subscriptions/a5d24bc1-5ea9-48e4-a0b2-d45f87706948/providers`
	out := RedactSensitive(in)

	for _, leaked := range []string{"secret-tok-12345", "eyJhbGciOiJIUzI1NiJ9", "top-secret-999", "ABCD-1234", "admin.ops@", "48e4-a0b2-d45f87706948"} {
		if strings.Contains(out, leaked) {
			t.Fatalf("expected %q to be redacted from %q", leaked, out)
		}
	}
	if !strings.Contains(out, "***@hailiang01.onmicrosoft.com") {
		t.Fatalf("expected email domain preserved with redacted local part, got: %q", out)
	}
}

func TestLogsBundleExportsRedactedChmod600Report(t *testing.T) {
	logDir := t.TempDir()
	outDir := t.TempDir()
	t.Setenv("RAX_LOG_DIR", logDir)

	var stdout, stderr bytes.Buffer
	app := App{
		Version: "0.7.0",
		Commit:  "abc1234",
		Date:    "2026-11-26T00:00:00Z",
		Stdout:  &stdout,
		Stderr:  &stderr,
	}

	rec := app.StartRunRecorder("azure onboard")
	if rec == nil {
		t.Fatalf("expected non-nil RunRecorder when RAX_LOG_DIR is set")
	}
	rec.Record(LogEntry{
		Level:       "warn",
		Event:       "retry",
		Step:        "4/5",
		Attempt:     1,
		MaxAttempts: 6,
		Reason:      "arm_request_timeout",
		Message:     "Bearer leaked-token client_secret=super-secret-xyz retrying PUT",
	})
	sc := false
	rec.Finish(ExitError, "ARM_REQUEST_TIMEOUT", "request", "timeout on sub", 12, 54, 42, &sc)

	bundlePath := filepath.Join(outDir, "diag.log")
	code := app.Run(context.Background(), []string{"logs", "bundle", "--no-doctor", "--output", bundlePath, "--json"})
	if code != ExitOK {
		t.Fatalf("logs bundle failed (exit %d): stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}

	var resp struct {
		OK           bool   `json:"ok"`
		BundlePath   string `json:"bundlePath"`
		RunsIncluded int    `json:"runsIncluded"`
		Redacted     bool   `json:"redacted"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json output: %v (%s)", err, stdout.String())
	}
	if !resp.OK || !resp.Redacted || resp.RunsIncluded != 1 || resp.BundlePath != bundlePath {
		t.Fatalf("unexpected bundle response: %+v", resp)
	}

	info, err := os.Stat(bundlePath)
	if err != nil {
		t.Fatalf("stat bundle: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected chmod 0600, got %o", info.Mode().Perm())
	}

	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "leaked-token") || strings.Contains(content, "super-secret-xyz") {
		t.Fatalf("sensitive string leaked into diagnostic bundle: %s", content)
	}
	if !strings.Contains(content, "progress=12/54") || !strings.Contains(content, "secretCreated=false") || !strings.Contains(content, "arm_request_timeout") {
		t.Fatalf("expected structured failure diagnostics in bundle, got:\n%s", content)
	}
}
