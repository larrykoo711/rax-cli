package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"
)

// Exit codes standardized for AI agent harnesses.
const (
	ExitOK         = 0
	ExitError      = 1
	ExitInvalidArg = 2
	ExitAuthFailed = 3
	ExitPermission = 4
)

type agentError struct {
	OK    bool   `json:"ok"`
	Event string `json:"event,omitempty"`
	Code  string `json:"code"`
	Error string `json:"error"`
	Hint  string `json:"hint,omitempty"`
}

func classifyAzureError(err error) (exitCode int, code string, hint string) {
	if err == nil {
		return ExitOK, "", ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "device code") || strings.Contains(msg, "tenant mismatch") || strings.Contains(msg, "declined") || strings.Contains(msg, "expired") || strings.Contains(msg, "token"):
		return ExitAuthFailed, "AUTH_FAILED", "Re-run the command and complete Microsoft Entra Device Code sign-in in a browser logged into the target Azure tenant."
	case strings.Contains(msg, "http 403") || strings.Contains(msg, "authorizationfailed") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "insufficient"):
		return ExitPermission, "PERMISSION_DENIED", "The signed-in Azure account needs Application Administrator (or App creation) in Entra ID and Owner / User Access Administrator on the target subscriptions."
	default:
		return ExitError, "EXECUTION_FAILED", "Inspect the error message and run `rax doctor --json` to verify network reachability."
	}
}

// runAgentInfo prints a self-describing machine-readable contract for AI agent harnesses.
func (a App) runAgentInfo() int {
	doc := map[string]any{
		"name":    "rax",
		"version": strings.TrimPrefix(a.Version, "v"),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
		"runtimeDependencies": map[string]bool{
			"python":   false,
			"nodejs":   false,
			"azureCli": false,
		},
		"defaultOutputDir": "~/Downloads/rax-cli",
		"bundleEncryption": "RSA-OAEP-256+A256GCM (sealed with Rax platform public key; zero plaintext clientSecret on disk)",
		"securityRules": []string{
			"Default onboarding writes an RSA-OAEP+AES-256-GCM sealed bundle to ~/Downloads/rax-cli/rax-<slug>-<timestamp>.rax.enc.json; plaintext clientSecret never touches disk.",
			"Only the Rax Console server can decrypt the sealed bundle. After onboarding succeeds, report the saved file path and subscription list so the user can upload it in Rax Console.",
			"Device Code OAuth tokens stay strictly in process memory; zero files are written to ~/.azure.",
		},
		"exitCodes": map[string]int{
			"ok":                ExitOK,
			"error":             ExitError,
			"invalid_argument":  ExitInvalidArg,
			"auth_failed":       ExitAuthFailed,
			"permission_denied": ExitPermission,
		},
		"commands": []map[string]any{
			{
				"command": "rax azure onboard",
				"purpose": "Native Entra Device Code onboarding: auto-discovers enabled subscriptions, provisions single-tenant SP + least-privilege RBAC, self-verifies in memory, and writes a sealed encrypted bundle to ~/Downloads/rax-cli/.",
				"agentInvocation": "rax azure onboard --slug <slug> --secret-days <7|30|90|180|365> --agent --apply",
				"agentProtocol": map[string]any{
					"format":             "NDJSON on stdout (one JSON object per line, flushed immediately)",
					"events":             []string{"step", "device_code", "done", "error"},
					"actionOnDeviceCode": "Relay verificationUri and userCode to the human immediately and wait for the process to finish.",
				},
			},
			{
				"command":         "rax azure verify",
				"purpose":         "Validate sealed bundle envelope integrity (or live-verify explicit credentials).",
				"agentInvocation": "rax azure verify --bundle ~/Downloads/rax-cli/<file>.rax.enc.json --json",
			},
			{
				"command":         "rax doctor",
				"purpose":         "Preflight check of OS/arch and HTTPS reachability to Microsoft Entra, Graph, and ARM endpoints.",
				"agentInvocation": "rax doctor --json",
			},
			{
				"command":         "rax upgrade",
				"purpose":         "Check or install latest release from GitHub Releases (auto-detects Homebrew).",
				"agentInvocation": "rax upgrade --check",
			},
		},
	}
	enc := json.NewEncoder(a.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(doc)
	return ExitOK
}

// runDoctor performs a fast non-destructive connectivity & environment preflight.
func (a App) runDoctor(ctx context.Context, args []string) int {
	asJSON := false
	for _, arg := range args {
		if arg == "--json" || arg == "--agent" {
			asJSON = true
		}
	}

	endpoints := []struct {
		Name string
		URL  string
	}{
		{"entra_login", "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"},
		{"microsoft_graph", "https://graph.microsoft.com/v1.0/$metadata"},
		{"azure_arm", "https://management.azure.com/metadata/endpoints?api-version=2022-09-01"},
	}

	client := &http.Client{Timeout: 8 * time.Second}
	type probeResult struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		OK        bool   `json:"ok"`
		Status    int    `json:"status,omitempty"`
		LatencyMs int64  `json:"latencyMs"`
		Error     string `json:"error,omitempty"`
	}

	results := make([]probeResult, 0, len(endpoints))
	allOK := true
	for _, ep := range endpoints {
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead, ep.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			// Retry GET for endpoints that reject HEAD.
			reqGet, _ := http.NewRequestWithContext(ctx, http.MethodGet, ep.URL, nil)
			resp, err = client.Do(reqGet)
		}
		latency := time.Since(start).Milliseconds()
		if err != nil {
			allOK = false
			results = append(results, probeResult{Name: ep.Name, URL: ep.URL, OK: false, LatencyMs: latency, Error: err.Error()})
			continue
		}
		resp.Body.Close()
		ok := resp.StatusCode >= 200 && resp.StatusCode < 500
		if !ok {
			allOK = false
		}
		results = append(results, probeResult{Name: ep.Name, URL: ep.URL, OK: ok, Status: resp.StatusCode, LatencyMs: latency})
	}

	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"ok":      allOK,
			"version": strings.TrimPrefix(a.Version, "v"),
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
			"checks":  results,
		})
		if !allOK {
			return ExitError
		}
		return ExitOK
	}

	fmt.Fprintf(a.Stdout, "rax %s (%s/%s) preflight:\n", strings.TrimPrefix(a.Version, "v"), runtime.GOOS, runtime.GOARCH)
	for _, r := range results {
		status := "OK"
		if !r.OK {
			status = "FAIL"
		}
		fmt.Fprintf(a.Stdout, "  [%s] %-16s (%dms)", status, r.Name, r.LatencyMs)
		if r.Error != "" {
			fmt.Fprintf(a.Stdout, " — %s", r.Error)
		}
		fmt.Fprintln(a.Stdout)
	}
	if !allOK {
		return ExitError
	}
	return ExitOK
}
