package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestAgentInfoEmitsValidSchemaAndSecurityRules(t *testing.T) {
	var out, errBuf bytes.Buffer
	app := App{Version: "0.2.0", Commit: "abc1234", Date: "2026-11-26", Stdout: &out, Stderr: &errBuf}

	code := app.Run(context.Background(), []string{"agent-info"})
	if code != ExitOK {
		t.Fatalf("expected exit 0, got %d (stderr=%s)", code, errBuf.String())
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid agent-info JSON: %v", err)
	}
	if doc["name"] != "rax" || doc["version"] != "0.2.0" {
		t.Fatalf("unexpected header: %+v", doc)
	}
	rules, ok := doc["securityRules"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("expected securityRules in agent-info")
	}
}

func TestOnboardAgentMissingSlugEmitsStructuredJSONError(t *testing.T) {
	var out, errBuf bytes.Buffer
	app := App{Version: "0.2.0", Stdout: &out, Stderr: &errBuf}

	code := app.Run(context.Background(), []string{"azure", "onboard", "--agent"})
	if code != ExitInvalidArg {
		t.Fatalf("expected exit %d, got %d", ExitInvalidArg, code)
	}
	var res map[string]any
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("expected JSON error on stdout in --agent mode, got %q", out.String())
	}
	if res["code"] != "INVALID_ARGUMENT" || res["ok"] != false {
		t.Fatalf("unexpected agent error payload: %+v", res)
	}
}
