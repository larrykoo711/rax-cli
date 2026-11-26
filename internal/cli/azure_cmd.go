package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/larrykoo711/rax-cli/internal/azure"
)

func (a App) runAzure(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(a.Stdout, `Usage:
  rax azure <subcommand> [flags]

Subcommands:
  onboard    Run native Entra Device Code onboarding and save an encrypted bundle to ~/Downloads/rax-cli/
  verify     Validate a sealed bundle envelope or verify live SP ARM + Monitor connectivity
`)
		return ExitOK
	}

	switch args[0] {
	case "onboard":
		return a.runAzureOnboard(ctx, args[1:])
	case "verify":
		return a.runAzureVerify(ctx, args[1:])
	default:
		fmt.Fprintf(a.Stderr, "Error: unknown azure subcommand %q\n", args[0])
		return ExitInvalidArg
	}
}

func (a App) runAzureOnboard(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax azure onboard", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		tenantID    string
		slug        string
		subsCSV     string
		freezeRole  string
		secretDays  int
		apply       bool
		outputPath  string
		plainOutput bool
		sealKeyPath string
		asJSON      bool
		agentMode   bool
		timeout     time.Duration
	)

	fs.StringVar(&tenantID, "tenant", "", "Optional Azure Entra Tenant ID (auto-detected after Device Code sign-in if omitted)")
	fs.StringVar(&slug, "slug", "", "Optional short tenant slug (auto-derived from tenant *.onmicrosoft.com domain if omitted)")
	fs.StringVar(&subsCSV, "subscriptions", "", "Optional comma-separated Subscription IDs (auto-discovers all enabled subscriptions if omitted)")
	fs.StringVar(&freezeRole, "freeze-role", "custom", "Freeze role mode: 'custom' (least-privilege default) or 'builtin'")
	fs.IntVar(&secretDays, "secret-days", 365, "Client secret validity in days (7-730)")
	fs.BoolVar(&apply, "apply", false, "Execute live Entra & ARM provisioning (omit for dry-run preview)")
	fs.StringVar(&outputPath, "output", "", "Optional output file or directory (defaults to ~/Downloads/rax-cli/rax-<slug>-<timestamp>.rax.enc.json)")
	fs.BoolVar(&plainOutput, "plain", false, "Write legacy unencrypted bundle JSON instead of RSA-OAEP+AES-256-GCM sealed bundle (debug only)")
	fs.StringVar(&sealKeyPath, "seal-key", "", "Optional path to a custom SPKI RSA public key PEM for sealing")
	fs.BoolVar(&asJSON, "json", false, "Print structured JSON summary to stdout")
	fs.BoolVar(&agentMode, "agent", os.Getenv("RAX_AGENT") == "1", "Emit line-flushed NDJSON progress & device_code events for AI agents")
	fs.DurationVar(&timeout, "timeout", 15*time.Minute, "Overall operation timeout including Device Code sign-in")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	writeNDJSON := func(v any) {
		raw, err := json.Marshal(v)
		if err == nil {
			_, _ = fmt.Fprintln(a.Stdout, string(raw))
		}
	}

	if secretDays < 7 || secretDays > 730 {
		if agentMode || asJSON {
			writeNDJSON(agentError{
				OK:    false,
				Event: "error",
				Code:  "INVALID_ARGUMENT",
				Error: fmt.Sprintf("--secret-days must be between 7 and 730 (got %d)", secretDays),
				Hint:  "Use a valid secret lifetime such as --secret-days 365",
			})
		} else {
			fmt.Fprintf(a.Stderr, "Error: --secret-days must be between 7 and 730 (got %d)\n", secretDays)
		}
		return ExitInvalidArg
	}

	var customPubPEM string
	if strings.TrimSpace(sealKeyPath) != "" {
		rawKey, err := os.ReadFile(strings.TrimSpace(sealKeyPath))
		if err != nil {
			if agentMode || asJSON {
				writeNDJSON(agentError{OK: false, Event: "error", Code: "INVALID_ARGUMENT", Error: fmt.Sprintf("read --seal-key: %v", err)})
			} else {
				fmt.Fprintf(a.Stderr, "Error: read --seal-key: %v\n", err)
			}
			return ExitInvalidArg
		}
		customPubPEM = string(rawKey)
	}

	var subs []string
	for _, part := range strings.Split(subsCSV, ",") {
		if s := strings.TrimSpace(part); s != "" {
			subs = append(subs, s)
		}
	}

	var logWriter io.Writer = a.Stderr
	var onEvent func(azure.OnboardEvent)
	if agentMode {
		// In --agent mode, keep stdout strictly NDJSON and silence human stderr noise.
		logWriter = io.Discard
		onEvent = func(ev azure.OnboardEvent) {
			writeNDJSON(ev)
		}
	}

	onboarder := azure.NewOnboarder()
	summary, err := onboarder.Run(ctx, azure.OnboardOptions{
		TenantID:         tenantID,
		Slug:             slug,
		Subscriptions:    subs,
		FreezeRoleMode:   freezeRole,
		SecretDays:       secretDays,
		Apply:            apply,
		OutputPath:       outputPath,
		PlainOutput:      plainOutput,
		SealPublicKeyPEM: customPubPEM,
		Log:              logWriter,
		OnEvent:          onEvent,
	})
	if err != nil {
		exitCode, code, hint := classifyAzureError(err)
		if agentMode || asJSON {
			writeNDJSON(agentError{
				OK:    false,
				Event: "error",
				Code:  code,
				Error: err.Error(),
				Hint:  hint,
			})
		} else {
			fmt.Fprintf(a.Stderr, "Error: %v\n", err)
		}
		return exitCode
	}

	if agentMode {
		nextStep := fmt.Sprintf(
			"Encrypted bundle saved to %s (only Rax Console can decrypt). Ask the user to import it in Rax Console -> Azure -> 租户与订阅 -> 接入租户 (Step 2).",
			summary.OutputPath,
		)
		if !summary.Sealed {
			nextStep = fmt.Sprintf(
				"Plaintext bundle saved to %s. Do NOT read or print clientSecret; ask the user to upload it in Rax Console.",
				summary.OutputPath,
			)
		}
		writeNDJSON(map[string]any{
			"event":    "done",
			"summary":  summary,
			"nextStep": nextStep,
		})
		return ExitOK
	}

	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return ExitOK
	}

	if !summary.Applied {
		fmt.Fprintf(a.Stdout, "Dry-run plan (zero Azure writes):\n")
		fmt.Fprintf(a.Stdout, "  SP Name:      %s\n", summary.AppName)
		fmt.Fprintf(a.Stdout, "  Secret TTL:   %d days\n", secretDays)
		fmt.Fprintf(a.Stdout, "  Freeze Role:  %s\n", summary.FreezeRoleMode)
		fmt.Fprintf(a.Stdout, "  Roles / Sub:  %s\n", strings.Join(summary.RolesPerSub, ", "))
		fmt.Fprintf(a.Stdout, "  Encryption:   %v (keyId=%s)\n", summary.Sealed, summary.KeyID)
		fmt.Fprintf(a.Stdout, "  Output File:  %s\n", summary.OutputPath)
		if len(summary.Subscriptions) == 0 {
			fmt.Fprintf(a.Stdout, "  Subscriptions: auto-discover all enabled subscriptions after Device Code login\n")
		} else {
			fmt.Fprintf(a.Stdout, "  Subscriptions: %d explicit\n", len(summary.Subscriptions))
		}
		fmt.Fprintf(a.Stdout, "\nRe-run with --apply to execute.\n")
		return ExitOK
	}

	fmt.Fprintf(a.Stdout, "\nAzure tenant onboarded successfully:\n")
	fmt.Fprintf(a.Stdout, "  Tenant ID:      %s\n", summary.TenantID)
	if summary.TenantDomain != "" {
		fmt.Fprintf(a.Stdout, "  Tenant Domain:  %s\n", summary.TenantDomain)
	}
	if summary.AuthorizedByEmail != "" {
		fmt.Fprintf(a.Stdout, "  Authorized By:  %s\n", summary.AuthorizedByEmail)
	}
	fmt.Fprintf(a.Stdout, "  SP Name:        %s\n", summary.AppName)
	fmt.Fprintf(a.Stdout, "  Client ID:      %s\n", summary.ClientID)
	if summary.Sealed {
		fmt.Fprintf(a.Stdout, "  Client Secret:  %s (RSA-OAEP+AES-256-GCM sealed; only Rax Console can decrypt)\n", summary.SecretMasked)
	} else {
		fmt.Fprintf(a.Stdout, "  Client Secret:  %s (stored only in bundle file)\n", summary.SecretMasked)
	}
	fmt.Fprintf(a.Stdout, "  Secret Expires: %s\n", summary.SecretExpiresAt)
	fmt.Fprintf(a.Stdout, "  Self-Verified:  %v\n", summary.Verified)
	fmt.Fprintf(a.Stdout, "  Subscriptions:  %d bound\n", len(summary.Subscriptions))
	for _, s := range summary.Subscriptions {
		fmt.Fprintf(a.Stdout, "    - %s (%s)\n", s.Name, s.ID)
	}
	if summary.OutputPath != "" {
		fmt.Fprintf(a.Stdout, "\nEncrypted bundle saved to:\n  %s\n", summary.OutputPath)
		fmt.Fprintf(a.Stdout, "\nNext step: upload this file in Rax Console -> Azure -> 租户与订阅 -> 接入租户 (Step 2)\n")
	}
	return ExitOK
}

func (a App) runAzureVerify(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax azure verify", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		bundlePath   string
		tenantID     string
		clientID     string
		clientSecret string
		asJSON       bool
	)

	fs.StringVar(&bundlePath, "bundle", "", "Path to a sealed (*.rax.enc.json) or legacy plaintext bundle file")
	fs.StringVar(&tenantID, "tenant", "", "Azure Tenant ID (alternative to --bundle)")
	fs.StringVar(&clientID, "client-id", "", "Service Principal Client ID")
	fs.StringVar(&clientSecret, "client-secret", "", "Service Principal Client Secret")
	fs.BoolVar(&asJSON, "json", os.Getenv("RAX_AGENT") == "1", "Print JSON output")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return ExitOK
		}
		return ExitInvalidArg
	}

	if strings.TrimSpace(bundlePath) != "" {
		if sealedRes, isSealed, err := azure.InspectSealedBundle(bundlePath); isSealed {
			if err != nil {
				if asJSON {
					_ = json.NewEncoder(a.Stdout).Encode(agentError{OK: false, Code: "INVALID_BUNDLE", Error: err.Error()})
				} else {
					fmt.Fprintf(a.Stderr, "Error: %v\n", err)
				}
				return ExitInvalidArg
			}
			if asJSON {
				enc := json.NewEncoder(a.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(sealedRes)
				return ExitOK
			}
			fmt.Fprintf(a.Stdout, "Sealed Rax bundle envelope verified:\n")
			fmt.Fprintf(a.Stdout, "  Tenant ID:         %s\n", sealedRes.TenantID)
			fmt.Fprintf(a.Stdout, "  Client ID:         %s\n", sealedRes.ClientID)
			fmt.Fprintf(a.Stdout, "  Encryption Key ID: %s (%s)\n", sealedRes.KeyID, azure.SealedBundleAlg)
			fmt.Fprintf(a.Stdout, "  Onboard Verified:  %v\n", sealedRes.VerifiedAtOnboard)
			fmt.Fprintf(a.Stdout, "  Subscriptions:     %d\n", len(sealedRes.Subscriptions))
			for _, s := range sealedRes.Subscriptions {
				fmt.Fprintf(a.Stdout, "    - %s (%s)\n", s.DisplayName, s.SubscriptionID)
			}
			fmt.Fprintf(a.Stdout, "\n%s\n", sealedRes.Note)
			return ExitOK
		}
	}

	var creds azure.VerifyCredentials
	if strings.TrimSpace(bundlePath) != "" {
		loaded, err := azure.LoadBundleCredentials(bundlePath)
		if err != nil {
			if asJSON {
				_ = json.NewEncoder(a.Stdout).Encode(agentError{OK: false, Code: "INVALID_BUNDLE", Error: err.Error()})
			} else {
				fmt.Fprintf(a.Stderr, "Error: %v\n", err)
			}
			return ExitInvalidArg
		}
		creds = *loaded
	} else {
		creds = azure.VerifyCredentials{
			TenantID:     strings.TrimSpace(tenantID),
			ClientID:     strings.TrimSpace(clientID),
			ClientSecret: strings.TrimSpace(clientSecret),
		}
	}

	if creds.TenantID == "" || creds.ClientID == "" || creds.ClientSecret == "" {
		if asJSON {
			_ = json.NewEncoder(a.Stdout).Encode(agentError{
				OK:    false,
				Code:  "INVALID_ARGUMENT",
				Error: "provide --bundle <path> or --tenant / --client-id / --client-secret",
			})
		} else {
			fmt.Fprintf(a.Stderr, "Error: provide --bundle <path> or --tenant / --client-id / --client-secret\n")
		}
		return ExitInvalidArg
	}

	onboarder := azure.NewOnboarder()
	res, err := onboarder.Verify(ctx, creds)
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if err != nil {
			code, _, _ := classifyAzureError(err)
			return code
		}
		return ExitOK
	}

	if err != nil {
		fmt.Fprintf(a.Stderr, "Verification failed: %v\n", err)
		code, _, _ := classifyAzureError(err)
		return code
	}

	fmt.Fprintf(a.Stdout, "Service Principal verification passed:\n")
	fmt.Fprintf(a.Stdout, "  Tenant ID:          %s\n", res.TenantID)
	fmt.Fprintf(a.Stdout, "  Client ID:          %s\n", res.ClientID)
	fmt.Fprintf(a.Stdout, "  ARM Token:          OK\n")
	fmt.Fprintf(a.Stdout, "  Monitor Data Token: OK\n")
	fmt.Fprintf(a.Stdout, "  Visible Subs:       %d\n", len(res.Subscriptions))
	for _, s := range res.Subscriptions {
		fmt.Fprintf(a.Stdout, "    - %s (%s) [%s]\n", s.DisplayName, s.SubscriptionID, s.State)
	}
	return ExitOK
}
