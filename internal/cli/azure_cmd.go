package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/larrykoo711/rax-cli/internal/azure"
)

func (a App) runAzure(ctx context.Context, args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintf(a.Stdout, `Usage:
  rax azure <subcommand> [flags]

Subcommands:
  onboard    Run native Entra Device Code onboarding and export rax-onboard-bundle.json
  verify     Verify Service Principal ARM + Monitor connectivity and visible subscriptions
`)
		return 0
	}

	switch args[0] {
	case "onboard":
		return a.runAzureOnboard(ctx, args[1:])
	case "verify":
		return a.runAzureVerify(ctx, args[1:])
	default:
		fmt.Fprintf(a.Stderr, "Error: unknown azure subcommand %q\n", args[0])
		return 2
	}
}

func (a App) runAzureOnboard(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("rax azure onboard", flag.ContinueOnError)
	fs.SetOutput(a.Stderr)

	var (
		tenantID   string
		slug       string
		subsCSV    string
		freezeRole string
		secretDays int
		apply      bool
		outputPath string
		asJSON     bool
	)

	fs.StringVar(&tenantID, "tenant", "", "Optional Azure Entra Tenant ID (auto-detected after Device Code sign-in if omitted)")
	fs.StringVar(&slug, "slug", "", "Short tenant slug used to name SP (e.g. hailiang01 -> rax-managed-sp-hailiang01)")
	fs.StringVar(&subsCSV, "subscriptions", "", "Optional comma-separated Subscription IDs (auto-discovers all enabled subscriptions if omitted)")
	fs.StringVar(&freezeRole, "freeze-role", "custom", "Freeze role mode: 'custom' (least-privilege default) or 'builtin'")
	fs.IntVar(&secretDays, "secret-days", 365, "Client secret validity in days (7-730)")
	fs.BoolVar(&apply, "apply", false, "Execute live Entra & ARM provisioning (omit for dry-run preview)")
	fs.StringVar(&outputPath, "output", "./rax-onboard-bundle.json", "Write chmod-600 onboarding bundle JSON path")
	fs.BoolVar(&asJSON, "json", false, "Print structured JSON summary to stdout")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if strings.TrimSpace(slug) == "" {
		fmt.Fprintf(a.Stderr, "Error: --slug is required (example: rax azure onboard --slug prod --apply)\n")
		return 2
	}

	var subs []string
	for _, part := range strings.Split(subsCSV, ",") {
		if s := strings.TrimSpace(part); s != "" {
			subs = append(subs, s)
		}
	}

	onboarder := azure.NewOnboarder()
	summary, err := onboarder.Run(ctx, azure.OnboardOptions{
		TenantID:       tenantID,
		Slug:           slug,
		Subscriptions:  subs,
		FreezeRoleMode: freezeRole,
		SecretDays:     secretDays,
		Apply:          apply,
		OutputPath:     outputPath,
		Log:            a.Stderr,
	})
	if err != nil {
		fmt.Fprintf(a.Stderr, "Error: %v\n", err)
		return 1
	}

	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(summary)
		return 0
	}

	if !summary.Applied {
		fmt.Fprintf(a.Stdout, "Dry-run plan (zero Azure writes):\n")
		fmt.Fprintf(a.Stdout, "  SP Name:      %s\n", summary.AppName)
		fmt.Fprintf(a.Stdout, "  Secret TTL:   %d days\n", secretDays)
		fmt.Fprintf(a.Stdout, "  Freeze Role:  %s\n", summary.FreezeRoleMode)
		fmt.Fprintf(a.Stdout, "  Roles / Sub:  %s\n", strings.Join(summary.RolesPerSub, ", "))
		if len(summary.Subscriptions) == 0 {
			fmt.Fprintf(a.Stdout, "  Subscriptions: auto-discover all enabled subscriptions after Device Code login\n")
		} else {
			fmt.Fprintf(a.Stdout, "  Subscriptions: %d explicit\n", len(summary.Subscriptions))
		}
		fmt.Fprintf(a.Stdout, "\nRe-run with --apply to execute.\n")
		return 0
	}

	fmt.Fprintf(a.Stdout, "\nAzure tenant onboarded successfully:\n")
	fmt.Fprintf(a.Stdout, "  Tenant ID:      %s\n", summary.TenantID)
	fmt.Fprintf(a.Stdout, "  SP Name:        %s\n", summary.AppName)
	fmt.Fprintf(a.Stdout, "  Client ID:      %s\n", summary.ClientID)
	fmt.Fprintf(a.Stdout, "  Client Secret:  %s (stored only in bundle file)\n", summary.SecretMasked)
	fmt.Fprintf(a.Stdout, "  Secret Expires: %s\n", summary.SecretExpiresAt)
	fmt.Fprintf(a.Stdout, "  Subscriptions:  %d bound\n", len(summary.Subscriptions))
	for _, s := range summary.Subscriptions {
		fmt.Fprintf(a.Stdout, "    - %s (%s)\n", s.Name, s.ID)
	}
	if summary.OutputPath != "" {
		fmt.Fprintf(a.Stdout, "\nNext step: upload %s in Rax Console -> Azure -> 租户与订阅 -> 接入租户\n", summary.OutputPath)
		fmt.Fprintf(a.Stdout, "Optional check: rax azure verify --bundle %s\n", summary.OutputPath)
	}
	return 0
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

	fs.StringVar(&bundlePath, "bundle", "", "Path to rax-onboard-bundle.json")
	fs.StringVar(&tenantID, "tenant", "", "Azure Tenant ID (alternative to --bundle)")
	fs.StringVar(&clientID, "client-id", "", "Service Principal Client ID")
	fs.StringVar(&clientSecret, "client-secret", "", "Service Principal Client Secret")
	fs.BoolVar(&asJSON, "json", false, "Print JSON output")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	var creds azure.VerifyCredentials
	if strings.TrimSpace(bundlePath) != "" {
		loaded, err := azure.LoadBundleCredentials(bundlePath)
		if err != nil {
			fmt.Fprintf(a.Stderr, "Error: %v\n", err)
			return 1
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
		fmt.Fprintf(a.Stderr, "Error: provide --bundle <path> or --tenant / --client-id / --client-secret\n")
		return 2
	}

	onboarder := azure.NewOnboarder()
	res, err := onboarder.Verify(ctx, creds)
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		if err != nil {
			return 1
		}
		return 0
	}

	if err != nil {
		fmt.Fprintf(a.Stderr, "Verification failed: %v\n", err)
		return 1
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
	return 0
}
