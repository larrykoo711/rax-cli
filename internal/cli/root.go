package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"
)

// App holds build metadata and I/O streams for the rax CLI.
type App struct {
	Version string
	Commit  string
	Date    string
	Stdout  io.Writer
	Stderr  io.Writer
}

// Run dispatches top-level commands and returns a standardized process exit code.
func (a App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.printRootHelp()
		return ExitOK
	}

	switch args[0] {
	case "-h", "--help", "help":
		a.printRootHelp()
		return ExitOK
	case "-v", "--version", "version":
		return a.runVersion(args[1:])
	case "agent-info", "--schema":
		return a.runAgentInfo()
	case "doctor":
		return a.runDoctor(ctx, args[1:])
	case "azure":
		a.maybeAutoUpdate(ctx, args[1:])
		return a.runAzure(ctx, args[1:])
	case "logs":
		return a.runLogs(ctx, args[1:])
	case "upgrade", "update":
		return a.runUpgrade(ctx, args[1:])
	default:
		fmt.Fprintf(a.Stderr, "Error: unknown command %q\n\n", args[0])
		a.printRootHelp()
		return ExitInvalidArg
	}
}

func (a App) printRootHelp() {
	fmt.Fprintf(a.Stdout, `rax — Rax Cloud Channel Control-Tower CLI (zero Python / zero az CLI required)

Usage:
  rax <command> [flags]

Commands:
  azure onboard    Interactive Entra Device Code onboarding (supports --agent NDJSON stream)
  azure verify     Verify Service Principal ARM & Monitor connectivity and subscription visibility
  logs             Inspect or package redacted local diagnostic logs (rax logs bundle --json)
  doctor           Preflight check of Microsoft Entra, Graph, and ARM connectivity
  agent-info       Print machine-readable CLI contract & security rules for AI agent harnesses
  version          Print CLI version and build metadata
  upgrade          Check GitHub Releases and upgrade rax to the latest version

Run 'rax <command> --help' for details on any command.
`)
}

func (a App) runVersion(args []string) int {
	asJSON := false
	for _, arg := range args {
		if arg == "--json" || arg == "--agent" {
			asJSON = true
		}
	}
	if asJSON {
		enc := json.NewEncoder(a.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{
			"version": strings.TrimPrefix(a.Version, "v"),
			"commit":  a.Commit,
			"date":    a.Date,
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		})
		return ExitOK
	}
	ver := strings.TrimPrefix(a.Version, "v")
	fmt.Fprintf(a.Stdout, "rax %s (%s, %s, %s/%s)\n", ver, a.Commit, a.Date, runtime.GOOS, runtime.GOARCH)
	return ExitOK
}
