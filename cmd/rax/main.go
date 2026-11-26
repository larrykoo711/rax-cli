package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/larrykoo711/rax-cli/internal/cli"
)

var (
	version = "0.6.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	app := cli.App{
		Version: version,
		Commit:  commit,
		Date:    date,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
	os.Exit(app.Run(ctx, os.Args[1:]))
}
