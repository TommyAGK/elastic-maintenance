package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"elastic-maintenance/internal/config"
	"elastic-maintenance/internal/server"
)

const (
	startupUsage    = "usage: elastic-maintainer [--config <server.yaml>] [--listen <address>] [--state-dir <dir>] [--public-url <url>] [--version]"
	shutdownTimeout = 10 * time.Second
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return execute(
		ctx,
		os.Args[1:],
		os.Stdout,
		os.Stderr,
		os.LookupEnv,
		server.NewHTTPRuntime,
		server.BuildInfo{Version: version, Commit: commit, Date: buildDate},
		shutdownTimeout,
	)
}

func execute(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	lookup config.LookupEnv,
	factory server.Factory,
	build server.BuildInfo,
	gracePeriod time.Duration,
) int {
	options, err := config.ParseStartupOptions(args, lookup)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, startupUsage)
			return 0
		}
		return writeError(stderr, err)
	}

	build = build.Normalized()
	if options.ShowVersion {
		fmt.Fprintf(stdout, "elastic-maintainer version=%s commit=%s date=%s\n", build.Version, build.Commit, build.Date)
		return 0
	}

	cfg, err := config.LoadServerConfig(options.ConfigPath)
	if err != nil {
		return writeError(stderr, err)
	}
	cfg.ApplyStartupOverrides(options)
	if err := cfg.ValidateStartup(); err != nil {
		return writeError(stderr, fmt.Errorf("validate server config: %w", err))
	}
	if factory == nil {
		return writeError(stderr, errors.New("server runtime factory is nil"))
	}

	runtime, err := factory(cfg, build)
	if err != nil {
		return writeError(stderr, fmt.Errorf("create API server: %w", err))
	}
	if err := server.Run(ctx, runtime, gracePeriod); err != nil {
		return writeError(stderr, fmt.Errorf("run API server: %w", err))
	}
	return 0
}

func writeError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "elastic-maintainer: %v\n", err)
	return 1
}
