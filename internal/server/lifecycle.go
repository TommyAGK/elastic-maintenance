package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"elastic-maintenance/internal/config"
)

type BuildInfo struct {
	Version string
	Commit  string
	Date    string
}

func (info BuildInfo) Normalized() BuildInfo {
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "none"
	}
	if info.Date == "" {
		info.Date = "unknown"
	}
	return info
}

type Runtime interface {
	Serve() error
	Shutdown(context.Context) error
}

type Factory func(*config.ServerConfig, BuildInfo) (Runtime, error)

func Run(ctx context.Context, runtime Runtime, shutdownTimeout time.Duration) error {
	if runtime == nil {
		return errors.New("server runtime is nil")
	}
	if shutdownTimeout <= 0 {
		return errors.New("shutdown timeout must be positive")
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- runtime.Serve()
	}()

	select {
	case err := <-serveResult:
		return err
	case <-ctx.Done():
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		return fmt.Errorf("shut down API server: %w", err)
	}

	select {
	case err := <-serveResult:
		return err
	case <-shutdownContext.Done():
		return fmt.Errorf("wait for API server shutdown: %w", shutdownContext.Err())
	}
}
