package main

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/server"
)

func TestExecuteVersionNeedsNoConfiguration(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	code := execute(
		context.Background(),
		[]string{"--version"},
		&stdout,
		&stderr,
		emptyLookup,
		func(*config.ServerConfig, server.BuildInfo) (server.Runtime, error) {
			called = true
			return nil, nil
		},
		server.BuildInfo{Version: "1.2.3", Commit: "abc123", Date: "2026-08-14"},
		time.Second,
	)
	if code != 0 || stdout.String() != "elastic-maintainer version=1.2.3 commit=abc123 date=2026-08-14\n" || stderr.Len() != 0 || called {
		t.Fatalf("code=%d stdout=%q stderr=%q factoryCalled=%v", code, stdout.String(), stderr.String(), called)
	}
}

func TestExecuteVersionNormalizesEmptyBuildInfo(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"--version"}, &stdout, &stderr, emptyLookup, nil, server.BuildInfo{}, time.Second)
	if code != 0 || stdout.String() != "elastic-maintainer version=dev commit=none date=unknown\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestExecuteHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := execute(context.Background(), []string{"--help"}, &stdout, &stderr, emptyLookup, nil, server.BuildInfo{}, time.Second)
	if code != 0 || stdout.String() != startupUsage+"\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestExecuteRejectsOperatorCLIAndCredentialFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"plan command":  {"plan"},
		"apply command": {"apply"},
		"API key flag":  {"--api-key", "sensitive-value"},
		"mode flag":     {"--mode", "apply"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), args, &stdout, &stderr, emptyLookup, nil, server.BuildInfo{}, time.Second)
			if code != 1 || stdout.Len() != 0 || strings.Count(stderr.String(), "elastic-maintainer:") != 1 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stderr.String(), "sensitive-value") {
				t.Fatalf("stderr exposed a rejected credential value: %q", stderr.String())
			}
		})
	}
}

func TestExecuteLoadsValidatesAndStartsRuntime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var receivedConfig *config.ServerConfig
	var receivedBuild server.BuildInfo
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	code := execute(
		ctx,
		[]string{
			"--config", validConfigPath(),
			"--listen", "127.0.0.1:9090",
			"--state-dir", "/tmp/elastic-maintainer-state",
		},
		&stdout,
		&stderr,
		emptyLookup,
		func(cfg *config.ServerConfig, build server.BuildInfo) (server.Runtime, error) {
			receivedConfig = cfg
			receivedBuild = build
			return &blockingRuntime{stopped: make(chan struct{})}, nil
		},
		server.BuildInfo{},
		time.Second,
	)
	if code != 0 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if receivedConfig == nil || receivedConfig.Listen != "127.0.0.1:9090" || receivedConfig.StateDir != "/tmp/elastic-maintainer-state" || receivedConfig.PublicURL != "https://elastic-maintainer.example.test" {
		t.Fatalf("received config = %#v", receivedConfig)
	}
	if receivedBuild != (server.BuildInfo{Version: "dev", Commit: "none", Date: "unknown"}) {
		t.Fatalf("received build = %#v", receivedBuild)
	}
}

func TestExecuteValidatesBeforeCreatingRuntime(t *testing.T) {
	var stdout, stderr bytes.Buffer
	called := false
	code := execute(
		context.Background(),
		[]string{"--config", validConfigPath(), "--public-url", "http://public.example.test"},
		&stdout,
		&stderr,
		emptyLookup,
		func(*config.ServerConfig, server.BuildInfo) (server.Runtime, error) {
			called = true
			return nil, nil
		},
		server.BuildInfo{},
		time.Second,
	)
	if code != 1 || called || !strings.Contains(stderr.String(), "validate server config: publicURL must use HTTPS") {
		t.Fatalf("code=%d called=%v stderr=%q", code, called, stderr.String())
	}
}

func TestExecuteReportsFactoryAndRuntimeErrorsOnce(t *testing.T) {
	for name, testCase := range map[string]struct {
		factory server.Factory
		want    string
	}{
		"factory": {
			factory: func(*config.ServerConfig, server.BuildInfo) (server.Runtime, error) {
				return nil, errors.New("factory failed")
			},
			want: "create API server: factory failed",
		},
		"runtime": {
			factory: func(*config.ServerConfig, server.BuildInfo) (server.Runtime, error) {
				return failingRuntime{err: errors.New("serve failed")}, nil
			},
			want: "run API server: serve failed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := execute(context.Background(), []string{"--config", validConfigPath()}, &stdout, &stderr, emptyLookup, testCase.factory, server.BuildInfo{}, time.Second)
			if code != 1 || stdout.Len() != 0 || strings.Count(stderr.String(), "elastic-maintainer:") != 1 || !strings.Contains(stderr.String(), testCase.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func emptyLookup(string) (string, bool) { return "", false }

func validConfigPath() string {
	return filepath.Join("..", "..", "internal", "config", "testdata", "server-valid.yaml")
}

type blockingRuntime struct {
	stopped chan struct{}
}

func (runtime *blockingRuntime) Serve() error {
	<-runtime.stopped
	return nil
}

func (runtime *blockingRuntime) Shutdown(context.Context) error {
	close(runtime.stopped)
	return nil
}

type failingRuntime struct {
	err error
}

func (runtime failingRuntime) Serve() error { return runtime.err }

func (failingRuntime) Shutdown(context.Context) error { return nil }
