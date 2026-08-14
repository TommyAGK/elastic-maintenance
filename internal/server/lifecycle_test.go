package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuildInfoNormalized(t *testing.T) {
	got := (BuildInfo{}).Normalized()
	if got.Version != "dev" || got.Commit != "none" || got.Date != "unknown" {
		t.Fatalf("Normalized() = %#v", got)
	}

	provided := BuildInfo{Version: "1.2.3", Commit: "abc123", Date: "2026-08-14"}
	if got := provided.Normalized(); got != provided {
		t.Fatalf("Normalized() = %#v", got)
	}
}

func TestRunReturnsServeFailure(t *testing.T) {
	want := errors.New("listen failed")
	runtime := &fakeRuntime{serve: func() error { return want }}
	if err := Run(context.Background(), runtime, time.Second); !errors.Is(err, want) {
		t.Fatalf("Run() error = %v", err)
	}
	if runtime.shutdownCalls() != 0 {
		t.Fatalf("Shutdown() calls = %d", runtime.shutdownCalls())
	}
}

func TestRunGracefullyShutsDownAfterCancellation(t *testing.T) {
	stopped := make(chan struct{})
	runtime := &fakeRuntime{
		serve: func() error {
			<-stopped
			return nil
		},
		shutdown: func(context.Context) error {
			close(stopped)
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Run(ctx, runtime, time.Second); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if runtime.shutdownCalls() != 1 {
		t.Fatalf("Shutdown() calls = %d", runtime.shutdownCalls())
	}
}

func TestRunReturnsShutdownFailure(t *testing.T) {
	want := errors.New("shutdown failed")
	stopped := make(chan struct{})
	runtime := &fakeRuntime{
		serve: func() error {
			<-stopped
			return nil
		},
		shutdown: func(context.Context) error {
			close(stopped)
			return want
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, runtime, time.Second)
	if !errors.Is(err, want) || !strings.Contains(err.Error(), "shut down API server") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunTimesOutWaitingForServe(t *testing.T) {
	stopped := make(chan struct{})
	runtime := &fakeRuntime{
		serve: func() error {
			<-stopped
			return nil
		},
		shutdown: func(context.Context) error {
			go func() {
				time.Sleep(50 * time.Millisecond)
				close(stopped)
			}()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := Run(ctx, runtime, 10*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "wait for API server shutdown") {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestRunRejectsInvalidInputs(t *testing.T) {
	if err := Run(context.Background(), nil, time.Second); err == nil {
		t.Fatal("Run(nil) error = nil")
	}
	if err := Run(context.Background(), &fakeRuntime{}, 0); err == nil {
		t.Fatal("Run(timeout=0) error = nil")
	}
}

func TestPendingRuntimeIsExplicit(t *testing.T) {
	runtime, err := NewPendingRuntime(nil, BuildInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Serve(); !errors.Is(err, ErrRuntimePending) {
		t.Fatalf("Serve() error = %v", err)
	}
}

type fakeRuntime struct {
	serve    func() error
	shutdown func(context.Context) error

	mu            sync.Mutex
	shutdownCount int
}

func (runtime *fakeRuntime) Serve() error {
	if runtime.serve == nil {
		return nil
	}
	return runtime.serve()
}

func (runtime *fakeRuntime) Shutdown(ctx context.Context) error {
	runtime.mu.Lock()
	runtime.shutdownCount++
	runtime.mu.Unlock()
	if runtime.shutdown == nil {
		return nil
	}
	return runtime.shutdown(ctx)
}

func (runtime *fakeRuntime) shutdownCalls() int {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.shutdownCount
}
