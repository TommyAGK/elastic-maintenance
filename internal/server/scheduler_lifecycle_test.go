package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

type lifecycleTestScheduler struct {
	mu               sync.Mutex
	healthErr        error
	shutdownErr      error
	shutdownWait     bool
	shutdowns        int
	shutdownContexts []context.Context
	onShutdown       func(context.Context)
}

func (scheduler *lifecycleTestScheduler) Health() error {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.healthErr
}

func (scheduler *lifecycleTestScheduler) Shutdown(ctx context.Context) error {
	scheduler.mu.Lock()
	scheduler.shutdowns++
	scheduler.shutdownContexts = append(scheduler.shutdownContexts, ctx)
	err := scheduler.shutdownErr
	onShutdown := scheduler.onShutdown
	scheduler.mu.Unlock()
	if onShutdown != nil {
		onShutdown(ctx)
	}
	if scheduler.shutdownWait {
		<-ctx.Done()
		return ctx.Err()
	}
	return err
}

func (scheduler *lifecycleTestScheduler) shutdownCount() int {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.shutdowns
}

type lifecycleTestWorker struct {
	mu               sync.Mutex
	shutdownErr      error
	shutdowns        int
	shutdownContexts []context.Context
}

func (worker *lifecycleTestWorker) Shutdown(ctx context.Context) error {
	worker.mu.Lock()
	worker.shutdowns++
	worker.shutdownContexts = append(worker.shutdownContexts, ctx)
	err := worker.shutdownErr
	worker.mu.Unlock()
	return err
}

type lifecycleTestHTTPServer struct {
	serveStarted   chan struct{}
	releaseServe   chan struct{}
	serveErr       error
	shutdownCalled chan struct{}
	serveOnce      sync.Once
	shutdownOnce   sync.Once
}

func (server *lifecycleTestHTTPServer) Serve(net.Listener) error {
	server.serveOnce.Do(func() { close(server.serveStarted) })
	<-server.releaseServe
	return server.serveErr
}

func (server *lifecycleTestHTTPServer) Shutdown(context.Context) error {
	server.shutdownOnce.Do(func() { close(server.shutdownCalled) })
	return nil
}

func (server *lifecycleTestHTTPServer) Close() error { return nil }

func constructorTestHooks(t *testing.T, timeout time.Duration) *runtimeConstructorHooks {
	t.Helper()
	var captured *statefs.Store
	hooks := &runtimeConstructorHooks{
		stateStoreOpened: func(store *statefs.Store) { captured = store },
		cleanupTimeout:   timeout,
	}
	t.Cleanup(func() {
		if captured != nil {
			_ = captured.Close()
		}
	})
	return hooks
}

func TestHTTPRuntimeSchedulerOrderingAndNoStartupSubmissions(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	created := time.Now().UTC().Add(-time.Hour)
	seedServerRecoveryJob(t, cfg.StateDir, serverRecoveryJob("scheduler-queued", jobs.StatusQueued, created))
	seedServerRecoveryJob(t, cfg.StateDir, serverRecoveryJob("scheduler-running", jobs.StatusRunning, created))

	var events []string
	var recoveredRepository *jobrecord.FileRepository
	fake := &lifecycleTestScheduler{}
	factory := func(repository *jobrecord.FileRepository) (schedulerLifecycle, error) {
		events = append(events, "factory")
		recoveredRepository = repository
		for _, id := range []string{"scheduler-queued", "scheduler-running"} {
			record, err := repository.Get(context.Background(), id)
			if err != nil {
				t.Fatalf("get recovered %s: %v", id, err)
			}
			if record.Job.Status != jobs.StatusInterrupted {
				t.Fatalf("record %s status=%s before factory", id, record.Job.Status)
			}
		}
		return fake, nil
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := func(string, string) (net.Listener, error) {
		events = append(events, "listener")
		return listener, nil
	}

	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), listen, factory)
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	if recoveredRepository == nil || runtime.jobRepository != recoveredRepository || runtime.scheduler != fake {
		t.Fatal("runtime did not retain the recovered repository and scheduler")
	}
	if strings.Join(events, ",") != "factory,listener" {
		t.Fatalf("startup ordering=%v", events)
	}
	if got := fake.shutdownCount(); got != 0 {
		t.Fatalf("scheduler shutdowns before runtime shutdown=%d", got)
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRuntimeSchedulerFactoryFailureIsSafeAndDoesNotListen(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	sentinel := errors.New("scheduler secret diagnostic sentinel")
	called := false
	_, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("listener must not be called")
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return nil, sentinel
	})
	if !errors.Is(err, errSchedulerStartup) || strings.Contains(err.Error(), sentinel.Error()) || called {
		t.Fatalf("factory failure=%v listenCalled=%v", err, called)
	}
	reopenStateStore(t, cfg)
}

func TestHTTPRuntimeSchedulerFactoryErrorWithSchedulerRetainsStateOnShutdownFailure(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	sentinel := errors.New("scheduler shutdown sentinel")
	fake := &lifecycleTestScheduler{shutdownErr: sentinel}
	hooks := constructorTestHooks(t, 10*time.Millisecond)
	_, err := newHTTPRuntimeWithSchedulerFactoryAndHooks(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		t.Fatal("listener must not be called")
		return nil, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, errors.New("factory failed")
	}, hooks)
	if !errors.Is(err, errSchedulerStartup) || strings.Contains(err.Error(), sentinel.Error()) {
		t.Fatalf("factory error=%v", err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("scheduler shutdowns=%d", fake.shutdownCount())
	}
	assertStateLockHeld(t, cfg)
}

func TestHTTPRuntimeListenerFailureShutsSchedulerBeforeReleasingState(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	fake := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenErr := errors.New("listener sentinel")
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, listenErr
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if runtimeValue != nil || !errors.Is(err, listenErr) {
		t.Fatalf("runtime=%v error=%v", runtimeValue, err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("scheduler shutdowns=%d", fake.shutdownCount())
	}
	reopenStateStore(t, cfg)
}

func TestHTTPRuntimeConstructorWorkerShutdownFailureRetainsState(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*config.ServerConfig)
		shutdownErr   error
		shutdownWait  bool
		listenerError bool
	}{
		{name: "listener failure", shutdownErr: errors.New("scheduler shutdown failed"), listenerError: true},
		{name: "listener timeout", shutdownWait: true, listenerError: true},
		{name: "later failure", configure: func(cfg *config.ServerConfig) {
			cfg.OIDC.Enabled = true
			cfg.OIDC.SecretMountRoot = filepath.Join(t.TempDir(), "missing")
		}, shutdownErr: errors.New("scheduler shutdown failed")},
		{name: "later timeout", configure: func(cfg *config.ServerConfig) {
			cfg.OIDC.Enabled = true
			cfg.OIDC.SecretMountRoot = filepath.Join(t.TempDir(), "missing")
		}, shutdownWait: true},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := serverRecoveryConfig(t)
			if testCase.configure != nil {
				testCase.configure(cfg)
			}
			fake := &lifecycleTestScheduler{shutdownErr: testCase.shutdownErr, shutdownWait: testCase.shutdownWait}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			hooks := constructorTestHooks(t, 10*time.Millisecond)
			listenErr := error(nil)
			if testCase.listenerError {
				listenErr = errors.New("listener sentinel")
			}
			_, err = newHTTPRuntimeWithSchedulerFactoryAndHooks(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
				return listener, listenErr
			}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
				return fake, nil
			}, hooks)
			if err == nil {
				t.Fatal("constructor unexpectedly succeeded")
			}
			if fake.shutdownCount() != 1 {
				t.Fatalf("scheduler shutdowns=%d", fake.shutdownCount())
			}
			if err := listener.Close(); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("listener was not closed: %v", err)
			}
			assertStateLockHeld(t, cfg)
		})
	}
}

func TestHTTPRuntimeLaterConstructorFailureShutsSchedulerAndReleasesState(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	cfg.OIDC.Enabled = true
	cfg.OIDC.SecretMountRoot = filepath.Join(t.TempDir(), "missing")
	fake := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, err = newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err == nil || fake.shutdownCount() != 1 {
		t.Fatalf("later constructor error=%v scheduler shutdowns=%d", err, fake.shutdownCount())
	}
	reopenStateStore(t, cfg)
}

func TestHTTPRuntimeShutdownRetainsStateWhenCurrentServiceFails(t *testing.T) {
	tests := []struct {
		name string
		set  func(*HTTPRuntime, *lifecycleTestWorker)
	}{
		{name: "validation", set: func(runtime *HTTPRuntime, worker *lifecycleTestWorker) {
			runtime.validation = worker
		}},
		{name: "live inventory", set: func(runtime *HTTPRuntime, worker *lifecycleTestWorker) {
			runtime.liveInventory = worker
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			cfg := serverRecoveryConfig(t)
			fakeScheduler := &lifecycleTestScheduler{}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
				return listener, nil
			}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
				return fakeScheduler, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			runtime := runtimeValue.(*HTTPRuntime)
			worker := &lifecycleTestWorker{shutdownErr: errors.New("service shutdown sentinel")}
			testCase.set(runtime, worker)
			shutdownErr := runtime.Shutdown(context.Background())
			if !errors.Is(shutdownErr, worker.shutdownErr) {
				t.Fatalf("shutdown error=%v", shutdownErr)
			}
			if worker.shutdowns != 1 {
				t.Fatalf("worker shutdowns=%d", worker.shutdowns)
			}
			assertStateLockHeld(t, cfg)
			if err := runtime.closeState(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTTPRuntimeShutdownUsesIndependentWorkerContexts(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	scheduler := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return scheduler, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	live := &lifecycleTestWorker{}
	validation := &lifecycleTestWorker{}
	runtime.liveInventory = live
	runtime.validation = validation
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(live.shutdownContexts) != 1 || len(validation.shutdownContexts) != 1 || len(scheduler.shutdownContexts) != 1 {
		t.Fatalf("shutdown contexts live=%d validation=%d scheduler=%d", len(live.shutdownContexts), len(validation.shutdownContexts), len(scheduler.shutdownContexts))
	}
	contexts := []context.Context{live.shutdownContexts[0], validation.shutdownContexts[0], scheduler.shutdownContexts[0]}
	for first := range contexts {
		for second := first + 1; second < len(contexts); second++ {
			if contexts[first] == contexts[second] {
				t.Fatalf("workers shared shutdown context: %d and %d", first, second)
			}
		}
	}
}

func TestHTTPRuntimeServeUnexpectedExitRaceRetainsState(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	scheduler := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return scheduler, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	server := &lifecycleTestHTTPServer{
		serveStarted:   make(chan struct{}),
		releaseServe:   make(chan struct{}),
		serveErr:       errors.New("forced unexpected serve error"),
		shutdownCalled: make(chan struct{}),
	}
	runtime.server = server
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.Serve() }()
	<-server.serveStarted
	shutdownResult := make(chan error, 1)
	go func() { shutdownResult <- runtime.Shutdown(context.Background()) }()
	<-server.shutdownCalled
	close(server.releaseServe)
	if err := <-serveResult; !errors.Is(err, server.serveErr) {
		t.Fatalf("Serve error=%v", err)
	}
	if err := <-shutdownResult; err != nil {
		t.Fatalf("Shutdown error=%v", err)
	}
	if !runtime.retainState.Load() {
		t.Fatal("unexpected Serve exit did not retain state")
	}
	assertStateLockHeld(t, cfg)
	if err := runtime.closeState(); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRuntimeReadinessIncludesSchedulerHealth(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	fake := &lifecycleTestScheduler{healthErr: errors.New("unhealthy scheduler sentinel")}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	runtime.ready.Store(true)
	if runtime.isReady() {
		t.Fatal("unhealthy scheduler reported ready")
	}
	fake.mu.Lock()
	fake.healthErr = nil
	fake.mu.Unlock()
	if !runtime.isReady() {
		t.Fatal("healthy scheduler did not recover readiness")
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRuntimeNormalShutdownStopsSchedulerBeforeState(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	fake := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	fake.mu.Lock()
	fake.onShutdown = func(context.Context) {
		if err := runtime.stateStore.Check(); err != nil {
			t.Errorf("state closed before scheduler shutdown: %v", err)
		}
	}
	fake.mu.Unlock()
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("scheduler shutdowns=%d", fake.shutdownCount())
	}
	if !errors.Is(runtime.stateStore.Check(), statefs.ErrClosed) {
		t.Fatalf("state remains open after normal shutdown: %v", runtime.stateStore.Check())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runtime.Shutdown(ctx); err != nil {
		t.Fatalf("repeated Shutdown error=%v", err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("repeated Shutdown called scheduler %d times", fake.shutdownCount())
	}
}

func TestHTTPRuntimeUnexpectedServeExitShutsSchedulerAndRetainsState(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	fake := &lifecycleTestScheduler{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.Serve() }()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err == nil {
		t.Fatal("unexpected Serve exit returned nil")
	}
	if fake.shutdownCount() != 1 || !runtime.retainState.Load() {
		t.Fatalf("scheduler shutdowns=%d retainState=%v", fake.shutdownCount(), runtime.retainState.Load())
	}
	if err := runtime.stateStore.Check(); err != nil {
		t.Fatalf("state closed after unexpected Serve exit: %v", err)
	}
	assertStateLockHeld(t, cfg)
	_ = runtime.closeState()
}

func TestHTTPRuntimeSchedulerShutdownTimeoutRetainsStateAndIsSafe(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	fake := &lifecycleTestScheduler{shutdownWait: true}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := runtime.Shutdown(ctx); !errors.Is(err, errSchedulerShutdown) {
		t.Fatalf("scheduler timeout error=%v", err)
	}
	if err := runtime.stateStore.Check(); err != nil {
		t.Fatalf("state not retained after scheduler timeout: %v", err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("scheduler shutdowns=%d", fake.shutdownCount())
	}
	assertStateLockHeld(t, cfg)
	_ = runtime.closeState()
}

func TestHTTPRuntimeSchedulerShutdownFailureRetainsStateAndIsSafe(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	sentinel := errors.New("scheduler lifecycle secret diagnostic sentinel")
	fake := &lifecycleTestScheduler{shutdownErr: sentinel}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntimeWithSchedulerFactory(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	}, func(*jobrecord.FileRepository) (schedulerLifecycle, error) {
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	shutdownErr := runtime.Shutdown(context.Background())
	if !errors.Is(shutdownErr, errSchedulerShutdown) || strings.Contains(shutdownErr.Error(), sentinel.Error()) {
		t.Fatalf("unsafe scheduler shutdown error=%v", shutdownErr)
	}
	if err := runtime.stateStore.Check(); err != nil {
		t.Fatalf("state not retained after scheduler shutdown failure: %v", err)
	}
	assertStateLockHeld(t, cfg)
	if err := runtime.Shutdown(context.Background()); !errors.Is(err, errSchedulerShutdown) {
		t.Fatalf("repeated shutdown error=%v", err)
	}
	if fake.shutdownCount() != 1 {
		t.Fatalf("repeated Shutdown called scheduler %d times", fake.shutdownCount())
	}
	_ = runtime.closeState()
}

func assertStateLockHeld(t *testing.T, cfg *config.ServerConfig) {
	t.Helper()
	ownerUID := os.Geteuid()
	store, err := statefs.Open(statefs.Options{StateDir: cfg.StateDir, ExpectedOwnerUID: &ownerUID, MinFreeBytes: 1})
	if err == nil {
		_ = store.Close()
		t.Fatal("state lock was released")
	}
	if !errors.Is(err, statefs.ErrAlreadyLocked) && !errors.Is(err, statefs.ErrLockUnavailable) {
		t.Fatalf("state lock assertion error=%v", err)
	}
}

func reopenStateStore(t *testing.T, cfg *config.ServerConfig) {
	t.Helper()
	ownerUID := os.Geteuid()
	store, err := statefs.Open(statefs.Options{StateDir: cfg.StateDir, ExpectedOwnerUID: &ownerUID, MinFreeBytes: 1})
	if err != nil {
		t.Fatalf("state lock was not released: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
