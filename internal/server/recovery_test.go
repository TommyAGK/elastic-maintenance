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
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
)

func TestHTTPRuntimeRecoversJobsBeforeListening(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	created := time.Now().UTC().Add(-10 * time.Minute)
	seedServerRecoveryJob(t, cfg.StateDir, serverRecoveryJob("startup-queued", jobs.StatusQueued, created))
	seedServerRecoveryJob(t, cfg.StateDir, serverRecoveryJob("startup-running", jobs.StatusRunning, created))
	seedServerRecoveryJob(t, cfg.StateDir, serverRecoveryJob("startup-terminal", jobs.StatusSucceeded, created))

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	called := false
	listen := func(network, address string) (net.Listener, error) {
		called = true
		if network != "tcp" || address != cfg.Listen {
			t.Fatalf("listen(%q, %q)", network, address)
		}
		for _, id := range []string{"startup-queued", "startup-running"} {
			encoded, readErr := os.ReadFile(filepath.Join(cfg.StateDir, statefs.JobsDir, id+".json"))
			if readErr != nil {
				t.Fatalf("read recovered %s: %v", id, readErr)
			}
			job, decodeErr := state.DecodeJob(encoded)
			if decodeErr != nil || job.Status != jobs.StatusInterrupted {
				t.Fatalf("job %s before listen = %#v, err=%v", id, job, decodeErr)
			}
		}
		return listener, nil
	}

	runtimeValue, err := newHTTPRuntime(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), listen)
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	if !called {
		t.Fatal("listener was not called")
	}
	if runtime.jobRepository == nil {
		t.Fatal("durable job repository was not retained")
	}
	if want := (jobrecord.RecoverySummary{Examined: 3, Preserved: 1, Interrupted: 2}); runtime.recovery != want {
		t.Fatalf("recovery summary=%#v want=%#v", runtime.recovery, want)
	}
	if err := runtime.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPRuntimeMalformedRecoveryClosesStateBeforeReturning(t *testing.T) {
	cfg := serverRecoveryConfig(t)
	ownerUID := os.Geteuid()
	store, err := statefs.Open(statefs.Options{StateDir: cfg.StateDir, ExpectedOwnerUID: &ownerUID, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	sentinel := "SERVER_RECOVERY_SECRET_SENTINEL"
	bad := []byte(`{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"Job","unknown":"` + sentinel + `"}`)
	if err := store.WriteAtomic(statefs.JobsDir+"/bad-startup.json", bad, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	called := false
	_, err = newHTTPRuntime(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("listener must not be called")
	})
	if !errors.Is(err, jobrecord.ErrRecovery) || !errors.Is(err, jobrecord.ErrRecoveryCorrupt) || !strings.Contains(err.Error(), "recover durable jobs") {
		t.Fatalf("constructor error=%v", err)
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "bad-startup") || strings.Contains(err.Error(), "unknown") {
		t.Fatalf("unsafe constructor error=%v", err)
	}
	if called {
		t.Fatal("listener was called after malformed recovery")
	}

	reopened, err := statefs.Open(statefs.Options{StateDir: cfg.StateDir, ExpectedOwnerUID: &ownerUID, MinFreeBytes: 1})
	if err != nil {
		t.Fatalf("state lock was not released after recovery failure: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func serverRecoveryConfig(t *testing.T) *config.ServerConfig {
	t.Helper()
	cfg, err := config.LoadServerConfig("../config/testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.Enabled = false
	cfg.StateDir = t.TempDir()
	if err := os.Chmod(cfg.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func seedServerRecoveryJob(t *testing.T, root string, job state.Job) {
	t.Helper()
	ownerUID := os.Geteuid()
	store, err := statefs.Open(statefs.Options{StateDir: root, ExpectedOwnerUID: &ownerUID, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := state.EncodeJob(job)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/"+job.ID+".json", encoded, false); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func serverRecoveryJob(id string, status jobs.Status, created time.Time) state.Job {
	job := state.Job{
		APIVersion:     state.APIVersion,
		Kind:           state.KindJob,
		ID:             id,
		Type:           jobs.TypeValidation,
		Status:         status,
		CreatedAt:      created.UTC(),
		Actor:          state.Actor{Subject: "operator@example.test", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC},
		RequestID:      "request-" + id,
		IdempotencyKey: "idem-" + id,
		RequestDigest:  strings.Repeat("a", 64),
	}
	if status == jobs.StatusRunning {
		started := created.Add(time.Minute).UTC()
		job.StartedAt = &started
	}
	if status == jobs.StatusSucceeded {
		finished := created.Add(2 * time.Minute).UTC()
		job.FinishedAt = &finished
	}
	return job
}
