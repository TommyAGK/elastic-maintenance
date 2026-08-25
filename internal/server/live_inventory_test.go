package server

import (
	"context"
	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/kibana"
	"github.com/TommyAGK/elastic-maintenance/internal/liveinventory"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeLiveInventory struct {
	started liveinventory.StartRequest
	probe   liveinventory.Probe
	record  liveinventory.Record
	err     error
}

func (backend *fakeLiveInventory) Probe(context.Context, config.TargetIdentity) liveinventory.Probe {
	return backend.probe
}
func (backend *fakeLiveInventory) Start(_ context.Context, request liveinventory.StartRequest) (jobs.Job, error) {
	backend.started = request
	return backend.record.Job, backend.err
}
func (backend *fakeLiveInventory) Get(context.Context, string) (liveinventory.Record, error) {
	return backend.record, backend.err
}
func TestTargetLiveInventoryRoutesAndPagination(t *testing.T) {
	validation := newPhaseOneBackend()
	now := time.Now().UTC()
	job := jobs.Job{ID: "target-inventory-job", Type: jobs.TypeTargetInventory, Status: jobs.StatusSucceeded, CreatedAt: now, StartedAt: &now, FinishedAt: &now, ActorSubject: "viewer", RequestID: "request-1"}
	backend := &fakeLiveInventory{probe: liveinventory.Probe{Ready: true, Version: "9.4.2", CheckedAt: now}, record: liveinventory.Record{Job: job, TargetID: "target-a", Result: &liveinventory.Result{APIVersion: liveinventory.APIVersion, TargetID: "target-a", KibanaVersion: "9.4.2", CheckedAt: now, Resources: []liveinventory.Resource{{Kind: manifest.KindAgentPolicy, ID: "agent-a", Name: "Agent", Manageable: true, Projection: []byte(`{"id":"agent-a"}`), Fingerprint: &kibana.LiveFingerprint{Algorithm: "sha256", Version: "v1", Value: strings.Repeat("a", 64)}}, {Kind: manifest.KindPackagePolicy, ID: "package-a", Name: "Package", Manageable: true, Projection: []byte(`{"id":"package-a"}`)}}}}}
	actor := auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC, CSRFToken: "csrf-token"}
	recorder := &recordingAudit{}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, ValidationBackend: validation, LiveInventoryBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	for _, path := range []string{"/api/v1/targets/target-a/readiness", "/api/v1/targets/target-a/version"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	start := httptest.NewRequest(http.MethodPost, "https://app.example.test/api/v1/targets/target-a/inventory", strings.NewReader(`{}`))
	start.Header.Set("Content-Type", "application/json")
	start.Header.Set("Idempotency-Key", "inventory-request-1")
	start.Header.Set("Origin", "https://app.example.test")
	start.Header.Set("X-CSRF-Token", "csrf-token")
	startResponse := httptest.NewRecorder()
	handler.ServeHTTP(startResponse, start)
	if startResponse.Code != http.StatusAccepted || backend.started.TargetID != "target-a" || backend.started.Identity.URL != "https://kibana.example.test" {
		t.Fatalf("status=%d body=%s", startResponse.Code, startResponse.Body.String())
	}
	if len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionTargetInventoryCreate || recorder.events[0].JobID != "target-inventory-job" || recorder.events[0].TargetID != "target-a" {
		t.Fatalf("audit=%#v", recorder.events)
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/v1/targets/target-a/inventory/target-inventory-job?pageSize=1", nil))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "nextPageToken") || strings.Contains(first.Body.String(), "created_by") {
		t.Fatalf("first=%d %s", first.Code, first.Body.String())
	}
}
func TestTargetLiveRoutesHideUnknownTargetsAndEnforceViewer(t *testing.T) {
	validation := newPhaseOneBackend()
	backend := &fakeLiveInventory{}
	viewer := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodBearer}}, ValidationBackend: validation, LiveInventoryBackend: backend})
	response := httptest.NewRecorder()
	viewer.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/targets/missing/readiness", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d", response.Code)
	}
	denied := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "none", Method: auth.MethodBearer}}, ValidationBackend: validation, LiveInventoryBackend: backend})
	response = httptest.NewRecorder()
	denied.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/targets/target-a/readiness", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("denied=%d", response.Code)
	}
}
