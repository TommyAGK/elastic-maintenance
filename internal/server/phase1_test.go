package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
	"github.com/TommyAGK/elastic-maintenance/internal/validation"
)

type phaseOneBackend struct {
	snapshot *manifest.SourceSnapshot
	record   validation.Record
	started  validation.StartRequest
	err      error
}

func (backend *phaseOneBackend) Start(_ context.Context, request validation.StartRequest) (jobs.Job, error) {
	backend.started = request
	if backend.err != nil {
		return jobs.Job{}, backend.err
	}
	return backend.record.Job, nil
}
func (backend *phaseOneBackend) Get(_ context.Context, id string) (validation.Record, error) {
	if backend.err != nil {
		return validation.Record{}, backend.err
	}
	if id != backend.record.Job.ID {
		return validation.Record{}, jobs.ErrNotFound
	}
	return backend.record, nil
}
func (backend *phaseOneBackend) List(_ context.Context, _ jobs.ListOptions) (validation.RecordPage, error) {
	if backend.err != nil {
		return validation.RecordPage{}, backend.err
	}
	return validation.RecordPage{Records: []validation.Record{backend.record}}, nil
}
func (backend *phaseOneBackend) CurrentSnapshot(context.Context) (*manifest.SourceSnapshot, error) {
	if backend.err != nil {
		return nil, backend.err
	}
	return backend.snapshot, nil
}

func TestPhaseOneInventoryEndpointsReturnSafePaginatedViews(t *testing.T) {
	backend := newPhaseOneBackend()
	handler := phaseOneHandler(backend, auth.RoleViewer)

	response := serveRequest(handler, http.MethodGet, "/api/v1/sources?pageSize=1", "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"source-a"`) || !strings.Contains(response.Body.String(), "nextPageToken") {
		t.Fatalf("source list status=%d body=%s", response.Code, response.Body.String())
	}
	var sourceList api.SourceListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &sourceList); err != nil {
		t.Fatal(err)
	}
	response = serveRequest(handler, http.MethodGet, "/api/v1/sources?pageSize=1&pageToken="+sourceList.NextPageToken, "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"source-b"`) {
		t.Fatalf("source page 2 status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveRequest(handler, http.MethodGet, "/api/v1/sources/source-a", "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"relativePath":"resource.yaml"`) {
		t.Fatalf("source detail status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveRequest(handler, http.MethodGet, "/api/v1/targets/target-a", "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"resourceSetID":"source-a"`) {
		t.Fatalf("target detail status=%d body=%s", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"credential-sentinel", "/absolute/", "source-body-sentinel", "credentialSecret"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response leaked %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestPhaseOneValidationEndpointsEnforceContractAndRBAC(t *testing.T) {
	backend := newPhaseOneBackend()
	planner := phaseOneHandler(backend, auth.RolePlanner)
	response := serveRequest(planner, http.MethodPost, "/api/v1/validations", `{"targetIds":["target-a"]}`, "validation-key-1")
	if response.Code != http.StatusAccepted {
		t.Fatalf("create status=%d body=%s", response.Code, response.Body.String())
	}
	if backend.started.ActorSubject != "operator-1" || backend.started.IdempotencyKey != "validation-key-1" || len(backend.started.Selection.TargetIDs) != 1 {
		t.Fatalf("start request = %#v", backend.started)
	}
	response = serveRequest(planner, http.MethodGet, "/api/v1/validations", "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), backend.record.Job.ID) {
		t.Fatalf("list status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveRequest(planner, http.MethodGet, "/api/v1/validations/"+backend.record.Job.ID, "", "")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"valid":true`) {
		t.Fatalf("detail status=%d body=%s", response.Code, response.Body.String())
	}

	viewer := phaseOneHandler(backend, auth.RoleViewer)
	response = serveRequest(viewer, http.MethodPost, "/api/v1/validations", `{}`, "validation-key-2")
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer create status=%d body=%s", response.Code, response.Body.String())
	}
	response = serveRequest(planner, http.MethodPost, "/api/v1/validations", `{"targetIds":[],"targetIds":[]}`, "validation-key-3")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate JSON status=%d body=%s", response.Code, response.Body.String())
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/validations", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add(api.IdempotencyKeyHeader, "validation-key-4")
	request.Header.Add(api.IdempotencyKeyHeader, "validation-key-5")
	response = httptest.NewRecorder()
	planner.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("duplicate header status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestValidationCreationRequiresBrowserCSRFButAllowsBearer(t *testing.T) {
	backend := newPhaseOneBackend()
	browser := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "planner", Roles: []auth.Role{auth.RolePlanner}, Method: auth.MethodOIDC, CSRFToken: "csrf"}}, ValidationBackend: backend, PublicURL: "https://app.example.test"})
	request := httptest.NewRequest(http.MethodPost, "https://app.example.test/api/v1/validations", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(api.IdempotencyKeyHeader, "validation-csrf")
	request.Header.Set("Origin", "https://app.example.test")
	response := httptest.NewRecorder()
	browser.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF status=%d", response.Code)
	}
	bearer := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "automation", Roles: []auth.Role{auth.RolePlanner}, Method: auth.MethodBearer}}, ValidationBackend: backend, PublicURL: "https://app.example.test"})
	request = httptest.NewRequest(http.MethodPost, "https://app.example.test/api/v1/validations", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(api.IdempotencyKeyHeader, "validation-bearer")
	response = httptest.NewRecorder()
	bearer.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("bearer status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPhaseOneBackendErrorsAreRedacted(t *testing.T) {
	backend := newPhaseOneBackend()
	backend.err = errors.New("credential-sentinel /absolute/secret")
	handler := phaseOneHandler(backend, auth.RoleViewer)
	response := serveRequest(handler, http.MethodGet, "/api/v1/sources", "", "")
	if response.Code != http.StatusUnprocessableEntity || strings.Contains(response.Body.String(), "credential-sentinel") || strings.Contains(response.Body.String(), "/absolute/") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func phaseOneHandler(backend ValidationBackend, roles ...auth.Role) http.Handler {
	return NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "operator-1", Roles: roles, CSRFToken: "csrf-token"}}, ValidationBackend: backend, PublicURL: "http://localhost"})
}

func serveRequest(handler http.Handler, method, path, body, key string) *httptest.ResponseRecorder {
	requestURL := path
	if method == http.MethodPost && strings.HasPrefix(path, "/") {
		requestURL = "http://localhost" + path
	}
	request := httptest.NewRequest(method, requestURL, strings.NewReader(body))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://localhost")
		request.Header.Set(api.CSRFTokenHeader, "csrf-token")
	}
	if key != "" {
		request.Header.Set(api.IdempotencyKeyHeader, key)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func newPhaseOneBackend() *phaseOneBackend {
	digest := manifest.DesiredDigest{Algorithm: "sha256", Version: manifest.DesiredDigestVersion, Value: strings.Repeat("a", 64)}
	resource := manifest.ResourceSnapshot{Resource: manifest.ResourceIdentity{Kind: manifest.KindAgentPolicy, ID: "agents"}, Source: source.Location{ResourceSetID: "source-a", RelativePath: "resource.yaml", Document: 1, Line: 1, Column: 1}, DesiredDigest: digest}
	snapshot := &manifest.SourceSnapshot{APIVersion: manifest.SourceSnapshotAPIVersion, DigestDomain: manifest.DesiredDigestDomain, DigestVersion: manifest.DesiredDigestVersion,
		ResourceSets: []manifest.ResourceSetSnapshot{{ID: "source-a", DesiredDigest: digest, Files: []source.RawFileDigest{{RelativePath: "resource.yaml", SHA256: strings.Repeat("b", 64), Bytes: 100}}, Resources: []manifest.ResourceSnapshot{resource}}, {ID: "source-b", DesiredDigest: digest, Files: []source.RawFileDigest{}, Resources: []manifest.ResourceSnapshot{}}},
		Targets:      []manifest.TargetSnapshot{{Identity: manifest.InventoryTargetIdentity{StateID: "state", Name: "target-a", URL: "https://kibana.example.test", Space: "default"}, Labels: []manifest.Label{{Key: "environment", Value: "test"}}, ResourceSetID: "source-a", DesiredDigest: digest, Resources: []manifest.ResourceSnapshot{resource}}},
	}
	created := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	finished := created.Add(time.Second)
	job := jobs.Job{ID: "validation-1", Type: jobs.TypeValidation, Status: jobs.StatusSucceeded, CreatedAt: created, StartedAt: &created, FinishedAt: &finished, ActorSubject: "operator-1", RequestID: "request-1", IdempotencyKey: "validation-key-1", RequestDigest: strings.Repeat("c", 64)}
	result := &validation.Result{APIVersion: validation.ResultAPIVersion, Valid: true, Snapshot: snapshot, Diagnostics: []validation.Diagnostic{}}
	return &phaseOneBackend{snapshot: snapshot, record: validation.Record{Job: job, Result: result}}
}
