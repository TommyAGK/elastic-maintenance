package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecovery"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
	"github.com/TommyAGK/elastic-maintenance/internal/statefs"
	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

type jobReadTestBackend struct {
	records   []jobrecord.Record
	getErr    error
	listErr   error
	getCalls  int
	listCalls int
	getID     string
	options   jobs.ListOptions
	page      jobrecord.Page
}

func (backend *jobReadTestBackend) Get(_ context.Context, id string) (jobrecord.Record, error) {
	backend.getCalls++
	backend.getID = id
	if backend.getErr != nil {
		return jobrecord.Record{}, backend.getErr
	}
	for _, record := range backend.records {
		if record.Job.ID == id {
			return record, nil
		}
	}
	return jobrecord.Record{}, jobs.ErrNotFound
}

func (backend *jobReadTestBackend) List(_ context.Context, options jobs.ListOptions) (jobrecord.Page, error) {
	backend.listCalls++
	backend.options = options
	if backend.listErr != nil {
		return jobrecord.Page{}, backend.listErr
	}
	if backend.page.Records != nil || backend.page.NextPageToken != "" {
		return backend.page, nil
	}
	return jobrecord.Page{Records: append([]jobrecord.Record(nil), backend.records...)}, nil
}

func TestJobReadAuthorizationAndMethods(t *testing.T) {
	backend := &jobReadTestBackend{records: []jobrecord.Record{{Job: httpJob("auth-job", jobs.TypeValidation, jobs.StatusQueued)}}}
	unauthenticated := NewHandler(HandlerOptions{JobReadBackend: backend})
	response := serveJobRequest(unauthenticated, http.MethodGet, "/api/v1/jobs", nil)
	if response.Code != http.StatusUnauthorized || backend.listCalls != 0 {
		t.Fatalf("unauthenticated list status=%d calls=%d body=%s", response.Code, backend.listCalls, response.Body.String())
	}
	response = serveJobRequest(unauthenticated, http.MethodGet, "/api/v1/jobs/auth-job", nil)
	if response.Code != http.StatusUnauthorized || backend.getCalls != 0 {
		t.Fatalf("unauthenticated get status=%d calls=%d body=%s", response.Code, backend.getCalls, response.Body.String())
	}

	denied := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "no-job-read", Roles: []auth.Role{}}},
		JobReadBackend: backend,
	})
	response = serveJobRequest(denied, http.MethodGet, "/api/v1/jobs", nil)
	if response.Code != http.StatusForbidden || backend.listCalls != 0 {
		t.Fatalf("denied list status=%d calls=%d body=%s", response.Code, backend.listCalls, response.Body.String())
	}

	for _, role := range auth.KnownRoles() {
		backend.listCalls, backend.getCalls = 0, 0
		handler := NewHandler(HandlerOptions{
			Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{role}}},
			JobReadBackend: backend,
		})
		if response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs", nil); response.Code != http.StatusOK {
			t.Errorf("role=%s list status=%d body=%s", role, response.Code, response.Body.String())
		}
		if response := serveJobRequest(handler, http.MethodHead, "/api/v1/jobs/auth-job", nil); response.Code != http.StatusOK || response.Body.Len() != 0 {
			t.Errorf("role=%s HEAD status=%d body=%q", role, response.Code, response.Body.String())
		}
		if backend.getCalls != 1 {
			t.Errorf("role=%s get calls=%d", role, backend.getCalls)
		}
	}

	wrongMethod := serveJobRequest(NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: backend,
	}), http.MethodPost, "/api/v1/jobs", nil)
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("wrong method status=%d allow=%q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}
}

func TestJobListProjectsEveryCurrentTypeAndStatus(t *testing.T) {
	types := []jobs.Type{jobs.TypeValidation, jobs.TypePlan, jobs.TypeApply, jobs.TypeTargetInventory}
	statuses := []jobs.Status{jobs.StatusQueued, jobs.StatusRunning, jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled, jobs.StatusInterrupted}
	backend := &jobReadTestBackend{}
	for typeIndex, jobType := range types {
		for statusIndex, status := range statuses {
			job := httpJob("matrix-"+string(rune('a'+typeIndex*len(statuses)+statusIndex)), jobType, status)
			backend.records = append(backend.records, jobrecord.Record{Job: job})
		}
	}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: backend,
	})
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body api.JobListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Jobs) != len(types)*len(statuses) {
		t.Fatalf("got %d jobs, want %d", len(body.Jobs), len(types)*len(statuses))
	}
	seen := make(map[string]bool, len(body.Jobs))
	for _, job := range body.Jobs {
		seen[string(job.Type)+"/"+string(job.Status)] = true
	}
	for _, jobType := range types {
		for _, status := range statuses {
			if !seen[string(jobType)+"/"+string(status)] {
				t.Errorf("missing %s/%s", jobType, status)
			}
		}
	}
}

func TestJobGetSafeProjectionAndNotFoundContract(t *testing.T) {
	job := httpJob("visible-job", jobs.TypeApply, jobs.StatusFailed)
	job.Actor = state.Actor{Subject: "actor-visible", Roles: []auth.Role{auth.Role("ACTOR_ROLE_SENTINEL")}, Method: auth.Method("AUTH_METHOD_SENTINEL")}
	job.IdempotencyKey = "IDEMPOTENCY_KEY_SENTINEL"
	job.RequestDigest = "REQUEST_DIGEST_SENTINEL"
	job.PlanID = "PLAN_LINK_SENTINEL"
	job.ReportID = "REPORT_LINK_SENTINEL"
	job.CancellationRequested = true
	job.FailureCode = "failure-visible"
	backend := &jobReadTestBackend{records: []jobrecord.Record{{Job: job}}}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: backend,
	})
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs/visible-job", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var body api.JobResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.APIVersion != api.Version || body.Job.ID != job.ID || body.Job.Type != job.Type || body.Job.Status != job.Status || body.Job.ActorSubject != job.Actor.Subject || body.Job.RequestID != job.RequestID || body.Job.FailureCode != job.FailureCode {
		t.Fatalf("projection=%#v", body)
	}
	if body.Job.IdempotencyKey != "" || body.Job.RequestDigest != "" {
		t.Fatalf("sensitive projection fields populated=%#v", body.Job)
	}
	for _, forbidden := range []string{`"actor":`, `"roles":`, `"authMethod":`, `"etag":`, `"idempotencyKey":`, `"requestDigest":`, `"planID":`, `"reportID":`, `"cancellationRequested":`, "ACTOR_ROLE_SENTINEL", "AUTH_METHOD_SENTINEL", "IDEMPOTENCY_KEY_SENTINEL", "REQUEST_DIGEST_SENTINEL", "PLAN_LINK_SENTINEL", "REPORT_LINK_SENTINEL"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Errorf("response contains forbidden %q: %s", forbidden, response.Body.String())
		}
	}

	for _, path := range []string{"/api/v1/jobs/no-such-job", "/api/v1/jobs/not%20a%20job", "/api/v1/jobs/visible-job/extra", "/api/v1/jobs/"} {
		response := serveJobRequest(handler, http.MethodGet, path, nil)
		if response.Code != http.StatusNotFound || !strings.Contains(response.Body.String(), `"code":"job_not_found"`) {
			t.Errorf("path=%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	response = serveJobRequest(handler, http.MethodGet, "/api/v1/jobs/visible-job?unexpected=sentinel", nil)
	if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "unexpected") || strings.Contains(response.Body.String(), "sentinel") {
		t.Fatalf("invalid detail query status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestJobListStrictQueryAndOpaqueRepositoryToken(t *testing.T) {
	token := strings.Repeat("t", 512)
	backend := &jobReadTestBackend{page: jobrecord.Page{Records: []jobrecord.Record{{Job: httpJob("filtered", jobs.TypePlan, jobs.StatusInterrupted)}}, NextPageToken: token}}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: backend,
	})
	query := url.Values{}
	query.Add("pageSize", "7")
	query.Add("pageToken", token)
	query.Add("type", string(jobs.TypePlan))
	query.Add("type", string(jobs.TypeApply))
	query.Add("status", string(jobs.StatusInterrupted))
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?"+query.Encode(), nil)
	if response.Code != http.StatusOK {
		t.Fatalf("valid query status=%d body=%s", response.Code, response.Body.String())
	}
	if backend.options.PageSize != 7 || backend.options.PageToken != token || len(backend.options.Types) != 2 || backend.options.Types[0] != jobs.TypePlan || backend.options.Types[1] != jobs.TypeApply || len(backend.options.Statuses) != 1 || backend.options.Statuses[0] != jobs.StatusInterrupted {
		t.Fatalf("repository options=%#v", backend.options)
	}
	var body api.JobListResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Jobs == nil || len(body.Jobs) != 1 || body.NextPageToken != token || !strings.Contains(response.Body.String(), token) {
		t.Fatalf("list response=%#v body=%s", body, response.Body.String())
	}

	invalid := []struct {
		name, query, code string
	}{
		{"unknown parameter", "unknown=sentinel", "invalid_job_query"},
		{"duplicate page size", "pageSize=1&pageSize=1", "invalid_job_query"},
		{"empty page size", "pageSize=", "invalid_job_query"},
		{"zero page size", "pageSize=0", "invalid_job_query"},
		{"too large page size", "pageSize=101", "invalid_job_query"},
		{"empty token", "pageToken=", "invalid_page_token"},
		{"too long token", "pageToken=" + strings.Repeat("x", 513), "invalid_page_token"},
		{"empty type", "type=", "invalid_job_filter"},
		{"unknown type", "type=unknown", "invalid_job_filter"},
		{"duplicate type", "type=plan&type=plan", "invalid_job_filter"},
		{"empty status", "status=", "invalid_job_filter"},
		{"unknown status", "status=unknown", "invalid_job_filter"},
		{"duplicate status", "status=failed&status=failed", "invalid_job_filter"},
		{"too many types", strings.TrimSuffix(strings.Repeat("type=plan&", 17), "&"), "invalid_job_filter"},
		{"too many statuses", strings.TrimSuffix(strings.Repeat("status=failed&", 17), "&"), "invalid_job_filter"},
		{"malformed query", "%zz", "invalid_job_query"},
	}
	for _, testCase := range invalid {
		t.Run(testCase.name, func(t *testing.T) {
			before := backend.listCalls
			response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?"+testCase.query, nil)
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"`+testCase.code+`"`) || strings.Contains(response.Body.String(), "sentinel") {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, backend.listCalls, response.Body.String())
			}
			if backend.listCalls != before {
				t.Fatal("invalid query reached repository")
			}
		})
	}
}

func TestJobListErrorMappingAndSafeEmptyArray(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"page changed", jobrecord.ErrPageChanged, http.StatusConflict, "job_page_changed"},
		{"invalid options", jobrecord.ErrInvalidOptions, http.StatusBadRequest, "invalid_job_options"},
		{"invalid token", jobrecord.ErrInvalidPageToken, http.StatusBadRequest, "invalid_page_token"},
		{"context canceled", context.Canceled, http.StatusServiceUnavailable, "jobs_unavailable"},
		{"backend", errors.New("backend SECRET_SENTINEL"), http.StatusServiceUnavailable, "jobs_unavailable"},
		{"corrupt", statefs.ErrCorrupt, http.StatusServiceUnavailable, "jobs_unavailable"},
		{"scan", jobrecord.ErrScanLimit, http.StatusServiceUnavailable, "jobs_unavailable"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			handler := NewHandler(HandlerOptions{
				Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
				JobReadBackend: &jobReadTestBackend{listErr: testCase.err},
			})
			response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs", nil)
			if response.Code != testCase.status || !strings.Contains(response.Body.String(), `"code":"`+testCase.code+`"`) || strings.Contains(response.Body.String(), "SECRET_SENTINEL") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}

	backend := &jobReadTestBackend{page: jobrecord.Page{Records: []jobrecord.Record{}}}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: backend,
	})
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs", nil)
	var body api.JobListResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Jobs == nil || len(body.Jobs) != 0 {
		t.Fatalf("empty response status=%d body=%s decoded=%#v", response.Code, response.Body.String(), body)
	}
}

func TestJobRepositoryHTTPProjectionPreservesStoredBytesAndPagination(t *testing.T) {
	repository, store, _ := newHTTPJobRepository(t)
	for index, status := range []jobs.Status{jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusCanceled} {
		job := httpJob("page-job-"+string(rune('a'+index)), jobs.TypeValidation, status)
		job.CreatedAt = time.Date(2026, 1, 2, 3, 4, index, 0, time.UTC)
		encoded, err := state.EncodeJob(job)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteAtomic(statefs.JobsDir+"/"+job.ID+".json", encoded, false); err != nil {
			t.Fatal(err)
		}
	}
	before := make(map[string][]byte)
	for _, id := range []string{"page-job-a", "page-job-b", "page-job-c"} {
		encoded, err := store.Read(statefs.JobsDir + "/" + id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		before[id] = encoded
	}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: repository,
	})
	var token string
	for index, wantID := range []string{"page-job-a", "page-job-b", "page-job-c"} {
		path := "/api/v1/jobs?pageSize=1"
		if token != "" {
			path += "&pageToken=" + url.QueryEscape(token)
		}
		response := serveJobRequest(handler, http.MethodGet, path, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("page=%d status=%d body=%s", index, response.Code, response.Body.String())
		}
		var body api.JobListResponse
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Jobs) != 1 || body.Jobs[0].ID != wantID {
			t.Fatalf("page=%d body=%s decoded=%#v err=%v", index, response.Body.String(), body, err)
		}
		token = body.NextPageToken
		if index < 2 && token == "" || index == 2 && token != "" {
			t.Fatalf("page=%d next token=%q", index, token)
		}
	}
	combined := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?type=validation&status=succeeded", nil)
	var combinedBody api.JobListResponse
	if combined.Code != http.StatusOK || json.Unmarshal(combined.Body.Bytes(), &combinedBody) != nil || len(combinedBody.Jobs) != 1 || combinedBody.Jobs[0].ID != "page-job-a" || combinedBody.Jobs[0].Type != jobs.TypeValidation || combinedBody.Jobs[0].Status != jobs.StatusSucceeded {
		t.Fatalf("combined filtered page status=%d body=%s decoded=%#v", combined.Code, combined.Body.String(), combinedBody)
	}
	empty := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?type=apply", nil)
	var emptyBody api.JobListResponse
	if empty.Code != http.StatusOK || json.Unmarshal(empty.Body.Bytes(), &emptyBody) != nil || emptyBody.Jobs == nil || len(emptyBody.Jobs) != 0 {
		t.Fatalf("empty filtered page status=%d body=%s", empty.Code, empty.Body.String())
	}
	for id, want := range before {
		got, err := store.Read(statefs.JobsDir + "/" + id + ".json")
		if err != nil || string(got) != string(want) {
			t.Fatalf("stored bytes changed for %s: err=%v", id, err)
		}
	}
}

func TestHTTPRuntimeRecoveryJobsAreReadThroughProductionHandler(t *testing.T) {
	cfg := runtimeJobReadConfig(t)
	queued := serverRecoveryJob("runtime-queued", jobs.StatusQueued, time.Now().UTC().Add(-10*time.Minute))
	running := serverRecoveryJob("runtime-running", jobs.StatusRunning, time.Now().UTC().Add(-9*time.Minute))
	for index, job := range []*state.Job{&queued, &running} {
		job.Actor = state.Actor{Subject: "runtime-public-actor", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodBreakGlass}
		job.IdempotencyKey = "DURABLE_IDEMPOTENCY_SENTINEL_" + string(rune('A'+index))
		job.RequestDigest = strings.Repeat("b", 64)
		job.CancellationRequested = true
		seedServerRecoveryJob(t, cfg.StateDir, *job)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	runtimeValue, err := newHTTPRuntime(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), func(string, string) (net.Listener, error) {
		return listener, nil
	})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	t.Cleanup(func() { _ = runtime.Shutdown(context.Background()) })
	if runtime.recovery != (jobrecord.RecoverySummary{Examined: 2, Interrupted: 2}) {
		t.Fatalf("recovery summary=%#v", runtime.recovery)
	}
	httpServer, ok := runtime.server.(*http.Server)
	if !ok || httpServer.Handler == nil {
		t.Fatalf("runtime server handler=%#v", runtime.server)
	}
	handler := httpServer.Handler
	unauthenticated := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs", nil)
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated list status=%d body=%s", unauthenticated.Code, unauthenticated.Body.String())
	}

	login := httptest.NewRequest(http.MethodPost, cfg.PublicURL+"/auth/break-glass/login", strings.NewReader(`{"username":"break-glass-admin","password":"runtime-job-read-password"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", cfg.PublicURL)
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusNoContent {
		t.Fatalf("break-glass login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range loginResponse.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("break-glass login did not set a session cookie")
	}

	storedBeforeReads := make(map[string][]byte, 2)
	for _, id := range []string{queued.ID, running.ID} {
		encoded, readErr := os.ReadFile(filepath.Join(cfg.StateDir, statefs.JobsDir, id+".json"))
		if readErr != nil {
			t.Fatalf("read recovered %s: %v", id, readErr)
		}
		storedBeforeReads[id] = encoded
	}
	requestWithSession := func(method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, cfg.PublicURL+path, nil)
		request.AddCookie(session)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	listResponse := requestWithSession(http.MethodGet, "/api/v1/jobs")
	if listResponse.Code != http.StatusOK {
		t.Fatalf("authenticated list status=%d body=%s", listResponse.Code, listResponse.Body.String())
	}
	var list api.JobListResponse
	if err := json.Unmarshal(listResponse.Body.Bytes(), &list); err != nil || len(list.Jobs) != 2 {
		t.Fatalf("list body=%s jobs=%#v err=%v", listResponse.Body.String(), list.Jobs, err)
	}
	assertRuntimeRecoveredPublicJobs(t, listResponse.Body.String(), list.Jobs)

	for _, expected := range []struct {
		id   string
		code string
	}{
		{queued.ID, string(jobrecovery.FailureCodeQueued)},
		{running.ID, string(jobrecovery.FailureCodeRunning)},
	} {
		response := requestWithSession(http.MethodGet, "/api/v1/jobs/"+expected.id)
		if response.Code != http.StatusOK {
			t.Fatalf("detail %s status=%d body=%s", expected.id, response.Code, response.Body.String())
		}
		var detail api.JobResponse
		if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
			t.Fatalf("detail %s body=%s err=%v", expected.id, response.Body.String(), err)
		}
		if detail.Job.ID != expected.id || detail.Job.Status != jobs.StatusInterrupted || detail.Job.FailureCode != expected.code {
			t.Fatalf("detail %s projection=%#v", expected.id, detail.Job)
		}
		assertRuntimeRecoveredPublicJobs(t, response.Body.String(), []jobs.Job{detail.Job})
	}
	if response := requestWithSession(http.MethodHead, "/api/v1/jobs"); response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("list HEAD status=%d body=%q", response.Code, response.Body.String())
	}
	for _, id := range []string{queued.ID, running.ID} {
		if response := requestWithSession(http.MethodHead, "/api/v1/jobs/"+id); response.Code != http.StatusOK || response.Body.Len() != 0 {
			t.Fatalf("detail HEAD %s status=%d body=%q", id, response.Code, response.Body.String())
		}
	}
	for id, want := range storedBeforeReads {
		got, readErr := os.ReadFile(filepath.Join(cfg.StateDir, statefs.JobsDir, id+".json"))
		if readErr != nil || string(got) != string(want) {
			t.Fatalf("stored bytes changed after reads for %s: err=%v", id, readErr)
		}
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
}

func assertRuntimeRecoveredPublicJobs(t *testing.T, body string, values []jobs.Job) {
	t.Helper()
	for _, job := range values {
		if job.Status != jobs.StatusInterrupted || (job.FailureCode != string(jobrecovery.FailureCodeQueued) && job.FailureCode != string(jobrecovery.FailureCodeRunning)) {
			t.Fatalf("unexpected public job=%#v", job)
		}
	}
	for _, forbidden := range []string{`"actor":`, `"roles":`, `"authMethod":`, `"idempotencyKey":`, `"requestDigest":`, `"planID":`, `"reportID":`, `"cancellationRequested":`, "DURABLE_IDEMPOTENCY_SENTINEL"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("public job response contains forbidden %q: %s", forbidden, body)
		}
	}
}

func runtimeJobReadConfig(t *testing.T) *config.ServerConfig {
	t.Helper()
	cfg, err := config.LoadServerConfig("../config/testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.Enabled = false
	cfg.Listen = "127.0.0.1:8080"
	cfg.StateDir = t.TempDir()
	if err := os.Chmod(cfg.StateDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretRoot := t.TempDir()
	if err := os.Chmod(secretRoot, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.SecretMountRoot = secretRoot
	cfg.BreakGlass = config.BreakGlassConfig{
		Enabled:  true,
		Username: "break-glass-admin",
		CredentialSecret: config.SecretKeyRef{
			Namespace: cfg.SecretPolicy.Namespace,
			Name:      "elastic-maintainer-break-glass",
			Key:       "credential",
		},
	}
	writeRuntimeJobReadSecret(t, secretRoot, cfg.OIDC.SessionSecret, []byte("elastic-maintainer-session-keyring/v1\ncurrent active "+base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))+"\n"))
	salt := []byte("0123456789abcdef")
	hash := argon2.IDKey([]byte("runtime-job-read-password"), salt, 3, 65536, 1, 32)
	credential := "elastic-maintainer-break-glass/v1\ngeneration " + base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")) + "\nverifier $argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash) + "\n"
	writeRuntimeJobReadSecret(t, secretRoot, cfg.BreakGlass.CredentialSecret, []byte(credential))
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "server.yaml")
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadServerConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func writeRuntimeJobReadSecret(t *testing.T, root string, ref config.SecretKeyRef, value []byte) {
	t.Helper()
	directory := filepath.Join(root, ref.Namespace, ref.Name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ref.Key), value, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestJobRepositoryMutationBetweenPagesReturnsConflict(t *testing.T) {
	repository, store, _ := newHTTPJobRepository(t)
	first := httpJob("mutation-a", jobs.TypeValidation, jobs.StatusSucceeded)
	first.CreatedAt = time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC)
	second := httpJob("mutation-b", jobs.TypeValidation, jobs.StatusSucceeded)
	second.CreatedAt = first.CreatedAt.Add(time.Second)
	for _, job := range []state.Job{first, second} {
		encoded, err := state.EncodeJob(job)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.WriteAtomic(statefs.JobsDir+"/"+job.ID+".json", encoded, false); err != nil {
			t.Fatal(err)
		}
	}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: repository,
	})
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?pageSize=1", nil)
	var page api.JobListResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.NextPageToken == "" {
		t.Fatalf("first page status=%d body=%s", response.Code, response.Body.String())
	}
	mismatched := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?pageSize=1&type=plan&pageToken="+url.QueryEscape(page.NextPageToken), nil)
	if mismatched.Code != http.StatusBadRequest || !strings.Contains(mismatched.Body.String(), `"code":"invalid_page_token"`) || strings.Contains(mismatched.Body.String(), page.NextPageToken) {
		t.Fatalf("mismatched page status=%d body=%s", mismatched.Code, mismatched.Body.String())
	}
	mutated := first
	mutated.RequestID = "request-mutated"
	encoded, err := state.EncodeJob(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/"+first.ID+".json", encoded, true); err != nil {
		t.Fatal(err)
	}
	response = serveJobRequest(handler, http.MethodGet, "/api/v1/jobs?pageSize=1&pageToken="+url.QueryEscape(page.NextPageToken), nil)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"job_page_changed"`) || strings.Contains(response.Body.String(), page.NextPageToken) {
		t.Fatalf("changed page status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestJobRepositoryRestartPolling(t *testing.T) {
	_, store, root := newHTTPJobRepository(t)
	job := httpJob("restart-job", jobs.TypeValidation, jobs.StatusSucceeded)
	encoded, err := state.EncodeJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteAtomic(statefs.JobsDir+"/"+job.ID+".json", encoded, false); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopenedStore, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopenedStore.Close() })
	reopenedRepository, err := jobrecord.New(reopenedStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(HandlerOptions{
		Authenticator:  authtest.Authenticator{Actor: auth.Actor{Subject: "reader", Roles: []auth.Role{auth.RoleViewer}}},
		JobReadBackend: reopenedRepository,
	})
	response := serveJobRequest(handler, http.MethodGet, "/api/v1/jobs/restart-job", nil)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"id":"restart-job"`) {
		t.Fatalf("restart polling status=%d body=%s", response.Code, response.Body.String())
	}
}

func serveJobRequest(handler http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func httpJob(id string, jobType jobs.Type, status jobs.Status) state.Job {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	job := state.Job{
		APIVersion:     state.APIVersion,
		Kind:           state.KindJob,
		ID:             id,
		Type:           jobType,
		Status:         status,
		CreatedAt:      created,
		Actor:          state.Actor{Subject: "actor-" + id, Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC},
		RequestID:      "request-" + id,
		IdempotencyKey: "idem-" + id,
		RequestDigest:  strings.Repeat("a", 64),
	}
	if status == jobs.StatusRunning {
		started := created.Add(time.Second)
		job.StartedAt = &started
	}
	if status == jobs.StatusSucceeded || status == jobs.StatusFailed || status == jobs.StatusCanceled || status == jobs.StatusInterrupted {
		finished := created.Add(2 * time.Second)
		job.FinishedAt = &finished
		if status == jobs.StatusFailed || status == jobs.StatusInterrupted {
			job.FailureCode = "failure-" + id
		}
	}
	if jobType == jobs.TypeApply {
		job.PlanID = "plan-" + id
	}
	return job
}

func newHTTPJobRepository(t *testing.T) (*jobrecord.FileRepository, *statefs.Store, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := statefs.Open(statefs.Options{StateDir: root, MinFreeBytes: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	repository, err := jobrecord.New(store)
	if err != nil {
		t.Fatal(err)
	}
	return repository, store, root
}
