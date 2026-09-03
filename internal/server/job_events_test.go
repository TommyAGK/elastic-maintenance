package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/jobscheduler"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

type phase336bBackend struct {
	mu            sync.Mutex
	record        jobrecord.Record
	states        []state.Job
	getErrors     []error
	getCalls      int
	getErr        error
	cancelErr     error
	cancelResult  *jobs.Job
	cancelCalls   int
	cancelRequest jobs.CancellationRequest
}

func (backend *phase336bBackend) Get(_ context.Context, id string) (jobrecord.Record, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.getCalls++
	if backend.getErr != nil {
		return jobrecord.Record{}, backend.getErr
	}
	if index := backend.getCalls - 1; index < len(backend.getErrors) && backend.getErrors[index] != nil {
		return jobrecord.Record{}, backend.getErrors[index]
	}
	if len(backend.states) != 0 {
		index := backend.getCalls - 1
		if index >= len(backend.states) {
			index = len(backend.states) - 1
		}
		return jobrecord.Record{Job: backend.states[index]}, nil
	}
	if backend.record.Job.ID != id {
		return jobrecord.Record{}, jobs.ErrNotFound
	}
	return backend.record, nil
}

func (backend *phase336bBackend) List(context.Context, jobs.ListOptions) (jobrecord.Page, error) {
	return jobrecord.Page{}, nil
}

func (backend *phase336bBackend) RequestCancellation(_ context.Context, request jobs.CancellationRequest) (jobs.Job, error) {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	backend.cancelCalls++
	backend.cancelRequest = request
	if backend.cancelErr != nil {
		return jobs.Job{}, backend.cancelErr
	}
	if backend.cancelResult != nil {
		return *backend.cancelResult, nil
	}
	projected := publicJob(backend.record.Job)
	projected.Status = jobs.StatusCanceled
	if projected.FinishedAt == nil {
		finished := projected.CreatedAt.Add(time.Second)
		projected.FinishedAt = &finished
	}
	return projected, nil
}

func phase336bActor(subject string, roles []auth.Role, method auth.Method) auth.Actor {
	return auth.Actor{Subject: subject, Roles: roles, Method: method, CSRFToken: "csrf-token"}
}

func phase336bCancelRequest(method, path string, actor auth.Actor, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, path, body)
	if actor.Method != auth.MethodBearer {
		request.Header.Set("Origin", "https://app.example.test")
		request.Header.Set(api.CSRFTokenHeader, actor.CSRFToken)
	}
	return request
}

func TestPhase336bCancellationRoleOriginAndAudit(t *testing.T) {
	backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("cancel-job", jobs.TypeValidation, jobs.StatusQueued)}}
	recorder := &recordingAudit{}
	planner := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: planner}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	request := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", planner, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted || !strings.Contains(response.Body.String(), `"status":"canceled"`) {
		t.Fatalf("accepted status=%d body=%s", response.Code, response.Body.String())
	}
	if backend.cancelRequest.ActorSubject != "planner" || backend.cancelRequest.RequestID == "" || backend.cancelCalls != 1 {
		t.Fatalf("cancellation request=%#v calls=%d", backend.cancelRequest, backend.cancelCalls)
	}
	if len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionJobCancel || recorder.events[0].Outcome != audit.OutcomeSucceeded || recorder.events[0].JobID != "cancel-job" || recorder.events[0].RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("audit=%#v response=%s", recorder.events, response.Body.String())
	}

	viewer := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodOIDC)
	deniedHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: viewer}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	before := backend.cancelCalls
	denied := httptest.NewRecorder()
	deniedHandler.ServeHTTP(denied, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", viewer, nil))
	if denied.Code != http.StatusForbidden || backend.cancelCalls != before || len(recorder.events) != 2 || recorder.events[1].Outcome != audit.OutcomeDenied || recorder.events[1].JobID != "cancel-job" {
		t.Fatalf("denied status=%d calls=%d audit=%#v", denied.Code, backend.cancelCalls, recorder.events)
	}

	badOrigin := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", planner, nil)
	badOrigin.Header.Set("Origin", "https://evil.example.test")
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, badOrigin)
	if badResponse.Code != http.StatusBadRequest || backend.cancelCalls != before {
		t.Fatalf("bad origin status=%d calls=%d", badResponse.Code, backend.cancelCalls)
	}

	bearer := phase336bActor("automation", []auth.Role{auth.RolePlanner}, auth.MethodBearer)
	bearerHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: bearer}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
	bearerRequest := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", bearer, nil)
	bearerResponse := httptest.NewRecorder()
	bearerHandler.ServeHTTP(bearerResponse, bearerRequest)
	if bearerResponse.Code != http.StatusAccepted {
		t.Fatalf("bearer status=%d body=%s", bearerResponse.Code, bearerResponse.Body.String())
	}
	bearerRequest.Header.Set("Origin", "https://app.example.test")
	bearerRejected := httptest.NewRecorder()
	bearerHandler.ServeHTTP(bearerRejected, bearerRequest)
	if bearerRejected.Code != http.StatusBadRequest {
		t.Fatalf("bearer origin status=%d", bearerRejected.Code)
	}

	missingCSRF := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", planner, nil)
	missingCSRF.Header.Del(api.CSRFTokenHeader)
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingCSRF)
	if missingResponse.Code != http.StatusBadRequest || backend.cancelCalls != 2 {
		t.Fatalf("missing CSRF status=%d calls=%d", missingResponse.Code, backend.cancelCalls)
	}
	wrongCSRF := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-job/cancel", planner, nil)
	wrongCSRF.Header.Set(api.CSRFTokenHeader, "wrong-csrf-token")
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrongCSRF)
	if wrongResponse.Code != http.StatusBadRequest || backend.cancelCalls != 2 {
		t.Fatalf("wrong CSRF status=%d calls=%d", wrongResponse.Code, backend.cancelCalls)
	}
}

func TestPhase336bCancellationQueuedReadRaceAndMalformedTimes(t *testing.T) {
	actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	cases := []struct {
		name        string
		result      func(state.Job) jobs.Job
		wantStatus  int
		wantOutcome audit.Outcome
	}{
		{
			name: "queued unchanged",
			result: func(job state.Job) jobs.Job {
				return publicJob(job)
			},
			wantStatus:  http.StatusAccepted,
			wantOutcome: audit.OutcomeSucceeded,
		},
		{
			name: "running after claim",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusRunning
				started := job.CreatedAt.Add(time.Second)
				projected.StartedAt = &started
				return projected
			},
			wantStatus:  http.StatusAccepted,
			wantOutcome: audit.OutcomeSucceeded,
		},
		{
			name: "canceled after claim",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusCanceled
				started := job.CreatedAt.Add(time.Second)
				finished := job.CreatedAt.Add(2 * time.Second)
				projected.StartedAt = &started
				projected.FinishedAt = &finished
				return projected
			},
			wantStatus:  http.StatusAccepted,
			wantOutcome: audit.OutcomeSucceeded,
		},
		{
			name: "running start before created",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusRunning
				started := job.CreatedAt.Add(-time.Second)
				projected.StartedAt = &started
				return projected
			},
			wantStatus:  http.StatusServiceUnavailable,
			wantOutcome: audit.OutcomeFailed,
		},
		{
			name: "canceled start before created",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusCanceled
				started := job.CreatedAt.Add(-time.Second)
				finished := job.CreatedAt.Add(time.Second)
				projected.StartedAt = &started
				projected.FinishedAt = &finished
				return projected
			},
			wantStatus:  http.StatusServiceUnavailable,
			wantOutcome: audit.OutcomeFailed,
		},
		{
			name: "canceled finish before created",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusCanceled
				finished := job.CreatedAt.Add(-time.Second)
				projected.FinishedAt = &finished
				return projected
			},
			wantStatus:  http.StatusServiceUnavailable,
			wantOutcome: audit.OutcomeFailed,
		},
		{
			name: "canceled finish before start",
			result: func(job state.Job) jobs.Job {
				projected := publicJob(job)
				projected.Status = jobs.StatusCanceled
				started := job.CreatedAt.Add(2 * time.Second)
				finished := job.CreatedAt.Add(time.Second)
				projected.StartedAt = &started
				projected.FinishedAt = &finished
				return projected
			},
			wantStatus:  http.StatusServiceUnavailable,
			wantOutcome: audit.OutcomeFailed,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			id := "queued-race-" + strings.ReplaceAll(testCase.name, " ", "-")
			queued := httpJob(id, jobs.TypeValidation, jobs.StatusQueued)
			backend := &phase336bBackend{
				record:       jobrecord.Record{Job: queued},
				cancelResult: func() *jobs.Job { result := testCase.result(queued); return &result }(),
			}
			recorder := &recordingAudit{}
			handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/"+id+"/cancel", actor, nil))

			if response.Code != testCase.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, testCase.wantStatus, response.Body.String())
			}
			if len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionJobCancel || recorder.events[0].Outcome != testCase.wantOutcome || recorder.events[0].JobID != id || recorder.events[0].RequestID != response.Header().Get("X-Request-ID") {
				t.Fatalf("audit=%#v response=%s", recorder.events, response.Body.String())
			}
		})
	}
}

func TestPhase336bCancellationStrictRouteBodyAndReadBeforePolicy(t *testing.T) {
	backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("strict-job", jobs.TypePlan, jobs.StatusQueued)}}
	actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
	for name, request := range map[string]*http.Request{
		"query":  phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-job/cancel?x=sentinel", actor, nil),
		"body":   phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-job/cancel", actor, strings.NewReader("x")),
		"method": phase336bCancelRequest(http.MethodPut, "https://app.example.test/api/v1/jobs/strict-job/cancel", actor, nil),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			want := http.StatusBadRequest
			if name == "method" {
				want = http.StatusMethodNotAllowed
			}
			if response.Code != want || strings.Contains(response.Body.String(), "sentinel") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/missing/cancel", actor, nil))
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), `"code":"job_not_found"`) {
		t.Fatalf("missing status=%d body=%s", missing.Code, missing.Body.String())
	}
}

func TestPhase336bSSEProjectionOrderingHashAndTerminalClose(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	queued := httpJob("event-job", jobs.TypeValidation, jobs.StatusQueued)
	queued.CreatedAt = created
	running := queued
	running.Status = jobs.StatusRunning
	started := created.Add(time.Second)
	running.StartedAt = &started
	succeeded := running
	succeeded.Status = jobs.StatusSucceeded
	finished := created.Add(2 * time.Second)
	succeeded.FinishedAt = &finished
	backend := &phase336bBackend{states: []state.Job{queued, running, succeeded}}
	actor := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodBearer)
	handler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: time.Second, MaxEvents: 8})
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/jobs/event-job/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	body := response.Body.String()
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/event-stream" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Accel-Buffering") != "no" || response.Header().Get("Connection") != "" {
		t.Fatalf("status=%d headers=%v body=%s", response.Code, response.Header(), body)
	}
	if strings.Count(body, "event: job\n") != 3 || strings.Contains(body, "cancellationRequested") || strings.Contains(body, "requestDigest") || strings.Contains(body, "roles") {
		t.Fatalf("SSE body=%s", body)
	}
	for _, job := range []state.Job{queued, running, succeeded} {
		data, _, _ := marshalJobEvent(job)
		digest := sha256.Sum256(data)
		want := "id: " + hex.EncodeToString(digest[:])
		if !strings.Contains(body, want) || !strings.Contains(body, "data: "+string(data)+"\n\n") {
			t.Fatalf("missing exact event for %s body=%s", job.Status, body)
		}
	}
}

func TestPhase336bSSEStrictHeadersReconnectAndFlusher(t *testing.T) {
	job := httpJob("strict-events", jobs.TypeValidation, jobs.StatusSucceeded)
	backend := &phase336bBackend{record: jobrecord.Record{Job: job}}
	actor := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodBearer)
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend})
	for name, accept := range map[string]string{"missing": "", "multiple": "text/event-stream, application/json", "wildcard": "text/*", "malformed": "text/event-stream;", "zero-quality": "text/event-stream; q=0", "too-many-decimals": "text/event-stream; q=0.0001"} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/strict-events/events", nil)
			if accept != "" {
				request.Header.Set("Accept", accept)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusNotAcceptable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	for name, request := range map[string]*http.Request{
		"body": func() *http.Request {
			r := phase336bEventRequest("/api/v1/jobs/strict-events/events")
			r.Body = io.NopCloser(strings.NewReader("body-sentinel"))
			r.ContentLength = int64(len("body-sentinel"))
			return r
		}(),
		"chunked": func() *http.Request {
			r := phase336bEventRequest("/api/v1/jobs/strict-events/events")
			r.TransferEncoding = []string{"chunked"}
			return r
		}(),
		"unknown-framing": func() *http.Request {
			r := phase336bEventRequest("/api/v1/jobs/strict-events/events")
			r.ContentLength = -1
			return r
		}(),
	} {
		t.Run("strict-"+name, func(t *testing.T) {
			before := backend.getCalls
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || backend.getCalls != before || strings.Contains(response.Body.String(), "body-sentinel") {
				t.Fatalf("status=%d calls=%d before=%d body=%s", response.Code, backend.getCalls, before, response.Body.String())
			}
		})
	}
	_, id, _ := marshalJobEvent(job)
	request := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/strict-events/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", id)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("terminal reconnect status=%d body=%q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodHead, "/api/v1/jobs/strict-events/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("HEAD status=%d", response.Code)
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/jobs/strict-events/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Last-Event-ID", strings.Repeat("A", 64))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid last ID status=%d", response.Code)
	}

	nonterminal := httpJob("nonterminal-reconnect", jobs.TypeValidation, jobs.StatusRunning)
	nonterminalBackend := &phase336bBackend{record: jobrecord.Record{Job: nonterminal}}
	nonterminalHandler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: nonterminalBackend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: 10 * time.Millisecond})
	firstResponse := httptest.NewRecorder()
	nonterminalHandler.ServeHTTP(firstResponse, phase336bEventRequest("/api/v1/jobs/nonterminal-reconnect/events"))
	_, reconnectID, _ := marshalJobEvent(nonterminal)
	reconnect := phase336bEventRequest("/api/v1/jobs/nonterminal-reconnect/events")
	reconnect.Header.Set("Last-Event-ID", reconnectID)
	reconnectResponse := httptest.NewRecorder()
	nonterminalHandler.ServeHTTP(reconnectResponse, reconnect)
	if firstResponse.Code != http.StatusOK || strings.Count(firstResponse.Body.String(), "event: job\n") != 1 || reconnectResponse.Code != http.StatusOK || reconnectResponse.Body.Len() != 0 {
		t.Fatalf("nonterminal reconnect first=%d/%s replay=%d/%q", firstResponse.Code, firstResponse.Body.String(), reconnectResponse.Code, reconnectResponse.Body.String())
	}

	for name, getErr := range map[string]error{"not found": jobs.ErrNotFound, "storage": errors.New("pre-header-secret-sentinel")} {
		t.Run("pre-header "+name, func(t *testing.T) {
			preHeaderBackend := &phase336bBackend{record: jobrecord.Record{Job: nonterminal}, getErr: getErr}
			preHeaderHandler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: preHeaderBackend}, jobEventOptions{MaxDuration: time.Second})
			preHeaderResponse := httptest.NewRecorder()
			preHeaderHandler.ServeHTTP(preHeaderResponse, phase336bEventRequest("/api/v1/jobs/nonterminal-reconnect/events"))
			want := http.StatusServiceUnavailable
			if errors.Is(getErr, jobs.ErrNotFound) {
				want = http.StatusNotFound
			}
			if preHeaderResponse.Code != want || strings.Contains(preHeaderResponse.Body.String(), "pre-header-secret-sentinel") {
				t.Fatalf("status=%d want=%d body=%s", preHeaderResponse.Code, want, preHeaderResponse.Body.String())
			}
		})
	}

	noFlush := &phase336bNoFlushWriter{header: make(http.Header)}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/jobs/strict-events/events", nil)
	request.Header.Set("Accept", "text/event-stream")
	handler.ServeHTTP(noFlush, request)
	if noFlush.status != http.StatusServiceUnavailable {
		t.Fatalf("no-flush status=%d body=%s", noFlush.status, noFlush.body.String())
	}
}

type phase336bNoFlushWriter struct {
	header http.Header
	body   strings.Builder
	status int
}

func (writer *phase336bNoFlushWriter) Header() http.Header    { return writer.header }
func (writer *phase336bNoFlushWriter) WriteHeader(status int) { writer.status = status }
func (writer *phase336bNoFlushWriter) Write(value []byte) (int, error) {
	return writer.body.Write(value)
}

func TestPhase336bSSEBoundsBackendFailureDisconnectAndPollingFallback(t *testing.T) {
	queued := httpJob("bounded-events", jobs.TypeValidation, jobs.StatusQueued)
	running := queued
	running.Status = jobs.StatusRunning
	started := queued.CreatedAt.Add(time.Second)
	running.StartedAt = &started
	succeeded := running
	succeeded.Status = jobs.StatusSucceeded
	finished := started.Add(time.Second)
	succeeded.FinishedAt = &finished
	backend := &phase336bBackend{states: []state.Job{queued, running, succeeded}}
	actor := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodBearer)
	handler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: time.Second, MaxEvents: 2})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, phase336bEventRequest("/api/v1/jobs/bounded-events/events"))
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), "event: job\n") != 2 || strings.Contains(response.Body.String(), string(jobs.StatusSucceeded)) {
		t.Fatalf("event bound status=%d body=%s", response.Code, response.Body.String())
	}

	failedBackend := &phase336bBackend{states: []state.Job{queued}, getErrors: []error{nil, errors.New("backend-event-secret-sentinel")}}
	failedHandler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: failedBackend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: time.Second})
	failedResponse := httptest.NewRecorder()
	failedHandler.ServeHTTP(failedResponse, phase336bEventRequest("/api/v1/jobs/bounded-events/events"))
	if failedResponse.Code != http.StatusOK || strings.Count(failedResponse.Body.String(), "event: job\n") != 1 || strings.Contains(failedResponse.Body.String(), "backend-event-secret-sentinel") {
		t.Fatalf("post-header failure status=%d body=%s", failedResponse.Code, failedResponse.Body.String())
	}
	pollRequest := httptest.NewRequest(http.MethodGet, "/api/v1/jobs/bounded-events", nil)
	pollResponse := httptest.NewRecorder()
	// SSE loss does not alter the read authority: the ordinary durable polling
	// endpoint remains available after the stream closes.
	failedHandler.ServeHTTP(pollResponse, pollRequest)
	if pollResponse.Code != http.StatusOK || !strings.Contains(pollResponse.Body.String(), `"id":"bounded-events"`) {
		t.Fatalf("polling fallback status=%d body=%s", pollResponse.Code, pollResponse.Body.String())
	}

	shortHandler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: &phase336bBackend{record: jobrecord.Record{Job: queued}}}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: 10 * time.Millisecond})
	shortResponse := httptest.NewRecorder()
	startedAt := time.Now()
	shortHandler.ServeHTTP(shortResponse, phase336bEventRequest("/api/v1/jobs/bounded-events/events"))
	if time.Since(startedAt) > time.Second || shortResponse.Code != http.StatusOK {
		t.Fatalf("duration status=%d elapsed=%s body=%s", shortResponse.Code, time.Since(startedAt), shortResponse.Body.String())
	}

	cancelBackend := &phase336bBlockingBackend{record: jobrecord.Record{Job: queued}, started: make(chan struct{}, 1), release: make(chan struct{})}
	cancelHandler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: cancelBackend, JobCancellationBackend: cancelBackend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	request := phase336bEventRequest("/api/v1/jobs/bounded-events/events").WithContext(ctx)
	streamDone := make(chan struct{})
	streamResponse := httptest.NewRecorder()
	go func() {
		cancelHandler.ServeHTTP(streamResponse, request)
		close(streamDone)
	}()
	select {
	case <-cancelBackend.started:
	case <-time.After(time.Second):
		t.Fatal("disconnect test did not reach backend")
	}
	close(cancelBackend.release)
	time.Sleep(5 * time.Millisecond)
	disconnectedAt := time.Now()
	cancel()
	select {
	case <-streamDone:
		if time.Since(disconnectedAt) > 500*time.Millisecond {
			t.Fatalf("disconnect took too long: %s", time.Since(disconnectedAt))
		}
	case <-time.After(time.Second):
		t.Fatal("disconnect did not stop stream")
	}
	if cancelBackend.CancellationCalls() != 0 {
		t.Fatalf("disconnect invoked cancellation backend calls=%d", cancelBackend.CancellationCalls())
	}
}

type phase336bBlockingBackend struct {
	mu          sync.Mutex
	record      jobrecord.Record
	started     chan struct{}
	release     chan struct{}
	getCalls    int
	cancelCalls int
}

func (backend *phase336bBlockingBackend) Get(ctx context.Context, id string) (jobrecord.Record, error) {
	backend.mu.Lock()
	backend.getCalls++
	calls := backend.getCalls
	record := backend.record
	backend.mu.Unlock()
	if calls <= cap(backend.started) {
		backend.started <- struct{}{}
		select {
		case <-backend.release:
		case <-ctx.Done():
			return jobrecord.Record{}, ctx.Err()
		}
	}
	if record.Job.ID != id {
		return jobrecord.Record{}, jobs.ErrNotFound
	}
	return record, nil
}

func (backend *phase336bBlockingBackend) List(context.Context, jobs.ListOptions) (jobrecord.Page, error) {
	return jobrecord.Page{}, nil
}

func (backend *phase336bBlockingBackend) RequestCancellation(context.Context, jobs.CancellationRequest) (jobs.Job, error) {
	backend.mu.Lock()
	backend.cancelCalls++
	backend.mu.Unlock()
	return jobs.Job{}, errors.New("unexpected cancellation")
}

func (backend *phase336bBlockingBackend) CancellationCalls() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.cancelCalls
}

func (backend *phase336bBlockingBackend) Calls() int {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.getCalls
}

func phase336bEventRequest(path string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("Accept", "text/event-stream")
	return request
}

func TestPhase336bStrictEventQualityAndMediaTypeTable(t *testing.T) {
	accepted := []string{
		"text/event-stream",
		"TEXT/EVENT-STREAM",
		"text/event-stream; q=1",
		"text/event-stream;q=1.0",
		"text/event-stream; q=1.00",
		"text/event-stream; q=1.000",
		"text/event-stream; q=0.1",
		"text/event-stream; q=0.01",
		"text/event-stream; q=0.001",
		"text/event-stream; q=0.100",
	}
	rejected := []string{
		"",
		"text/event-stream, application/json",
		"text/*",
		"*/*",
		"application/json",
		"text/event-stream;",
		"text/event-stream; charset=utf-8",
		"text/event-stream; q=0",
		"text/event-stream; q=0.0",
		"text/event-stream; q=0.000",
		"text/event-stream; q=0.0001",
		"text/event-stream; q=1.1",
		"text/event-stream; q=1.001",
		"text/event-stream; q=1.0000",
		"text/event-stream; q=+1",
		"text/event-stream; q=-1",
		"text/event-stream; q=.1",
		"text/event-stream; q=",
		"text/event-stream; q=1; foo=bar",
		"text/event-stream; Q=\"1\"",
	}
	for _, value := range accepted {
		request := phase336bEventRequest("/api/v1/jobs/q/events")
		request.Header.Set("Accept", value)
		if !validEventAccept(request) {
			t.Errorf("valid Accept rejected: %q", value)
		}
	}
	for _, value := range rejected {
		request := phase336bEventRequest("/api/v1/jobs/q/events")
		request.Header.Del("Accept")
		if value != "" {
			request.Header.Set("Accept", value)
		}
		if validEventAccept(request) {
			t.Errorf("invalid Accept accepted: %q", value)
		}
	}
	request := phase336bEventRequest("/api/v1/jobs/q/events")
	request.Header.Add("Accept", "text/event-stream")
	request.Header.Add("Accept", "text/event-stream")
	if validEventAccept(request) {
		t.Error("duplicate Accept headers accepted")
	}
}

func TestPhase336bSSELimiterCapacityReleaseAndPrevalidation(t *testing.T) {
	job := httpJob("limited-events", jobs.TypeValidation, jobs.StatusRunning)
	backend := &phase336bBlockingBackend{
		record:  jobrecord.Record{Job: job},
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	actor := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodBearer)
	handler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend}, jobEventOptions{
		PollInterval: time.Millisecond,
		MaxDuration:  100 * time.Millisecond,
		MaxEvents:    4,
		MaxStreams:   2,
	})
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, phase336bEventRequest("/api/v1/jobs/limited-events/events"))
			responses <- response
		}()
	}
	for range 2 {
		select {
		case <-backend.started:
		case <-time.After(time.Second):
			t.Fatal("stream did not reach backend")
		}
	}
	invalid := httptest.NewRecorder()
	handler.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/api/v1/jobs/limited-events/events", nil))
	if invalid.Code != http.StatusNotAcceptable || backend.Calls() != 2 {
		t.Fatalf("prevalidation status=%d calls=%d body=%s", invalid.Code, backend.Calls(), invalid.Body.String())
	}

	saturated := httptest.NewRecorder()
	handler.ServeHTTP(saturated, phase336bEventRequest("/api/v1/jobs/limited-events/events"))
	if saturated.Code != http.StatusTooManyRequests || saturated.Header().Get("Retry-After") != "1" || !strings.Contains(saturated.Body.String(), `"code":"job_event_limit"`) || backend.Calls() != 2 {
		t.Fatalf("saturated status=%d retry=%q calls=%d body=%s", saturated.Code, saturated.Header().Get("Retry-After"), backend.Calls(), saturated.Body.String())
	}
	close(backend.release)
	for range 2 {
		select {
		case response := <-responses:
			if response.Code != http.StatusOK {
				t.Fatalf("stream status=%d body=%s", response.Code, response.Body.String())
			}
		case <-time.After(time.Second):
			t.Fatal("stream did not release")
		}
	}

	released := httptest.NewRecorder()
	handler.ServeHTTP(released, phase336bEventRequest("/api/v1/jobs/limited-events/events"))
	if released.Code != http.StatusOK {
		t.Fatalf("post-release status=%d body=%s", released.Code, released.Body.String())
	}
}

func TestPhase336bOversizedEventProjectionFailsSafely(t *testing.T) {
	oversized := httpJob("oversized-event", jobs.TypeValidation, jobs.StatusQueued)
	oversized.Actor.Subject = strings.Repeat("projection-sentinel-", 300)
	backend := &phase336bBackend{record: jobrecord.Record{Job: oversized}}
	actor := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodBearer)
	handler := newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend}, jobEventOptions{MaxDuration: time.Second})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, phase336bEventRequest("/api/v1/jobs/oversized-event/events"))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "projection-sentinel") || strings.Contains(response.Body.String(), "event: job") {
		t.Fatalf("oversized initial status=%d body=%s", response.Code, response.Body.String())
	}

	first := httpJob("oversized-after-header", jobs.TypeValidation, jobs.StatusRunning)
	next := first
	next.Actor.Subject = strings.Repeat("post-header-sentinel-", 300)
	backend = &phase336bBackend{states: []state.Job{first, next}}
	handler = newHandlerWithJobEventOptions(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend}, jobEventOptions{PollInterval: time.Millisecond, MaxDuration: time.Second})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, phase336bEventRequest("/api/v1/jobs/oversized-after-header/events"))
	if response.Code != http.StatusOK || strings.Count(response.Body.String(), "event: job\n") != 1 || strings.Contains(response.Body.String(), "post-header-sentinel") {
		t.Fatalf("oversized follow-up status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestPhase336bCancellationRoleAndTerminalMatrix(t *testing.T) {
	roleAllowed := map[auth.Role]map[jobs.Type]bool{
		auth.RoleViewer:        {jobs.TypeTargetInventory: true},
		auth.RolePlanner:       {jobs.TypeValidation: true, jobs.TypePlan: true, jobs.TypeTargetInventory: true},
		auth.RoleApplier:       {jobs.TypeApply: true, jobs.TypeTargetInventory: true},
		auth.RoleAdministrator: {jobs.TypeValidation: true, jobs.TypePlan: true, jobs.TypeApply: true, jobs.TypeTargetInventory: true},
	}
	for _, jobType := range []jobs.Type{jobs.TypeValidation, jobs.TypePlan, jobs.TypeApply, jobs.TypeTargetInventory} {
		for _, role := range auth.KnownRoles() {
			backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("role-"+string(jobType), jobType, jobs.StatusQueued)}}
			handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: phase336bActor("actor", []auth.Role{role}, auth.MethodOIDC)}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/role-"+string(jobType)+"/cancel", phase336bActor("actor", []auth.Role{role}, auth.MethodOIDC), nil))
			want := http.StatusForbidden
			if roleAllowed[role][jobType] {
				want = http.StatusAccepted
			}
			if response.Code != want || (want == http.StatusForbidden && backend.cancelCalls != 0) || (want == http.StatusAccepted && backend.cancelCalls != 1) {
				t.Errorf("type=%s role=%s status=%d cancelCalls=%d body=%s", jobType, role, response.Code, backend.cancelCalls, response.Body.String())
			}
		}
	}

	for _, status := range []jobs.Status{jobs.StatusSucceeded, jobs.StatusFailed, jobs.StatusInterrupted, jobs.StatusCanceled} {
		job := httpJob("terminal-"+string(status), jobs.TypeValidation, status)
		if status == jobs.StatusCanceled {
			job.CancellationRequested = true
		}
		backend := &phase336bBackend{record: jobrecord.Record{Job: job}}
		actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
		handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/terminal-"+string(status)+"/cancel", actor, nil))
		want := http.StatusConflict
		if status == jobs.StatusCanceled {
			want = http.StatusAccepted
		}
		if response.Code != want || backend.cancelCalls != boolInt(status == jobs.StatusCanceled) {
			t.Errorf("status=%s response=%d want=%d calls=%d body=%s", status, response.Code, want, backend.cancelCalls, response.Body.String())
		}
	}
	normalCanceled := httpJob("normal-canceled", jobs.TypeValidation, jobs.StatusCanceled)
	normalBackend := &phase336bBackend{record: jobrecord.Record{Job: normalCanceled}}
	actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	normalHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: normalBackend, JobCancellationBackend: normalBackend, PublicURL: "https://app.example.test"})
	normalResponse := httptest.NewRecorder()
	normalHandler.ServeHTTP(normalResponse, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/normal-canceled/cancel", actor, nil))
	if normalResponse.Code != http.StatusConflict || normalBackend.cancelCalls != 0 {
		t.Fatalf("ordinary canceled replay status=%d calls=%d body=%s", normalResponse.Code, normalBackend.cancelCalls, normalResponse.Body.String())
	}
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestPhase336bCancellationSafeErrorMapsAndStrictFraming(t *testing.T) {
	actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	for name, readErr := range map[string]error{
		"not found": jobs.ErrNotFound,
		"storage":   errors.New("storage-secret-sentinel"),
	} {
		t.Run(name, func(t *testing.T) {
			backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("map-job", jobs.TypeValidation, jobs.StatusQueued)}, getErr: readErr}
			handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/map-job/cancel", actor, nil))
			want := http.StatusServiceUnavailable
			if errors.Is(readErr, jobs.ErrNotFound) {
				want = http.StatusNotFound
			}
			if response.Code != want || strings.Contains(response.Body.String(), "storage-secret-sentinel") || backend.cancelCalls != 0 {
				t.Fatalf("status=%d want=%d calls=%d body=%s", response.Code, want, backend.cancelCalls, response.Body.String())
			}
		})
	}
	for name, cancelErr := range map[string]error{
		"unavailable": errors.New("cancel-secret-sentinel"),
		"closed":      jobs.ErrQueueClosed,
		"unhealthy":   jobscheduler.ErrUnhealthy,
		"conflict":    jobs.ErrConflict,
		"not found":   jobs.ErrNotFound,
	} {
		t.Run("cancel "+name, func(t *testing.T) {
			backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("cancel-map", jobs.TypeValidation, jobs.StatusQueued)}, cancelErr: cancelErr}
			handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/cancel-map/cancel", actor, nil))
			want := http.StatusServiceUnavailable
			if errors.Is(cancelErr, jobs.ErrConflict) {
				want = http.StatusConflict
			} else if errors.Is(cancelErr, jobs.ErrNotFound) {
				want = http.StatusNotFound
			}
			if response.Code != want || strings.Contains(response.Body.String(), "secret-sentinel") {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
		})
	}
	malformedResult := &phase336bBackend{record: jobrecord.Record{Job: httpJob("malformed-result", jobs.TypeValidation, jobs.StatusQueued)}, cancelResult: &jobs.Job{ID: "malformed-result", Type: jobs.TypeValidation, Status: jobs.StatusCanceled}}
	malformedHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: malformedResult, JobCancellationBackend: malformedResult, PublicURL: "https://app.example.test"})
	malformedResponse := httptest.NewRecorder()
	malformedHandler.ServeHTTP(malformedResponse, phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/malformed-result/cancel", actor, nil))
	if malformedResponse.Code != http.StatusServiceUnavailable || strings.Contains(malformedResponse.Body.String(), "malformed-result") {
		t.Fatalf("malformed result status=%d body=%s", malformedResponse.Code, malformedResponse.Body.String())
	}

	for name, request := range map[string]*http.Request{
		"fragment": func() *http.Request {
			r := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-map/cancel", actor, nil)
			r.URL.Fragment = "fragment-sentinel"
			return r
		}(),
		"body": phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-map/cancel", actor, strings.NewReader("body-sentinel")),
		"chunked": func() *http.Request {
			r := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-map/cancel", actor, nil)
			r.TransferEncoding = []string{"chunked"}
			return r
		}(),
		"framing": func() *http.Request {
			r := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/strict-map/cancel", actor, nil)
			r.Header.Set("Transfer-Encoding", "chunked")
			return r
		}(),
	} {
		t.Run("strict "+name, func(t *testing.T) {
			backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("strict-map", jobs.TypeValidation, jobs.StatusQueued)}}
			handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test"})
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || backend.cancelCalls != 0 || strings.Contains(response.Body.String(), "sentinel") {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, backend.cancelCalls, response.Body.String())
			}
		})
	}
}

func TestPhase336bCancellationAuditExactFailureMetadata(t *testing.T) {
	actor := phase336bActor("planner", []auth.Role{auth.RolePlanner}, auth.MethodOIDC)
	recorder := &recordingAudit{}
	backend := &phase336bBackend{record: jobrecord.Record{Job: httpJob("audit-failed", jobs.TypeValidation, jobs.StatusQueued)}, cancelErr: errors.New("audit-secret-sentinel")}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	request := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/audit-failed/cancel", actor, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionJobCancel || recorder.events[0].Outcome != audit.OutcomeFailed || recorder.events[0].JobID != "audit-failed" || recorder.events[0].RequestID != response.Header().Get("X-Request-ID") || strings.Contains(response.Body.String(), "audit-secret-sentinel") {
		t.Fatalf("status=%d audit=%#v response=%s", response.Code, recorder.events, response.Body.String())
	}

	recorder.events = nil
	backend.cancelErr = nil
	viewer := phase336bActor("viewer", []auth.Role{auth.RoleViewer}, auth.MethodOIDC)
	deniedHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: viewer}, JobReadBackend: backend, JobCancellationBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	deniedRequest := phase336bCancelRequest(http.MethodPost, "https://app.example.test/api/v1/jobs/audit-failed/cancel", viewer, nil)
	denied := httptest.NewRecorder()
	deniedHandler.ServeHTTP(denied, deniedRequest)
	if denied.Code != http.StatusForbidden || len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionJobCancel || recorder.events[0].Outcome != audit.OutcomeDenied || recorder.events[0].JobID != "audit-failed" || recorder.events[0].RequestID != denied.Header().Get("X-Request-ID") {
		t.Fatalf("status=%d audit=%#v response=%s", denied.Code, recorder.events, denied.Body.String())
	}
}

func TestPhase336bRuntimeSchedulerCapabilityCancelsDurably(t *testing.T) {
	cfg := runtimeJobReadConfig(t)
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
	scheduler, ok := runtime.scheduler.(*jobscheduler.Scheduler)
	if !ok {
		t.Fatalf("runtime scheduler=%T, want concrete scheduler capability", runtime.scheduler)
	}
	job := httpJob("runtime-cancel", jobs.TypeValidation, jobs.StatusQueued)
	started := make(chan struct{})
	_, err = scheduler.Submit(context.Background(), jobscheduler.Submission{Job: job, Executor: func(ctx context.Context, _ state.Job) jobscheduler.ExecutionResult {
		close(started)
		<-ctx.Done()
		return jobscheduler.ExecutionResult{Outcome: jobscheduler.ExecutionSucceeded}
	}})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("runtime scheduler did not start submitted job")
	}

	httpServer := runtime.server.(*http.Server)
	handler := httpServer.Handler
	login := httptest.NewRequest(http.MethodPost, cfg.PublicURL+"/auth/break-glass/login", strings.NewReader(`{"username":"break-glass-admin","password":"runtime-job-read-password"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", cfg.PublicURL)
	loginResponse := httptest.NewRecorder()
	handler.ServeHTTP(loginResponse, login)
	if loginResponse.Code != http.StatusNoContent {
		t.Fatalf("login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	var session *http.Cookie
	for _, cookie := range loginResponse.Result().Cookies() {
		if cookie.Name == auth.SessionCookieName {
			session = cookie
			break
		}
	}
	if session == nil {
		t.Fatal("login did not return session cookie")
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, cfg.PublicURL+"/api/v1/session", nil)
	sessionRequest.AddCookie(session)
	sessionResponse := httptest.NewRecorder()
	handler.ServeHTTP(sessionResponse, sessionRequest)
	var sessionBody api.SessionResponse
	if sessionResponse.Code != http.StatusOK || json.Unmarshal(sessionResponse.Body.Bytes(), &sessionBody) != nil || sessionBody.CSRFToken == "" {
		t.Fatalf("session status=%d body=%s", sessionResponse.Code, sessionResponse.Body.String())
	}
	cancelRequest := httptest.NewRequest(http.MethodPost, cfg.PublicURL+"/api/v1/jobs/runtime-cancel/cancel", nil)
	cancelRequest.AddCookie(session)
	cancelRequest.Header.Set("Origin", cfg.PublicURL)
	cancelRequest.Header.Set(api.CSRFTokenHeader, sessionBody.CSRFToken)
	cancelResponse := httptest.NewRecorder()
	handler.ServeHTTP(cancelResponse, cancelRequest)
	if cancelResponse.Code != http.StatusAccepted {
		t.Fatalf("cancel status=%d body=%s", cancelResponse.Code, cancelResponse.Body.String())
	}
	deadline := time.Now().Add(time.Second)
	for {
		record, getErr := runtime.jobRepository.Get(context.Background(), job.ID)
		if getErr == nil && record.Job.Status == jobs.StatusCanceled && record.Job.CancellationRequested {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("durable cancellation status=%s requested=%t err=%v", record.Job.Status, record.Job.CancellationRequested, getErr)
		}
		time.Sleep(time.Millisecond)
	}
}
