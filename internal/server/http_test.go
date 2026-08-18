package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

func TestHandlerRoutes(t *testing.T) {
	for name, testCase := range map[string]struct {
		method          string
		path            string
		ready           bool
		wantStatus      int
		wantCode        string
		wantStatusValue string
	}{
		"live":                  {method: http.MethodGet, path: "/health/live", ready: false, wantStatus: http.StatusOK, wantStatusValue: "live"},
		"ready":                 {method: http.MethodGet, path: "/health/ready", ready: true, wantStatus: http.StatusOK, wantStatusValue: "ready"},
		"not ready":             {method: http.MethodGet, path: "/health/ready", ready: false, wantStatus: http.StatusServiceUnavailable, wantCode: "not_ready"},
		"login placeholder":     {method: http.MethodGet, path: "/auth/login", wantStatus: http.StatusNotImplemented, wantCode: "not_implemented"},
		"callback placeholder":  {method: http.MethodGet, path: "/auth/callback", wantStatus: http.StatusNotImplemented, wantCode: "not_implemented"},
		"logout placeholder":    {method: http.MethodPost, path: "/auth/logout", wantStatus: http.StatusNotImplemented, wantCode: "not_implemented"},
		"protected API root":    {method: http.MethodGet, path: "/api/v1", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"protected API":         {method: http.MethodGet, path: "/api/v1/session", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"protected unknown API": {method: http.MethodGet, path: "/api/v1/future", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"unknown route":         {method: http.MethodGet, path: "/missing", wantStatus: http.StatusNotFound, wantCode: "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			handler := NewHandler(HandlerOptions{IsReady: func() bool { return testCase.ready }})
			response := httptest.NewRecorder()
			request := httptest.NewRequest(testCase.method, testCase.path, nil)
			handler.ServeHTTP(response, request)

			if response.Code != testCase.wantStatus {
				t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
			}
			if response.Header().Get("Content-Type") != "application/json" || response.Header().Get("X-Request-ID") == "" {
				t.Fatalf("headers = %#v", response.Header())
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("security headers = %#v", response.Header())
			}
			if testCase.wantCode != "" {
				var envelope api.ErrorEnvelope
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.Error.Code != testCase.wantCode || envelope.Error.RequestID != response.Header().Get("X-Request-ID") {
					t.Fatalf("error envelope = %#v", envelope)
				}
			}
			if testCase.wantStatusValue != "" {
				var body map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["status"] != testCase.wantStatusValue {
					t.Fatalf("body = %#v", body)
				}
			}
		})
	}
}

func TestAuthenticatedSessionAndProtectedRouting(t *testing.T) {
	handler := NewHandler(HandlerOptions{
		Authenticator: authtest.Authenticator{Actor: auth.Actor{
			Subject:     "operator-1",
			DisplayName: "Operator",
			Roles:       []auth.Role{auth.RoleViewer, auth.RolePlanner, auth.RoleViewer},
		}},
	})

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var session api.SessionResponse
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.APIVersion != api.Version || !session.Authenticated || session.Actor.Subject != "operator-1" || session.Actor.DisplayName != "Operator" || len(session.Actor.Roles) != 2 || session.Actor.Roles[0] != auth.RolePlanner || session.Actor.Roles[1] != auth.RoleViewer {
		t.Fatalf("session = %#v", session)
	}

	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/api/v1/future", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown protected status=%d body=%q", unknown.Code, unknown.Body.String())
	}
}

func TestProtectedRouteAuthorizationDeniesActorWithoutRole(t *testing.T) {
	handler := NewHandler(HandlerOptions{
		Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "operator-1"}},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	var envelope api.ErrorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != "permission_denied" {
		t.Fatalf("error = %#v", envelope.Error)
	}
}

func TestProtectedRouteAuthenticationErrorsRemainGeneric(t *testing.T) {
	handler := NewHandler(HandlerOptions{
		Authenticator: authtest.Authenticator{Err: errors.New("token contained sensitive diagnostic")},
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "sensitive diagnostic") {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestMutationJobPlaceholdersEnforceRoleAndRequestContract(t *testing.T) {
	for name, testCase := range map[string]struct {
		roles       []auth.Role
		method      string
		path        string
		contentType string
		key         string
		wantStatus  int
		wantCode    string
	}{
		"validation planner":   {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPost, path: "/api/v1/validations", contentType: "application/json", key: "validation-request-1", wantStatus: http.StatusServiceUnavailable, wantCode: "validation_unavailable"},
		"plan planner":         {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPost, path: "/api/v1/plans", contentType: "application/json; charset=utf-8", key: "plan-request-1", wantStatus: http.StatusNotImplemented, wantCode: "job_execution_not_implemented"},
		"apply applier":        {roles: []auth.Role{auth.RoleApplier}, method: http.MethodPost, path: "/api/v1/plans/plan-1/apply", contentType: "application/json", key: "apply-request-1", wantStatus: http.StatusNotImplemented, wantCode: "job_execution_not_implemented"},
		"viewer denied":        {roles: []auth.Role{auth.RoleViewer}, method: http.MethodPost, path: "/api/v1/plans", contentType: "application/json", key: "plan-request-1", wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
		"planner cannot apply": {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPost, path: "/api/v1/plans/plan-1/apply", contentType: "application/json", key: "apply-request-1", wantStatus: http.StatusForbidden, wantCode: "permission_denied"},
		"missing key":          {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPost, path: "/api/v1/plans", contentType: "application/json", wantStatus: http.StatusBadRequest, wantCode: "invalid_idempotency_key"},
		"wrong content type":   {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPost, path: "/api/v1/plans", contentType: "text/plain", key: "plan-request-1", wantStatus: http.StatusUnsupportedMediaType, wantCode: "json_required"},
		"wrong method":         {roles: []auth.Role{auth.RolePlanner}, method: http.MethodPatch, path: "/api/v1/plans", contentType: "application/json", key: "plan-request-1", wantStatus: http.StatusMethodNotAllowed, wantCode: "method_not_allowed"},
		"unknown plan path":    {roles: []auth.Role{auth.RoleApplier}, method: http.MethodPost, path: "/api/v1/plans/plan-1/resume", contentType: "application/json", key: "apply-request-1", wantStatus: http.StatusNotFound, wantCode: "not_found"},
	} {
		t.Run(name, func(t *testing.T) {
			handler := NewHandler(HandlerOptions{
				Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "operator-1", Roles: testCase.roles}},
			})
			request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(`{}`))
			if testCase.contentType != "" {
				request.Header.Set("Content-Type", testCase.contentType)
			}
			if testCase.key != "" {
				request.Header.Set(api.IdempotencyKeyHeader, testCase.key)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != testCase.wantStatus {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
			var envelope api.ErrorEnvelope
			if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if envelope.Error.Code != testCase.wantCode {
				t.Fatalf("error=%#v", envelope.Error)
			}
			if strings.Contains(response.Body.String(), testCase.key) && testCase.key != "" {
				t.Fatal("response echoed idempotency key")
			}
		})
	}
}

func TestMutationJobPlaceholderIsDeniedWithoutAuthentication(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(api.IdempotencyKeyHeader, "plan-request-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestOpenAPIEndpoint(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/openapi.json", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", response.Code, response.Body.String())
	}
	var document map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %#v", document["openapi"])
	}
}

func TestHandlerHEADAndMethodRules(t *testing.T) {
	handler := NewHandler(HandlerOptions{})

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/health/live", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%q", head.Code, head.Body.String())
	}

	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, "/health/live", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed || wrongMethod.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("status=%d allow=%q", wrongMethod.Code, wrongMethod.Header().Get("Allow"))
	}
}

func TestHandlerRejectsOversizedBodyBeforeRouting(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(strings.Repeat("x", maxRequestBodyBytes+1)))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestRequestIDsAreServerGenerated(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	request.Header.Set("X-Request-ID", "attacker-controlled")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	got := response.Header().Get("X-Request-ID")
	if got == "" || got == "attacker-controlled" || !requestIDPattern.MatchString(got) {
		t.Fatalf("X-Request-ID = %q", got)
	}
}

func TestRecoveryAndAccessLogsExcludeSensitiveValues(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	panicHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("credential-value-must-not-be-logged")
	})
	handler := requestIDMiddleware(accessLogMiddleware(logger, recoveryMiddleware(logger, panicHandler)))
	request := httptest.NewRequest(http.MethodGet, "/panic?api_key=query-secret", nil)
	request.Header.Set("Authorization", "Bearer header-secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	for _, forbidden := range []string{"credential-value-must-not-be-logged", "query-secret", "header-secret", "Authorization", "api_key"} {
		if strings.Contains(logs.String(), forbidden) {
			t.Fatalf("logs contain %q: %s", forbidden, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "HTTP handler panic recovered") || !strings.Contains(logs.String(), `"path":"/panic"`) {
		t.Fatalf("logs = %s", logs.String())
	}
}

func TestHTTPRuntimeServesAndShutsDown(t *testing.T) {
	cfg, err := config.LoadServerConfig("../config/testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := func(network, address string) (net.Listener, error) {
		if network != "tcp" || address != cfg.Listen {
			t.Fatalf("listen(%q, %q)", network, address)
		}
		return listener, nil
	}
	var logs bytes.Buffer
	runtimeValue, err := newHTTPRuntime(cfg, BuildInfo{}, slog.New(slog.NewJSONHandler(&logs, nil)), listen)
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeValue.(*HTTPRuntime)
	serveResult := make(chan error, 1)
	go func() { serveResult <- runtime.Serve() }()

	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/health/ready")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(response.Body)
	response.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), `"status":"ready"`) {
		t.Fatalf("status=%d body=%q", response.StatusCode, body)
	}
	if runtime.build != (BuildInfo{Version: "dev", Commit: "none", Date: "unknown"}) {
		t.Fatalf("build = %#v", runtime.build)
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtime.Shutdown(shutdownContext); err != nil {
		t.Fatal(err)
	}
	if err := <-serveResult; err != nil {
		t.Fatalf("Serve() error = %v", err)
	}
	if runtime.ready.Load() {
		t.Fatal("runtime remained ready after shutdown")
	}
}

func TestNewHTTPRuntimeValidatesBeforeListening(t *testing.T) {
	called := false
	listen := func(string, string) (net.Listener, error) {
		called = true
		return nil, errors.New("must not be called")
	}
	_, err := newHTTPRuntime(&config.ServerConfig{}, BuildInfo{}, slog.Default(), listen)
	if err == nil || called {
		t.Fatalf("error=%v listenCalled=%v", err, called)
	}
}
