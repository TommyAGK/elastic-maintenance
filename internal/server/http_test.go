package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/credentials"
	"golang.org/x/crypto/argon2"
)

type fakeCredentialBackend struct {
	status      credentials.Status
	err         error
	put         credentials.PutRequest
	target, key string
	actor       auth.Actor
	deleted     bool
}

func (backend *fakeCredentialBackend) Status(context.Context, string) (credentials.Status, error) {
	return backend.status, backend.err
}
func (backend *fakeCredentialBackend) Put(_ context.Context, target, key string, actor auth.Actor, request credentials.PutRequest) (credentials.Status, error) {
	backend.target, backend.key, backend.actor, backend.put = target, key, actor, request
	return backend.status, backend.err
}
func (backend *fakeCredentialBackend) Delete(_ context.Context, target, key string, actor auth.Actor) (credentials.Status, error) {
	backend.target, backend.key, backend.actor, backend.deleted = target, key, actor, true
	return backend.status, backend.err
}

type recordingAudit struct{ events []audit.Event }

func (recorder *recordingAudit) Record(_ context.Context, event audit.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	recorder.events = append(recorder.events, event)
	return nil
}

type serverMappedSecrets map[string][]byte

func (secrets serverMappedSecrets) Read(_ context.Context, ref config.SecretKeyRef) ([]byte, error) {
	value, ok := secrets[ref.Key]
	if !ok {
		return nil, errors.New("missing")
	}
	return append([]byte{}, value...), nil
}

type serverSessionSecrets struct{ contents []byte }

func (secrets serverSessionSecrets) Read(context.Context, config.SecretKeyRef) ([]byte, error) {
	return append([]byte{}, secrets.contents...), nil
}

type successfulBrowserAuth struct{}

func (successfulBrowserAuth) BeginLogin(http.ResponseWriter, *http.Request) error       { return nil }
func (successfulBrowserAuth) CompleteCallback(http.ResponseWriter, *http.Request) error { return nil }
func (successfulBrowserAuth) Logout(w http.ResponseWriter, _ *http.Request) error {
	w.WriteHeader(http.StatusNoContent)
	return nil
}

type conflictBrowserAuth struct{}

func (conflictBrowserAuth) BeginLogin(http.ResponseWriter, *http.Request) error {
	return auth.ErrAuthenticationConflict
}
func (conflictBrowserAuth) CompleteCallback(http.ResponseWriter, *http.Request) error {
	return auth.ErrAuthenticationConflict
}
func (conflictBrowserAuth) Logout(http.ResponseWriter, *http.Request) error {
	return auth.ErrAuthenticationConflict
}

func TestBreakGlassLoginWorksWithoutOIDCAndIsAudited(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	salt := bytes.Repeat([]byte{7}, 16)
	password := "vault-only-sentinel-password"
	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 1, 32)
	generation := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 16))
	credential := []byte("elastic-maintainer-break-glass/v1\ngeneration " + generation + "\nverifier $argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(hash) + "\n")
	cfg := &config.ServerConfig{PublicURL: "https://app.example.test", OIDC: config.OIDCConfig{SecretMountRoot: "/secrets", SessionSecret: config.SecretKeyRef{Namespace: "ns", Name: "session", Key: "keys"}}, BreakGlass: config.BreakGlassConfig{Enabled: true, Username: "break-glass-admin", CredentialSecret: config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}}}
	var events []auth.BreakGlassAuditEvent
	service, err := auth.NewBreakGlass(auth.BreakGlassOptions{Config: cfg, Secrets: serverMappedSecrets{"keys": []byte("elastic-maintainer-session-keyring/v1\ncurrent active " + key + "\n"), "credential": credential}, Audit: func(_ context.Context, event auth.BreakGlassAuditEvent) error {
		events = append(events, event)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	oidcService, err := auth.NewBrowserOIDC(auth.BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: "https://unreachable-idp.invalid", EndpointOrigins: []string{"https://unreachable-idp.invalid"}, ClientID: "client", ClientSecret: config.SecretKeyRef{Key: "client"}, SessionSecret: cfg.OIDC.SessionSecret, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}}, Secrets: serverMappedSecrets{"keys": []byte("elastic-maintainer-session-keyring/v1\ncurrent active " + key + "\n")}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(HandlerOptions{Authenticator: auth.NewCompositeAuthenticator(oidcService, service), BrowserAuth: oidcService, BreakGlassAuth: service, LogoutAuth: service})
	login := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/break-glass/login", strings.NewReader(`{"username":"break-glass-admin","password":"`+password+`"}`))
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("Origin", "https://app.example.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, login)
	if response.Code != http.StatusNoContent {
		t.Fatalf("login status=%d body=%s", response.Code, response.Body.String())
	}
	session := response.Result().Cookies()[0]
	inspect := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	inspect.AddCookie(session)
	inspected := httptest.NewRecorder()
	handler.ServeHTTP(inspected, inspect)
	if inspected.Code != http.StatusOK || !strings.Contains(inspected.Body.String(), `"authenticationMethod":"break-glass"`) || !strings.Contains(inspected.Body.String(), `"expiresAt"`) {
		t.Fatalf("session status=%d body=%s", inspected.Code, inspected.Body.String())
	}
	if strings.Contains(inspected.Body.String(), password) || len(events) != 1 || events[0].Outcome != "succeeded" {
		t.Fatalf("unsafe response or audit events=%#v", events)
	}
}

func TestBrowserCallbackConflictReturnsDocumentedStatus(t *testing.T) {
	handler := NewHandler(HandlerOptions{BrowserAuth: conflictBrowserAuth{}})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/callback", nil))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "authentication_conflict") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRoutes(t *testing.T) {
	for name, testCase := range map[string]struct {
		method          string
		path            string
		ready           bool
		wantStatus      int
		wantCode        string
		wantStatusValue string
	}{
		"live":                   {method: http.MethodGet, path: "/health/live", ready: false, wantStatus: http.StatusOK, wantStatusValue: "live"},
		"ready":                  {method: http.MethodGet, path: "/health/ready", ready: true, wantStatus: http.StatusOK, wantStatusValue: "ready"},
		"not ready":              {method: http.MethodGet, path: "/health/ready", ready: false, wantStatus: http.StatusServiceUnavailable, wantCode: "not_ready"},
		"OIDC unavailable":       {method: http.MethodGet, path: "/auth/login", wantStatus: http.StatusServiceUnavailable, wantCode: "oidc_unavailable"},
		"callback unavailable":   {method: http.MethodGet, path: "/auth/callback", wantStatus: http.StatusServiceUnavailable, wantCode: "oidc_unavailable"},
		"logout unauthenticated": {method: http.MethodPost, path: "/auth/logout", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"protected API root":     {method: http.MethodGet, path: "/api/v1", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"protected API":          {method: http.MethodGet, path: "/api/v1/session", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"protected unknown API":  {method: http.MethodGet, path: "/api/v1/future", wantStatus: http.StatusUnauthorized, wantCode: "authentication_required"},
		"unknown route":          {method: http.MethodGet, path: "/missing", wantStatus: http.StatusNotFound, wantCode: "not_found"},
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
	if session.APIVersion != api.Version || !session.Authenticated || session.AuthenticationMethod != auth.MethodSession || session.Actor.Subject != "operator-1" || session.Actor.DisplayName != "Operator" || len(session.Actor.Roles) != 2 || session.Actor.Roles[0] != auth.RolePlanner || session.Actor.Roles[1] != auth.RoleViewer {
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

func TestAuthenticationAmbiguityReturnsConflict(t *testing.T) {
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	service, err := auth.NewBrowserOIDC(auth.BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: "https://identity.example.test", EndpointOrigins: []string{"https://identity.example.test"}, ClientID: "client", SessionSecret: config.SecretKeyRef{Key: "session"}, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}}, Authorization: config.AuthorizationConfig{}, Secrets: serverSessionSecrets{contents: []byte("elastic-maintainer-session-keyring/v1\ncurrent test " + key + "\n")}})
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(HandlerOptions{Authenticator: service, BrowserAuth: service})
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "first"})
	request.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "second"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "authentication_conflict") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
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

func TestCredentialEndpointsEnforceContractOriginRBACAndNoReadback(t *testing.T) {
	rotated := time.Now().UTC()
	backend := &fakeCredentialBackend{status: credentials.Status{Configured: true, SecretResourceVersion: "7", RotatedAt: rotated, RotatedBy: "admin"}}
	admin := auth.Actor{Subject: "admin", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodOIDC, CSRFToken: "csrf-token"}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: admin}, CredentialBackend: backend, PublicURL: "https://app.example.test"})
	put := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"credential-sentinel"}`))
	put.Header.Set("Content-Type", "application/json")
	put.Header.Set("Origin", "https://app.example.test")
	put.Header.Set(api.CSRFTokenHeader, "csrf-token")
	put.Header.Set(api.IdempotencyKeyHeader, "credential-request")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, put)
	if response.Code != http.StatusOK || backend.target != "prod" || backend.key != "credential-request" || backend.put.APIKey != "credential-sentinel" || strings.Contains(response.Body.String(), "credential-sentinel") {
		t.Fatalf("status=%d body=%s backend=%#v", response.Code, response.Body.String(), backend)
	}
	statusRequest := httptest.NewRequest(http.MethodGet, "/api/v1/targets/prod/credential-status", nil)
	statusResponse := httptest.NewRecorder()
	handler.ServeHTTP(statusResponse, statusRequest)
	if statusResponse.Code != http.StatusOK || !strings.Contains(statusResponse.Body.String(), `"secretResourceVersion":"7"`) {
		t.Fatalf("status response=%d %s", statusResponse.Code, statusResponse.Body.String())
	}
	missingCSRF := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"x"}`))
	missingCSRF.Header.Set("Content-Type", "application/json")
	missingCSRF.Header.Set("Origin", "https://app.example.test")
	missingCSRF.Header.Set(api.IdempotencyKeyHeader, "missing-csrf")
	missingCSRFResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRFResponse, missingCSRF)
	if missingCSRFResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF status=%d", missingCSRFResponse.Code)
	}
	bearerActor := auth.Actor{Subject: "automation", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodBearer}
	bearerHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: bearerActor}, CredentialBackend: backend, PublicURL: "https://app.example.test"})
	bearerRequest := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"bearer-value"}`))
	bearerRequest.Header.Set("Content-Type", "application/json")
	bearerRequest.Header.Set(api.IdempotencyKeyHeader, "bearer-request")
	bearerResponse := httptest.NewRecorder()
	bearerHandler.ServeHTTP(bearerResponse, bearerRequest)
	if bearerResponse.Code != http.StatusOK {
		t.Fatalf("bearer status=%d body=%s", bearerResponse.Code, bearerResponse.Body.String())
	}
	proxyHandler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: admin}, CredentialBackend: backend, PublicURL: "https://app.example.test", TrustedProxies: []string{"10.0.0.0/8"}})
	proxyRequest := httptest.NewRequest(http.MethodPut, "http://internal/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"proxy-value"}`))
	proxyRequest.RemoteAddr = "10.0.0.2:1234"
	proxyRequest.Header.Set("X-Forwarded-Proto", "https")
	proxyRequest.Header.Set("X-Forwarded-Host", "app.example.test")
	proxyRequest.Header.Set("Origin", "https://app.example.test")
	proxyRequest.Header.Set(api.CSRFTokenHeader, "csrf-token")
	proxyRequest.Header.Set("Content-Type", "application/json")
	proxyRequest.Header.Set(api.IdempotencyKeyHeader, "proxy-request")
	proxyResponse := httptest.NewRecorder()
	proxyHandler.ServeHTTP(proxyResponse, proxyRequest)
	if proxyResponse.Code != http.StatusOK {
		t.Fatalf("proxy status=%d body=%s", proxyResponse.Code, proxyResponse.Body.String())
	}
	badOrigin := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"x"}`))
	badOrigin.Header.Set("Content-Type", "application/json")
	badOrigin.Header.Set(api.IdempotencyKeyHeader, "bad-origin")
	badResponse := httptest.NewRecorder()
	handler.ServeHTTP(badResponse, badOrigin)
	if badResponse.Code != http.StatusBadRequest {
		t.Fatalf("missing origin status=%d", badResponse.Code)
	}
	viewer := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}}, CredentialBackend: backend, PublicURL: "https://app.example.test"})
	denied := httptest.NewRecorder()
	viewer.ServeHTTP(denied, put.Clone(context.Background()))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("viewer status=%d", denied.Code)
	}
	deleteRequest := httptest.NewRequest(http.MethodDelete, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"confirm":true}`))
	deleteRequest.Header.Set("Content-Type", "application/json")
	deleteRequest.Header.Set("Origin", "https://app.example.test")
	deleteRequest.Header.Set(api.CSRFTokenHeader, "csrf-token")
	deleteRequest.Header.Set(api.IdempotencyKeyHeader, "delete-request")
	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, deleteRequest)
	if deleted.Code != http.StatusOK || !backend.deleted {
		t.Fatalf("delete status=%d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestCredentialMutationRejectsMalformedLivePublicOrigins(t *testing.T) {
	request := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", nil)
	request = request.WithContext(auth.WithActor(request.Context(), auth.Actor{Subject: "automation", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodBearer}))
	for _, publicURL := range []string{"https://:443", "https://app.example.test:", "https://app.example.test:99999", "http://app.example.test"} {
		if validCredentialMutationOrigin(request, publicURL, nil) {
			t.Errorf("publicURL %q accepted", publicURL)
		}
	}
}

func TestCredentialEndpointErrorsAreGeneric(t *testing.T) {
	backend := &fakeCredentialBackend{err: errors.New("credential-value-must-not-escape")}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}}}, CredentialBackend: backend})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/targets/prod/credential-status", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "credential-value") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestEveryProtectedEndpointUsesTheCentralRoleMatrix(t *testing.T) {
	routes := []struct {
		method, path string
		permission   auth.Permission
	}{{"GET", "/api/v1/session", auth.PermissionSessionRead}, {"GET", "/api/v1/sources", auth.PermissionSourcesRead}, {"GET", "/api/v1/sources/source-1", auth.PermissionSourcesRead}, {"GET", "/api/v1/targets", auth.PermissionTargetsRead}, {"GET", "/api/v1/targets/target-1", auth.PermissionTargetsRead}, {"GET", "/api/v1/targets/target-1/credential-status", auth.PermissionCredentialsRead}, {"PUT", "/api/v1/targets/target-1/credentials", auth.PermissionCredentialsWrite}, {"DELETE", "/api/v1/targets/target-1/credentials", auth.PermissionCredentialsWrite}, {"GET", "/api/v1/validations", auth.PermissionValidationsRead}, {"POST", "/api/v1/validations", auth.PermissionValidationsCreate}, {"GET", "/api/v1/validations/job-1", auth.PermissionValidationsRead}, {"GET", "/api/v1/plans", auth.PermissionPlansRead}, {"POST", "/api/v1/plans", auth.PermissionPlansCreate}, {"GET", "/api/v1/plans/plan-1", auth.PermissionPlansRead}, {"POST", "/api/v1/plans/plan-1/apply", auth.PermissionPlansApply}, {"GET", "/api/v1/jobs", auth.PermissionJobsRead}, {"GET", "/api/v1/jobs/job-1", auth.PermissionJobsRead}, {"GET", "/api/v1/reports", auth.PermissionReportsRead}, {"GET", "/api/v1/reports/report-1", auth.PermissionReportsRead}, {"GET", "/api/v1/audit", auth.PermissionAuditRead}}
	for _, role := range auth.KnownRoles() {
		actor := auth.Actor{Subject: "operator", Roles: []auth.Role{role}, Method: auth.MethodSession}
		handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}})
		for _, route := range routes {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set(api.IdempotencyKeyHeader, "matrix-key")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			allowed := actor.HasPermission(route.permission)
			if allowed && response.Code == http.StatusForbidden {
				t.Errorf("role=%s %s %s unexpectedly denied", role, route.method, route.path)
			}
			if !allowed && response.Code != http.StatusForbidden {
				t.Errorf("role=%s %s %s status=%d want403", role, route.method, route.path, response.Code)
			}
		}
	}
}

func TestLogoutAuditIsRecordedExactlyOnce(t *testing.T) {
	recorder := &recordingAudit{}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "operator", Roles: []auth.Role{auth.RoleViewer}}}, LogoutAuth: successfulBrowserAuth{}, AuditRecorder: recorder})
	request := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || len(recorder.events) != 1 || recorder.events[0].Action != audit.ActionLogout || recorder.events[0].Outcome != audit.OutcomeSucceeded {
		t.Fatalf("status=%d events=%#v", response.Code, recorder.events)
	}
}

func TestCredentialAuditDistinguishesUploadAndRotation(t *testing.T) {
	recorder := &recordingAudit{}
	backend := &fakeCredentialBackend{status: credentials.Status{Configured: true, Created: true, SecretResourceVersion: "1"}}
	actor := auth.Actor{Subject: "admin", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodOIDC, CSRFToken: "csrf"}
	handler := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: actor}, CredentialBackend: backend, PublicURL: "https://app.example.test", AuditRecorder: recorder})
	request := func(key string) *http.Request {
		item := httptest.NewRequest(http.MethodPut, "https://app.example.test/api/v1/targets/prod/credentials", strings.NewReader(`{"apiKey":"value"}`))
		item.Header.Set("Content-Type", "application/json")
		item.Header.Set("Origin", "https://app.example.test")
		item.Header.Set(api.CSRFTokenHeader, "csrf")
		item.Header.Set(api.IdempotencyKeyHeader, key)
		return item
	}
	handler.ServeHTTP(httptest.NewRecorder(), request("upload-key"))
	backend.status.Created = false
	handler.ServeHTTP(httptest.NewRecorder(), request("rotate-key"))
	if len(recorder.events) != 2 || recorder.events[0].Action != audit.ActionCredentialUpload || recorder.events[1].Action != audit.ActionCredentialRotate || recorder.events[1].TargetID != "prod" {
		t.Fatalf("events=%#v", recorder.events)
	}
}

func TestMutationAuditHooksRecordActorActionAndOutcome(t *testing.T) {
	recorder := &recordingAudit{}
	backend := newPhaseOneBackend()
	planner := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "planner", Roles: []auth.Role{auth.RolePlanner}}}, ValidationBackend: backend, AuditRecorder: recorder})
	response := serveRequest(planner, http.MethodPost, "/api/v1/validations", `{}`, "audit-validation")
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	viewer := NewHandler(HandlerOptions{Authenticator: authtest.Authenticator{Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}}}, ValidationBackend: backend, AuditRecorder: recorder})
	response = serveRequest(viewer, http.MethodPost, "/api/v1/validations", `{}`, "audit-denied")
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d", response.Code)
	}
	response = serveRequest(planner, http.MethodPost, "/api/v1/plans", `{}`, "audit-plan")
	if response.Code != http.StatusNotImplemented {
		t.Fatalf("status=%d", response.Code)
	}
	if len(recorder.events) != 3 {
		t.Fatalf("events=%#v", recorder.events)
	}
	if recorder.events[0].Action != audit.ActionValidationCreate || recorder.events[0].Outcome != audit.OutcomeSucceeded || recorder.events[0].Actor.Subject != "planner" {
		t.Fatalf("success=%#v", recorder.events[0])
	}
	if recorder.events[1].Outcome != audit.OutcomeDenied || recorder.events[1].Actor.Subject != "viewer" {
		t.Fatalf("denied=%#v", recorder.events[1])
	}
	if recorder.events[2].Action != audit.ActionPlanCreate || recorder.events[2].Outcome != audit.OutcomeFailed {
		t.Fatalf("failed=%#v", recorder.events[2])
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

func TestEmbeddedWebInterfaceRoutesAndSecurityHeaders(t *testing.T) {
	handler := NewHandler(HandlerOptions{})
	for _, testCase := range []struct{ path, contentType, contains string }{
		{path: "/", contentType: "text/html; charset=utf-8", contains: "Elastic Maintainer"},
		{path: "/sources", contentType: "text/html; charset=utf-8", contains: "External GitOps owns desired state"},
		{path: "/assets/app.css", contentType: "text/css; charset=utf-8", contains: ":root"},
		{path: "/assets/app.js", contentType: "text/javascript; charset=utf-8", contains: "/api/v1/validations"},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, testCase.path, nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != testCase.contentType || !strings.Contains(response.Body.String(), testCase.contains) {
			t.Errorf("GET %s status=%d type=%q body=%q", testCase.path, response.Code, response.Header().Get("Content-Type"), response.Body.String())
		}
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), "default-src 'none'") || response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Errorf("GET %s security headers = %#v", testCase.path, response.Header())
		}
	}
	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD / status=%d body=%q", head.Code, head.Body.String())
	}
	wrongMethod := httptest.NewRecorder()
	handler.ServeHTTP(wrongMethod, httptest.NewRequest(http.MethodPost, "/assets/app.js", nil))
	if wrongMethod.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST asset status=%d", wrongMethod.Code)
	}
	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil))
	if missing.Code != http.StatusNotFound || missing.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("missing asset status=%d type=%q", missing.Code, missing.Header().Get("Content-Type"))
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
	cfg.OIDC.Enabled = false
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
	if runtime.targetClients == nil {
		t.Fatal("target client factory was not wired")
	}
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

func TestHTTPRuntimeOIDCInitializationDoesNotContactProvider(t *testing.T) {
	cfg, err := config.LoadServerConfig("../config/testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	cfg.OIDC.SecretMountRoot = root
	directory := filepath.Join(root, cfg.OIDC.SessionSecret.Namespace, cfg.OIDC.SessionSecret.Name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if err := os.WriteFile(filepath.Join(directory, cfg.OIDC.SessionSecret.Key), []byte("elastic-maintainer-session-keyring/v1\ncurrent test "+key+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.IssuerURL = "https://127.0.0.1:1"
	cfg.OIDC.EndpointOrigins = []string{"https://127.0.0.1:1"}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listen := func(string, string) (net.Listener, error) { return listener, nil }
	runtimeValue, err := newHTTPRuntime(cfg, BuildInfo{}, slog.New(slog.NewTextHandler(io.Discard, nil)), listen)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := runtimeValue.Shutdown(ctx); err != nil {
		t.Fatal(err)
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
