package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"golang.org/x/crypto/argon2"
)

func testBreakGlassAudit(context.Context, BreakGlassAuditEvent) error { return nil }

func TestBreakGlassLoginAndLiveSessionValidation(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	generation := randomBreakGlassGeneration(t)
	password := "correct horse battery staple"
	credential := breakGlassCredentialFixture(t, generation, password)
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	secrets := memorySecrets{"keys": keyRingFixture("active", nil), "credential": credential}
	service, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: testBreakGlassAudit, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/break-glass", strings.NewReader(`{"username":"break-glass-admin","password":"correct horse battery staple"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://app.example.test")
	response := httptest.NewRecorder()
	if err := service.Login(response, request); err != nil {
		t.Fatalf("Login() error=%v", err)
	}
	if response.Code != http.StatusOK || response.Header().Get("Location") != "" {
		t.Fatalf("login response status=%d location=%q", response.Code, response.Header().Get("Location"))
	}
	session := cookieByName(t, response.Result().Cookies(), SessionCookieName)
	if !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" {
		t.Fatalf("session cookie attributes=%#v", session)
	}
	if strings.Contains(session.Value, password) || strings.Contains(session.Value, cfg.BreakGlass.Username) {
		t.Fatal("session cookie exposed login material")
	}

	authenticated := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	authenticated.AddCookie(session)
	actor, err := service.Authenticate(authenticated)
	if err != nil {
		t.Fatalf("Authenticate() error=%v", err)
	}
	if actor.Subject != "break-glass-admin" || actor.Method != MethodBreakGlass || len(actor.Roles) != 1 || actor.Roles[0] != RoleAdministrator {
		t.Fatalf("actor=%#v", actor)
	}

	keys, _ := newKeyRingSource(secrets, cfg.OIDC.SessionSecret)
	var payload sessionPayload
	if err := newCookieCodec(keys, func() time.Time { return clock }).decode(context.Background(), "session", session.Value, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Revision == "" || payload.Method != MethodBreakGlass || payload.ExpiresAt-payload.IssuedAt != int64(BreakGlassSessionLifetime/time.Second) {
		t.Fatalf("session payload=%#v", payload)
	}

	// The mounted credential is reloaded on every request. Changing only its
	// opaque generation invalidates the existing session.
	secrets["credential"] = breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), password)
	if _, err := service.Authenticate(authenticated); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("rotated credential error=%v", err)
	}
}

func TestBreakGlassRejectsPreviousSessionKeyButOIDCCodecKeepsOverlap(t *testing.T) {
	password := "correct horse battery staple"
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	secrets := memorySecrets{"keys": keyRingFixture("one", nil), "credential": breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), password)}
	service, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: testBreakGlassAudit})
	if err != nil {
		t.Fatal(err)
	}
	cookie, _, err := service.AuthenticateCredentials(context.Background(), cfg.BreakGlass.Username, password)
	if err != nil {
		t.Fatal(err)
	}
	secrets["keys"] = keyRingFixture("two", []string{"one"})
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	if _, err := service.Authenticate(request); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("previous key was accepted: %v", err)
	}
	keys, _ := newKeyRingSource(secrets, cfg.OIDC.SessionSecret)
	var payload sessionPayload
	if err := newCookieCodec(keys, time.Now).decode(context.Background(), "session", cookie, &payload); err != nil {
		t.Fatalf("OIDC-compatible cookie decoder rejected previous key: %v", err)
	}
}

func TestBreakGlassLoginRequiresSameOriginPOSTAndGenericFailure(t *testing.T) {
	password := "correct horse battery staple"
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	secrets := memorySecrets{"keys": keyRingFixture("active", nil), "credential": breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), password)}
	service, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: testBreakGlassAudit})
	if err != nil {
		t.Fatal(err)
	}
	newRequest := func(method, origin, body string) *http.Request {
		request := httptest.NewRequest(method, "https://app.example.test/auth/break-glass", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		return request
	}
	for name, request := range map[string]*http.Request{
		"get":             newRequest(http.MethodGet, "https://app.example.test", "{}"),
		"missing origin":  newRequest(http.MethodPost, "", `{"username":"break-glass-admin","password":"`+password+`"}`),
		"other origin":    newRequest(http.MethodPost, "https://other.example.test", `{"username":"break-glass-admin","password":"`+password+`"}`),
		"null field":      newRequest(http.MethodPost, "https://app.example.test", `{"username":null,"password":"x"}`),
		"duplicate field": newRequest(http.MethodPost, "https://app.example.test", `{"username":"a","username":"b","password":"x"}`),
		"unknown field":   newRequest(http.MethodPost, "https://app.example.test", `{"username":"a","password":"x","extra":true}`),
	} {
		t.Run(name, func(t *testing.T) {
			if err := service.Login(httptest.NewRecorder(), request); err == nil {
				t.Fatal("Login() error=nil")
			}
		})
	}
	bad := newRequest(http.MethodPost, "https://app.example.test", `{"username":"not-the-user","password":"wrong"}`)
	if err := service.Login(httptest.NewRecorder(), bad); !errors.Is(err, ErrBreakGlassAuthenticationFailed) {
		t.Fatalf("wrong credentials error=%v", err)
	}
	if strings.Contains(errString(func() error { return service.Login(httptest.NewRecorder(), bad) }), password) {
		t.Fatal("authentication error exposed password")
	}
}

func TestBreakGlassAuditFailurePreventsSession(t *testing.T) {
	password := "audit-sentinel-password"
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	secrets := memorySecrets{"keys": keyRingFixture("active", nil), "credential": breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), password)}
	var events []BreakGlassAuditEvent
	service, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: func(_ context.Context, event BreakGlassAuditEvent) error {
		events = append(events, event)
		if event.Outcome == "succeeded" {
			return errors.New("audit unavailable")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/break-glass/login", strings.NewReader(`{"username":"break-glass-admin","password":"`+password+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://app.example.test")
	response := httptest.NewRecorder()
	if err := service.Login(response, request); !errors.Is(err, ErrBreakGlassAuthenticationFailed) {
		t.Fatalf("error=%v", err)
	}
	if len(response.Result().Cookies()) != 0 || len(events) != 1 || events[0].Actor == nil {
		t.Fatalf("cookies/events=%#v %#v", response.Result().Cookies(), events)
	}
	denied, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: func(context.Context, BreakGlassAuditEvent) error { return errors.New("audit unavailable") }})
	if err != nil {
		t.Fatal(err)
	}
	wrong := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/break-glass/login", strings.NewReader(`{"username":"break-glass-admin","password":"wrong"}`))
	wrong.Header.Set("Content-Type", "application/json")
	wrong.Header.Set("Origin", "https://app.example.test")
	if err := denied.Login(httptest.NewRecorder(), wrong); !errors.Is(err, ErrBreakGlassUnavailable) {
		t.Fatalf("denied audit error=%v", err)
	}
}

func TestBreakGlassLoginRejectsFormEncoding(t *testing.T) {
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	service, err := NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: memorySecrets{"keys": keyRingFixture("active", nil), "credential": breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), "password")}, Audit: testBreakGlassAudit})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/break-glass/login", strings.NewReader("username=x&password=y"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://app.example.test")
	if err := service.Login(httptest.NewRecorder(), request); !errors.Is(err, ErrBreakGlassUnsupportedMediaType) {
		t.Fatalf("error=%v", err)
	}
}

func TestBreakGlassThrottlesAndExpiresWithoutRenewal(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	password := "correct horse battery staple"
	ref := config.SecretKeyRef{Namespace: "ns", Name: "break-glass", Key: "credential"}
	cfg := breakGlassConfig(ref)
	secrets := memorySecrets{"keys": keyRingFixture("active", nil), "credential": breakGlassCredentialFixture(t, randomBreakGlassGeneration(t), password)}
	service, err := NewBreakGlass(BreakGlassOptions{
		Config: cfg, Secrets: secrets, Audit: testBreakGlassAudit, Now: func() time.Time { return clock },
		Throttle: BreakGlassThrottleOptions{FailuresBeforeLockout: 2, BaseDelay: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1; i++ {
		if _, _, err := service.AuthenticateCredentials(context.Background(), cfg.BreakGlass.Username, "wrong"); !errors.Is(err, ErrBreakGlassAuthenticationFailed) {
			t.Fatalf("failure %d error=%v", i, err)
		}
	}
	if _, _, err := service.AuthenticateCredentials(context.Background(), cfg.BreakGlass.Username, "wrong"); !errors.Is(err, ErrBreakGlassThrottled) {
		t.Fatalf("lockout error=%v", err)
	}
	cookie, _, err := service.AuthenticateCredentials(context.Background(), cfg.BreakGlass.Username, password)
	if !errors.Is(err, ErrBreakGlassThrottled) {
		t.Fatalf("locked successful credentials error=%v cookie=%q", err, cookie)
	}

	// A separate service demonstrates the absolute expiry and lack of renewal.
	service, err = NewBreakGlass(BreakGlassOptions{Config: cfg, Secrets: secrets, Audit: testBreakGlassAudit, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	cookie, expires, err := service.AuthenticateCredentials(context.Background(), cfg.BreakGlass.Username, password)
	if err != nil {
		t.Fatal(err)
	}
	if !expires.Equal(clock.Add(BreakGlassSessionLifetime)) {
		t.Fatalf("expires=%s", expires)
	}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	clock = clock.Add(BreakGlassSessionLifetime + time.Second)
	if _, err := service.Authenticate(request); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expired session error=%v", err)
	}
}

func TestBreakGlassCredentialDocumentIsStrictAndPinned(t *testing.T) {
	generation := strings.TrimRight(base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef")), "=")
	valid := []byte("elastic-maintainer-break-glass/v1\ngeneration " + generation + "\nverifier $argon2id$v=19$m=65536,t=3,p=1$" + base64.RawStdEncoding.EncodeToString(make([]byte, 16)) + "$" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)) + "\n")
	if _, err := ParseBreakGlassCredential(valid); err != nil {
		t.Fatalf("valid document error=%v", err)
	}
	for name, document := range map[string][]byte{
		"wrong header":      []byte("elastic-maintainer-break-glass/v2\ngeneration " + generation + "\nverifier x"),
		"extra line":        append(append([]byte{}, valid...), '\n'),
		"padded generation": []byte("elastic-maintainer-break-glass/v1\ngeneration " + generation + "=\nverifier x"),
		"wrong parameters":  []byte("elastic-maintainer-break-glass/v1\ngeneration " + generation + "\nverifier $argon2id$v=19$m=1,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
		"wrong salt length": []byte("elastic-maintainer-break-glass/v1\ngeneration " + generation + "\nverifier $argon2id$v=19$m=65536,t=3,p=1$AAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBreakGlassCredential(document); err == nil {
				t.Fatal("ParseBreakGlassCredential() error=nil")
			}
		})
	}
}

func breakGlassConfig(ref config.SecretKeyRef) *config.ServerConfig {
	return &config.ServerConfig{
		PublicURL: "https://app.example.test",
		OIDC: config.OIDCConfig{
			SecretMountRoot: "/var/run/secrets/elastic-maintainer",
			SessionSecret:   config.SecretKeyRef{Namespace: "ns", Name: "session", Key: "keys"},
		},
		BreakGlass: config.BreakGlassConfig{Enabled: true, Username: "break-glass-admin", CredentialSecret: ref},
	}
}

func breakGlassCredentialFixture(t *testing.T, generation, password string) []byte {
	t.Helper()
	salt := make([]byte, breakGlassArgonSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	hash := argon2.IDKey([]byte(password), salt, breakGlassArgonTime, breakGlassArgonMemory, breakGlassArgonThreads, breakGlassArgonHashBytes)
	return []byte(breakGlassCredentialHeader + "\ngeneration " + generation + "\nverifier $argon2id$v=19$m=65536,t=3,p=1$" + encodeBreakGlassPHC(salt) + "$" + encodeBreakGlassPHC(hash) + "\n")
}

func encodeBreakGlassPHC(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }

func randomBreakGlassGeneration(t *testing.T) string {
	t.Helper()
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func errString(fn func() error) string {
	return func() string {
		err := fn()
		if err == nil {
			return ""
		}
		return err.Error()
	}()
}
