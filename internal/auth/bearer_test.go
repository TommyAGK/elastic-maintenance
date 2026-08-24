package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/go-jose/go-jose/v4"
)

func TestBearerOIDCValidationAndIdentityAmbiguity(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var calls atomic.Int64
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig"}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL
	browser, err := NewBrowserOIDC(BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: issuer, EndpointOrigins: []string{issuer}, ClientID: "client", SessionSecret: config.SecretKeyRef{Key: "keys"}, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}}, Authorization: config.AuthorizationConfig{RoleClaim: "groups", RoleMapping: map[string][]string{"viewer": {"readers"}}}, Secrets: memorySecrets{"keys": keyRingFixture("active", nil)}, HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := NewBearerOIDC(browser)
	authenticator := NewRequestAuthenticator(DenyAuthenticator{}, bearer)
	token := signedBearerToken(t, key, issuer, "client", []string{"readers"})
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	actor, err := authenticator.Authenticate(request)
	if err != nil {
		t.Fatal(err)
	}
	if actor.Subject != "automation-1" || actor.Method != MethodBearer || len(actor.Roles) != 1 || actor.Roles[0] != RoleViewer || actor.SessionExpiresAt.IsZero() {
		t.Fatalf("actor=%#v", actor)
	}
	firstCalls := calls.Load()
	if _, err := authenticator.Authenticate(request); err != nil || calls.Load() != firstCalls {
		t.Fatalf("cached validation err=%v calls=%d/%d", err, calls.Load(), firstCalls)
	}
	ambiguous := request.Clone(request.Context())
	ambiguous.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "session"})
	if _, err := authenticator.Authenticate(ambiguous); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("ambiguity error=%v", err)
	}
	duplicate := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	duplicate.Header["Authorization"] = []string{"Bearer " + token, "Bearer " + token}
	if _, err := authenticator.Authenticate(duplicate); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("duplicate error=%v", err)
	}
	for _, value := range []string{"Basic abc", "Bearer", "Bearer  token", "Bearer abc,def", "Bearer " + strings.Repeat("a", maxBearerTokenBytes+1)} {
		bad := httptest.NewRequest(http.MethodGet, "/", nil)
		bad.Header.Set("Authorization", value)
		if _, err := authenticator.Authenticate(bad); !errors.Is(err, ErrInvalidAuthentication) {
			t.Errorf("header %q error=%v", value, err)
		}
	}
	unknownKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	unknown := signedBearerTokenWithKid(t, unknownKey, "unknown-key", issuer, "client", []string{"readers"})
	beforeUnknown := calls.Load()
	unknownRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	unknownRequest.Header.Set("Authorization", "Bearer "+unknown)
	if _, err := authenticator.Authenticate(unknownRequest); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("unknown key error=%v", err)
	}
	afterUnknown := calls.Load()
	if afterUnknown != beforeUnknown {
		t.Fatalf("unknown key bypassed outbound cooldown calls=%d/%d", afterUnknown, beforeUnknown)
	}
	if _, err := authenticator.Authenticate(unknownRequest); !errors.Is(err, ErrInvalidAuthentication) || calls.Load() != afterUnknown {
		t.Fatalf("unknown key cooldown err=%v calls=%d/%d", err, calls.Load(), afterUnknown)
	}
	tampered := token[:len(token)-1] + map[bool]string{true: "A", false: "B"}[token[len(token)-1] != 'A']
	tamperedRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	tamperedRequest.Header.Set("Authorization", "Bearer "+tampered)
	beforeTampered := calls.Load()
	if _, err := authenticator.Authenticate(tamperedRequest); !errors.Is(err, ErrInvalidAuthentication) || calls.Load() != beforeTampered {
		t.Fatalf("tampered known-kid amplification err=%v calls=%d/%d", err, calls.Load(), beforeTampered)
	}
	noRole := signedBearerToken(t, key, issuer, "client", []string{"unknown"})
	noRoleRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	noRoleRequest.Header.Set("Authorization", "Bearer "+noRole)
	if _, err := authenticator.Authenticate(noRoleRequest); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("no-role error=%v", err)
	}
	wrongAudience := signedBearerToken(t, key, issuer, "other", []string{"readers"})
	bad := httptest.NewRequest(http.MethodGet, "/", nil)
	bad.Header.Set("Authorization", "Bearer "+wrongAudience)
	if _, err := authenticator.Authenticate(bad); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("audience error=%v", err)
	}
}

func TestOIDCDiscoveryFailureHasRetryCooldown(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	browser, err := NewBrowserOIDC(BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: server.URL, EndpointOrigins: []string{server.URL}, ClientID: "client", SessionSecret: config.SecretKeyRef{Key: "keys"}, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}}, Secrets: memorySecrets{"keys": keyRingFixture("active", nil)}, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := browser.getProvider(context.Background()); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("error=%v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("discovery calls=%d, want 1", calls.Load())
	}
}

func TestBearerOIDCFailsClosedWhenProviderUnavailable(t *testing.T) {
	browser, err := NewBrowserOIDC(BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: "https://127.0.0.1:1", EndpointOrigins: []string{"https://127.0.0.1:1"}, ClientID: "client", SessionSecret: config.SecretKeyRef{Key: "keys"}, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}}, Secrets: memorySecrets{"keys": keyRingFixture("active", nil)}})
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := NewBearerOIDC(browser)
	key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	token := signedBearerToken(t, key, "https://127.0.0.1:1", "client", []string{"readers"})
	if _, err := bearer.ValidateBearerToken(context.Background(), token); !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("error=%v", err)
	}
}

func signedBearerToken(t *testing.T, key *rsa.PrivateKey, issuer, audience string, groups []string) string {
	return signedBearerTokenWithKid(t, key, "key-1", issuer, audience, groups)
}
func signedBearerTokenWithKid(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience string, groups []string) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claims := map[string]any{"iss": issuer, "sub": "automation-1", "aud": audience, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "groups": groups}
	raw, _ := json.Marshal(claims)
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}
