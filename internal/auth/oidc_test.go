package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/go-jose/go-jose/v4"
)

type memorySecrets map[string][]byte

func (secrets memorySecrets) Read(_ context.Context, ref config.SecretKeyRef) ([]byte, error) {
	value, ok := secrets[ref.Key]
	if !ok {
		return nil, fmt.Errorf("missing")
	}
	return append([]byte{}, value...), nil
}

func TestProtectedCookiesRotateAndSeparatePurposes(t *testing.T) {
	ref := config.SecretKeyRef{Namespace: "ns", Name: "session", Key: "keys"}
	secrets := memorySecrets{"keys": keyRingFixture("one", nil)}
	source, err := newKeyRingSource(secrets, ref)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	codec := newCookieCodec(source, func() time.Time { return clock })
	encoded, err := codec.encode(context.Background(), "session", map[string]string{"subject": "operator"})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := codec.decode(context.Background(), "session", encoded, &decoded); err != nil || decoded["subject"] != "operator" {
		t.Fatalf("decode=%#v err=%v", decoded, err)
	}
	if codec.decode(context.Background(), "oidc-transaction", encoded, &decoded) == nil {
		t.Fatal("cookie purpose was interchangeable")
	}
	secrets["keys"] = keyRingFixture("two", []string{"one"})
	if err := codec.decode(context.Background(), "session", encoded, &decoded); err != nil {
		t.Fatalf("previous key rejected: %v", err)
	}
	secrets["keys"] = keyRingFixture("two", nil)
	if err := codec.decode(context.Background(), "session", encoded, &decoded); err == nil {
		t.Fatal("removed key remained valid")
	}
}

func TestBrowserOIDCLoginCallbackAndOfflineSession(t *testing.T) {
	clock := time.Now().UTC().Truncate(time.Second)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var calls atomic.Int64
	var expectedChallenge, expectedNonce string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/keys":
			json.NewEncoder(w).Encode(map[string]any{"keys": []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: "key-1", Algorithm: "RS256", Use: "sig"}}})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			challenge := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(challenge[:]) != expectedChallenge {
				t.Error("PKCE verifier mismatch")
			}
			signer, signErr := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privateKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "key-1"))
			if signErr != nil {
				t.Fatal(signErr)
			}
			claims := fmt.Sprintf(`{"iss":%q,"sub":"operator-1","aud":"client-1","exp":%d,"iat":%d,"nonce":%q,"name":"Operator","groups":["maintainers"]}`, issuer, clock.Add(time.Hour).Unix(), clock.Unix(), expectedNonce)
			signed, signErr := signer.Sign([]byte(claims))
			if signErr != nil {
				t.Fatal(signErr)
			}
			raw, signErr := signed.CompactSerialize()
			if signErr != nil {
				t.Fatal(signErr)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-token-sentinel", "token_type": "Bearer", "id_token": raw, "expires_in": 3600})
		default:
			http.NotFound(w, r)
		}
	}))
	issuer = provider.URL
	refClient := config.SecretKeyRef{Namespace: "ns", Name: "oidc", Key: "client"}
	refSession := config.SecretKeyRef{Namespace: "ns", Name: "session", Key: "keys"}
	secrets := memorySecrets{"client": []byte("client-secret-sentinel"), "keys": keyRingFixture("active", nil)}
	var audited Actor
	service, err := NewBrowserOIDC(BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: issuer, ClientID: "client-1", ClientSecret: refClient, SessionSecret: refSession, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid", "profile"}, EndpointOrigins: []string{issuer}, SubjectClaim: "sub", DisplayNameClaim: "name"}, Authorization: config.AuthorizationConfig{RoleClaim: "groups", RoleMapping: map[string][]string{"administrator": {"maintainers"}}}, Secrets: secrets, HTTPClient: provider.Client(), Now: func() time.Time { return clock }, Audit: func(_ context.Context, actor Actor) error { audited = actor; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("constructor contacted the IdP")
	}
	loginRequest := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/login", nil)
	loginResponse := httptest.NewRecorder()
	if err := service.BeginLogin(loginResponse, loginRequest); err != nil {
		t.Fatal(err)
	}
	if loginResponse.Code != http.StatusFound {
		t.Fatalf("login status=%d body=%s", loginResponse.Code, loginResponse.Body.String())
	}
	location, err := url.Parse(loginResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	expectedChallenge = location.Query().Get("code_challenge")
	expectedNonce = location.Query().Get("nonce")
	state := location.Query().Get("state")
	if expectedChallenge == "" || expectedNonce == "" || state == "" || location.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL=%s", location.String())
	}
	transaction := cookieByName(t, loginResponse.Result().Cookies(), TransactionCookieName)
	if !transaction.Secure || !transaction.HttpOnly || transaction.SameSite != http.SameSiteLaxMode || transaction.Path != "/" {
		t.Fatalf("transaction cookie attributes = %#v", transaction)
	}
	aliasRequest := httptest.NewRequest(http.MethodGet, "https://alias.example.test/auth/callback?code=valid-code&state="+url.QueryEscape(state), nil)
	aliasRequest.AddCookie(transaction)
	if err := service.CompleteCallback(httptest.NewRecorder(), aliasRequest); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("alias callback error=%v", err)
	}
	callbackRequest := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/callback?code=valid-code&state="+url.QueryEscape(state), nil)
	callbackRequest.AddCookie(transaction)
	callbackResponse := httptest.NewRecorder()
	if err := service.CompleteCallback(callbackResponse, callbackRequest); err != nil {
		t.Fatalf("callback error=%v providerCalls=%d", err, calls.Load())
	}
	if callbackResponse.Code != http.StatusSeeOther || callbackResponse.Header().Get("Location") != "/" {
		t.Fatalf("callback status=%d headers=%#v body=%s", callbackResponse.Code, callbackResponse.Header(), callbackResponse.Body.String())
	}
	session := cookieByName(t, callbackResponse.Result().Cookies(), SessionCookieName)
	if !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" {
		t.Fatalf("session cookie attributes = %#v", session)
	}
	if strings.Contains(session.Value, "access-token-sentinel") || strings.Contains(session.Value, "client-secret-sentinel") {
		t.Fatal("session cookie exposed tokens")
	}
	provider.Close()
	callsBefore := calls.Load()
	authenticated := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	authenticated.AddCookie(session)
	actor, err := service.Authenticate(authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if audited.Subject != "operator-1" || audited.Method != MethodOIDC {
		t.Fatalf("audited actor=%#v", audited)
	}
	if actor.Subject != "operator-1" || actor.DisplayName != "Operator" || actor.Method != MethodOIDC || len(actor.Roles) != 1 || actor.Roles[0] != RoleAdministrator {
		t.Fatalf("actor=%#v", actor)
	}
	if calls.Load() != callsBefore {
		t.Fatal("session authentication contacted unavailable IdP")
	}
	badLogout := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/logout", nil)
	badLogout.Header.Set("Origin", "https://app.example.test/path")
	if err := service.Logout(httptest.NewRecorder(), badLogout); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("malformed origin error=%v", err)
	}
	logoutRequest := httptest.NewRequest(http.MethodPost, "https://app.example.test/auth/logout", nil)
	logoutRequest.Header.Set("Origin", "HTTPS://app.example.test:443")
	logoutResponse := httptest.NewRecorder()
	if err := service.Logout(logoutResponse, logoutRequest); err != nil || logoutResponse.Code != http.StatusNoContent {
		t.Fatalf("logout status=%d error=%v", logoutResponse.Code, err)
	}
	cleared := false
	for _, cookie := range logoutResponse.Result().Cookies() {
		if cookie.Name == SessionCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("logout did not clear session cookie")
	}
}

func TestBrowserOIDCRejectsStateMismatchAndBearerAmbiguity(t *testing.T) {
	ref := config.SecretKeyRef{Namespace: "ns", Name: "session", Key: "keys"}
	secrets := memorySecrets{"keys": keyRingFixture("active", nil), "client": []byte("secret")}
	clock := time.Now().UTC()
	source, _ := newKeyRingSource(secrets, ref)
	codec := newCookieCodec(source, func() time.Time { return clock })
	transaction, _ := codec.encode(context.Background(), "oidc-transaction", transactionPayload{Version: "v1", State: "expected", Nonce: "nonce", Verifier: "verifier", IssuedAt: clock.Unix(), ExpiresAt: clock.Add(time.Minute).Unix()})
	service := &BrowserOIDC{config: config.OIDCConfig{ClientSecret: config.SecretKeyRef{Key: "client"}, RedirectURL: "https://app.example.test/auth/callback"}, secrets: secrets, cookies: codec, now: func() time.Time { return clock }}
	request := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/callback?code=code&state=wrong", nil)
	request.AddCookie(&http.Cookie{Name: TransactionCookieName, Value: transaction})
	if err := service.CompleteCallback(httptest.NewRecorder(), request); !errors.Is(err, ErrInvalidAuthentication) {
		t.Fatalf("error=%v", err)
	}
	duplicateSessionValue, _ := codec.encode(context.Background(), "session", sessionPayload{Version: "v1", Actor: Actor{Subject: "operator", Roles: []Role{RoleViewer}, Method: MethodOIDC}, Method: MethodOIDC, IssuedAt: clock.Unix(), ExpiresAt: clock.Add(time.Minute).Unix()})
	duplicateSession := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	duplicateSession.AddCookie(&http.Cookie{Name: SessionCookieName, Value: duplicateSessionValue})
	duplicateSession.AddCookie(&http.Cookie{Name: SessionCookieName, Value: duplicateSessionValue})
	if _, err := service.Authenticate(duplicateSession); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("duplicate session error=%v", err)
	}
	request = httptest.NewRequest(http.MethodGet, "https://app.example.test/api/v1/session", nil)
	request.Header["Authorization"] = []string{"", "Bearer ambiguous"}
	if _, err := service.Authenticate(request); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("error=%v", err)
	}
	duplicateTransaction := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/callback?code=code&state=expected", nil)
	duplicateTransaction.AddCookie(&http.Cookie{Name: TransactionCookieName, Value: transaction})
	duplicateTransaction.AddCookie(&http.Cookie{Name: TransactionCookieName, Value: transaction})
	if err := service.CompleteCallback(httptest.NewRecorder(), duplicateTransaction); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("duplicate transaction error=%v", err)
	}
	login := httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/login", nil)
	login.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "one"})
	login.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "two"})
	if err := service.BeginLogin(httptest.NewRecorder(), login); !errors.Is(err, ErrAuthenticationConflict) {
		t.Fatalf("duplicate session login error=%v", err)
	}
}

func TestOIDCDiscoveryRejectsUnpinnedEndpointOrigin(t *testing.T) {
	var issuer string
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": "http://169.254.169.254/token", "jwks_uri": issuer + "/keys", "response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"}, "id_token_signing_alg_values_supported": []string{"RS256"}})
	}))
	defer provider.Close()
	issuer = provider.URL
	secrets := memorySecrets{"keys": keyRingFixture("active", nil)}
	service, err := NewBrowserOIDC(BrowserOIDCOptions{OIDC: config.OIDCConfig{Enabled: true, IssuerURL: issuer, ClientID: "client", SessionSecret: config.SecretKeyRef{Key: "keys"}, RedirectURL: "https://app.example.test/auth/callback", Scopes: []string{"openid"}, EndpointOrigins: []string{issuer}}, Authorization: config.AuthorizationConfig{}, Secrets: secrets, HTTPClient: provider.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.BeginLogin(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://app.example.test/auth/login", nil)); !errors.Is(err, ErrOIDCUnavailable) {
		t.Fatalf("error=%v", err)
	}
}
func TestSuppliedOIDCHTTPClientIsWrappedWithRedirectAndBodyBounds(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusFound)
			return
		}
		w.Write([]byte(strings.Repeat("x", int(maxOIDCHTTPBodyBytes)+1)))
	}))
	defer server.Close()
	client := secureOIDCHTTPClient(&http.Client{Transport: http.DefaultTransport, CheckRedirect: func(*http.Request, []*http.Request) error { return nil }})
	if _, err := client.Get(server.URL + "/redirect"); err == nil {
		t.Fatal("redirect was accepted")
	}
	response, err := client.Get(server.URL + "/large")
	if err != nil {
		return
	}
	defer response.Body.Close()
	if _, err = io.ReadAll(response.Body); err == nil {
		t.Fatal("oversized response was accepted")
	}
}

func keyRingFixture(current string, previous []string) []byte {
	key := func(id string) string {
		sum := sha256.Sum256([]byte("key:" + id))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}
	var builder strings.Builder
	builder.WriteString(keyRingHeader + "\ncurrent " + current + " " + key(current))
	for _, id := range previous {
		builder.WriteString("\nprevious " + id + " " + key(id))
	}
	builder.WriteByte('\n')
	return []byte(builder.String())
}
func cookieByName(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, item := range cookies {
		if item.Name == name && item.Value != "" {
			return item
		}
	}
	t.Fatalf("cookie %s not found in %#v", name, cookies)
	return nil
}
