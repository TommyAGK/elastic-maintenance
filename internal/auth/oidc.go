package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/secretmount"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	OIDCTransactionLifetime       = 10 * time.Minute
	OIDCSessionLifetime           = 8 * time.Hour
	providerCacheLifetime         = 15 * time.Minute
	maxOIDCHTTPBodyBytes    int64 = 1 << 20
	maxCallbackURIBytes           = 16 << 10
)

var (
	ErrOIDCDisabled           = errors.New("OIDC authentication is disabled")
	ErrOIDCUnavailable        = errors.New("OIDC provider is unavailable")
	ErrAuthenticationConflict = errors.New("multiple authentication identities are not allowed")
)

type OIDCAuditFunc func(context.Context, Actor) error

type BrowserOIDCOptions struct {
	OIDC           config.OIDCConfig
	Authorization  config.AuthorizationConfig
	Secrets        secretmount.Reader
	HTTPClient     *http.Client
	Now            func() time.Time
	TrustedProxies []string
	Audit          OIDCAuditFunc
}

type BrowserOIDC struct {
	config             config.OIDCConfig
	authorization      config.AuthorizationConfig
	secrets            secretmount.Reader
	cookies            *cookieCodec
	httpClient         *http.Client
	now                func() time.Time
	trustedProxies     []*net.IPNet
	providerMu         sync.Mutex
	provider           *oidc.Provider
	providerExpires    time.Time
	providerRetryAfter time.Time
	audit              OIDCAuditFunc
}

func NewBrowserOIDC(options BrowserOIDCOptions) (*BrowserOIDC, error) {
	if !options.OIDC.Enabled {
		return nil, ErrOIDCDisabled
	}
	if options.Secrets == nil {
		return nil, errors.New("OIDC secret reader is required")
	}
	if len(options.OIDC.EndpointOrigins) == 0 {
		return nil, errors.New("OIDC endpoint origins are required")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	keys, err := newKeyRingSource(options.Secrets, options.OIDC.SessionSecret)
	if err != nil {
		return nil, err
	}
	client := secureOIDCHTTPClient(options.HTTPClient)
	trusted := make([]*net.IPNet, 0, len(options.TrustedProxies))
	for _, value := range options.TrustedProxies {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, errors.New("trusted proxy configuration is invalid")
		}
		trusted = append(trusted, network)
	}
	return &BrowserOIDC{config: options.OIDC, authorization: options.Authorization, secrets: options.Secrets, cookies: newCookieCodec(keys, now), httpClient: client, now: now, trustedProxies: trusted, audit: options.Audit}, nil
}

func (service *BrowserOIDC) Authenticate(request *http.Request) (Actor, error) {
	if len(request.Header.Values("Authorization")) != 0 {
		return Actor{}, ErrAuthenticationConflict
	}
	encoded, err := readUniqueCookie(request, SessionCookieName)
	if errors.Is(err, ErrAuthenticationConflict) {
		return Actor{}, err
	}
	if err != nil {
		return Actor{}, ErrAuthenticationRequired
	}
	var payload sessionPayload
	if err := service.cookies.decode(request.Context(), "session", encoded, &payload); err != nil {
		return Actor{}, ErrInvalidAuthentication
	}
	now := service.now().UTC()
	if payload.Version != "v1" || !validAbsoluteTimes(now, payload.IssuedAt, payload.ExpiresAt, OIDCSessionLifetime) {
		return Actor{}, ErrSessionExpired
	}
	payload.Actor.Method = payload.Method
	actor, err := payload.Actor.Normalized()
	actor.CSRFToken = payload.CSRFToken
	actor.SessionExpiresAt = time.Unix(payload.ExpiresAt, 0).UTC()
	if err != nil || actor.Method != MethodOIDC {
		return Actor{}, ErrInvalidAuthentication
	}
	return actor, nil
}

func (service *BrowserOIDC) BeginLogin(w http.ResponseWriter, request *http.Request) error {
	if len(request.Header.Values("Authorization")) != 0 {
		return ErrAuthenticationConflict
	}
	if request.Method != http.MethodGet {
		return errors.New("method not allowed")
	}
	if hasNamedCookie(request, SessionCookieName) {
		return ErrAuthenticationConflict
	}
	provider, err := service.getProvider(request.Context())
	if err != nil {
		return err
	}
	state, err := randomURLValue(32)
	if err != nil {
		return err
	}
	nonce, err := randomURLValue(32)
	if err != nil {
		return err
	}
	verifier, err := randomURLValue(32)
	if err != nil {
		return err
	}
	now := service.now().UTC()
	transaction := transactionPayload{Version: "v1", State: state, Nonce: nonce, Verifier: verifier, IssuedAt: now.Unix(), ExpiresAt: now.Add(OIDCTransactionLifetime).Unix()}
	encoded, err := service.cookies.encode(request.Context(), "oidc-transaction", transaction)
	if err != nil {
		return err
	}
	setProtectedCookie(w, TransactionCookieName, encoded, now.Add(OIDCTransactionLifetime))
	challenge := sha256.Sum256([]byte(verifier))
	oauthConfig := service.oauthConfig(provider, "")
	location := oauthConfig.AuthCodeURL(state, oauth2.AccessTypeOnline, oauth2.SetAuthURLParam("nonce", nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	http.Redirect(w, request, location, http.StatusFound)
	return nil
}

func (service *BrowserOIDC) CompleteCallback(w http.ResponseWriter, request *http.Request) error {
	if len(request.Header.Values("Authorization")) != 0 {
		return ErrAuthenticationConflict
	}
	if hasNamedCookie(request, SessionCookieName) {
		return ErrAuthenticationConflict
	}
	if request.Method != http.MethodGet || len(request.RequestURI) > maxCallbackURIBytes || !service.validCallbackRequest(request) {
		return ErrInvalidAuthentication
	}
	if request.URL.Query().Get("error") != "" {
		if rejectUnexpectedQuery(request, "error", "error_description", "error_uri", "state") != nil {
			return ErrInvalidAuthentication
		}
		return ErrInvalidAuthentication
	}
	if err := rejectUnexpectedQuery(request, "code", "state"); err != nil {
		return ErrInvalidAuthentication
	}
	state, err := parseSingleQuery(request, "state")
	if err != nil {
		return ErrInvalidAuthentication
	}
	code, err := parseSingleQuery(request, "code")
	if err != nil {
		return ErrInvalidAuthentication
	}
	encoded, err := readUniqueCookie(request, TransactionCookieName)
	if errors.Is(err, ErrAuthenticationConflict) {
		return err
	}
	if err != nil {
		return ErrInvalidAuthentication
	}
	var transaction transactionPayload
	if err := service.cookies.decode(request.Context(), "oidc-transaction", encoded, &transaction); err != nil {
		return ErrInvalidAuthentication
	}
	now := service.now().UTC()
	if transaction.Version != "v1" || !validAbsoluteTimes(now, transaction.IssuedAt, transaction.ExpiresAt, OIDCTransactionLifetime) || !constantTimeEqual(state, transaction.State) {
		return ErrInvalidAuthentication
	}
	clearProtectedCookie(w, TransactionCookieName)
	provider, err := service.getProvider(request.Context())
	if err != nil {
		return err
	}
	secret, err := service.secrets.Read(request.Context(), service.config.ClientSecret)
	if err != nil || len(secret) == 0 || len(secret) > 4096 {
		return ErrOIDCUnavailable
	}
	clientContext := oidc.ClientContext(request.Context(), service.httpClient)
	token, err := service.oauthConfig(provider, string(secret)).Exchange(clientContext, code, oauth2.SetAuthURLParam("code_verifier", transaction.Verifier))
	clear(secret)
	if err != nil {
		return ErrInvalidAuthentication
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return ErrInvalidAuthentication
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: service.config.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}})
	idToken, err := verifier.Verify(clientContext, rawIDToken)
	if err != nil {
		return ErrInvalidAuthentication
	}
	actor, err := service.actorFromToken(idToken, transaction.Nonce, MethodOIDC)
	if err != nil {
		return ErrInvalidAuthentication
	}
	expires := now.Add(OIDCSessionLifetime)
	if idToken.Expiry.Before(expires) {
		expires = idToken.Expiry
	}
	if !expires.After(now) {
		return ErrInvalidAuthentication
	}
	csrf, err := randomURLValue(32)
	if err != nil {
		return err
	}
	payload := sessionPayload{Version: "v1", Actor: actor, Method: actor.Method, CSRFToken: csrf, IssuedAt: now.Unix(), ExpiresAt: expires.Unix()}
	session, err := service.cookies.encode(request.Context(), "session", payload)
	if err != nil {
		return err
	}
	if service.audit != nil {
		if err := service.audit(request.Context(), actor); err != nil {
			return ErrOIDCUnavailable
		}
	}
	setProtectedCookie(w, SessionCookieName, session, expires)
	http.Redirect(w, request, "/", http.StatusSeeOther)
	return nil
}

func (service *BrowserOIDC) Logout(w http.ResponseWriter, request *http.Request) error {
	if request.Method != http.MethodPost {
		return errors.New("method not allowed")
	}
	origins := request.Header.Values("Origin")
	if len(origins) != 1 {
		return ErrInvalidAuthentication
	}
	origin, err := url.Parse(origins[0])
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return ErrInvalidAuthentication
	}
	publicURL, err := url.Parse(service.config.RedirectURL)
	if err != nil || !sameWebOrigin(origin, publicURL) {
		return ErrInvalidAuthentication
	}
	if request.ContentLength > 0 {
		return ErrInvalidAuthentication
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 1))
	if err != nil || len(body) != 0 {
		return ErrInvalidAuthentication
	}
	clearProtectedCookie(w, SessionCookieName)
	clearProtectedCookie(w, TransactionCookieName)
	w.WriteHeader(http.StatusNoContent)
	return nil
}

func (service *BrowserOIDC) getProvider(ctx context.Context) (*oidc.Provider, error) {
	service.providerMu.Lock()
	defer service.providerMu.Unlock()
	now := service.now().UTC()
	if service.provider != nil && now.Before(service.providerExpires) {
		return service.provider, nil
	}
	if now.Before(service.providerRetryAfter) {
		return nil, ErrOIDCUnavailable
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, service.httpClient), service.config.IssuerURL)
	if err != nil {
		service.providerRetryAfter = service.now().UTC().Add(5 * time.Second)
		return nil, ErrOIDCUnavailable
	}
	var metadata struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil || metadata.Issuer != service.config.IssuerURL || !service.validProviderEndpoint(metadata.AuthorizationEndpoint) || !service.validProviderEndpoint(metadata.TokenEndpoint) || !service.validProviderEndpoint(metadata.JWKSURI) {
		service.providerRetryAfter = service.now().UTC().Add(5 * time.Second)
		return nil, ErrOIDCUnavailable
	}
	service.providerRetryAfter = time.Time{}
	service.provider = provider
	service.providerExpires = now.Add(providerCacheLifetime)
	return provider, nil
}
func (service *BrowserOIDC) oauthConfig(provider *oidc.Provider, secret string) *oauth2.Config {
	return &oauth2.Config{ClientID: service.config.ClientID, ClientSecret: secret, Endpoint: provider.Endpoint(), RedirectURL: service.config.RedirectURL, Scopes: append([]string{}, service.config.Scopes...)}
}

func (service *BrowserOIDC) actorFromToken(token *oidc.IDToken, expectedNonce string, method Method) (Actor, error) {
	var claims map[string]json.RawMessage
	if err := token.Claims(&claims); err != nil {
		return Actor{}, err
	}
	if expectedNonce != "" && !claimStringEquals(claims, "nonce", expectedNonce) {
		return Actor{}, ErrInvalidAuthentication
	}
	if len(token.Audience) > 1 && !claimStringEquals(claims, "azp", service.config.ClientID) {
		return Actor{}, ErrInvalidAuthentication
	}
	if azp, ok := claimString(claims, "azp"); ok && azp != service.config.ClientID {
		return Actor{}, ErrInvalidAuthentication
	}
	subjectClaim := service.config.SubjectClaim
	if subjectClaim == "" {
		subjectClaim = "sub"
	}
	subject, ok := claimString(claims, subjectClaim)
	if !ok || len(subject) > 256 {
		return Actor{}, ErrInvalidAuthentication
	}
	display := ""
	if service.config.DisplayNameClaim != "" {
		display, _ = claimString(claims, service.config.DisplayNameClaim)
		if len(display) > 256 {
			return Actor{}, ErrInvalidAuthentication
		}
	}
	roleValues, err := claimStrings(claims, service.authorization.RoleClaim)
	if err != nil {
		return Actor{}, err
	}
	roles := make([]Role, 0)
	for roleName, matches := range service.authorization.RoleMapping {
		for _, match := range matches {
			if contains(roleValues, match) {
				roles = append(roles, Role(roleName))
				break
			}
		}
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i] < roles[j] })
	if len(roles) == 0 {
		return Actor{}, ErrPermissionDenied
	}
	return Actor{Subject: subject, DisplayName: display, Roles: roles, Method: method}.Normalized()
}
func claimString(claims map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := claims[name]
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" {
		return "", false
	}
	return value, true
}
func claimStringEquals(claims map[string]json.RawMessage, name, expected string) bool {
	value, ok := claimString(claims, name)
	return ok && constantTimeEqual(value, expected)
}
func claimStrings(claims map[string]json.RawMessage, name string) ([]string, error) {
	raw, ok := claims[name]
	if !ok {
		return nil, ErrPermissionDenied
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" || len(one) > 256 {
			return nil, ErrPermissionDenied
		}
		return []string{one}, nil
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil || len(many) == 0 || len(many) > 100 {
		return nil, ErrPermissionDenied
	}
	seen := map[string]bool{}
	for _, item := range many {
		if item == "" || len(item) > 256 || seen[item] {
			return nil, ErrPermissionDenied
		}
		seen[item] = true
	}
	return many, nil
}
func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func (service *BrowserOIDC) validProviderEndpoint(raw string) bool {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.User != nil || endpoint.Fragment != "" || endpoint.Host == "" {
		return false
	}
	issuer, err := url.Parse(service.config.IssuerURL)
	if err != nil {
		return false
	}
	if endpoint.Scheme != "https" && !(endpoint.Scheme == "http" && isLoopbackHost(issuer.Hostname()) && isLoopbackHost(endpoint.Hostname())) {
		return false
	}
	allowed := service.config.EndpointOrigins
	if len(allowed) == 0 {
		return false
	}
	for _, rawOrigin := range allowed {
		origin, parseErr := url.Parse(rawOrigin)
		if parseErr == nil && sameWebOrigin(endpoint, origin) {
			return true
		}
	}
	return false
}
func (service *BrowserOIDC) validCallbackRequest(request *http.Request) bool {
	expected, err := url.Parse(service.config.RedirectURL)
	if err != nil || request.URL.Path != expected.Path || (request.URL.RawPath != "" && request.URL.RawPath != expected.EscapedPath()) {
		return false
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	host := request.Host
	if service.requestFromTrustedProxy(request) {
		if values := request.Header.Values("X-Forwarded-Proto"); len(values) == 1 && !strings.Contains(values[0], ",") {
			scheme = strings.ToLower(strings.TrimSpace(values[0]))
		} else if len(values) != 0 {
			return false
		}
		if values := request.Header.Values("X-Forwarded-Host"); len(values) == 1 && !strings.Contains(values[0], ",") {
			host = strings.TrimSpace(values[0])
		} else if len(values) != 0 {
			return false
		}
	}
	actual := &url.URL{Scheme: scheme, Host: host}
	return sameWebOrigin(actual, expected)
}
func (service *BrowserOIDC) requestFromTrustedProxy(request *http.Request) bool {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		host = request.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range service.trustedProxies {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func sameWebOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && canonicalWebHost(left) == canonicalWebHost(right)
}
func canonicalWebHost(value *url.URL) string {
	host := strings.ToLower(value.Hostname())
	port := value.Port()
	scheme := strings.ToLower(value.Scheme)
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		return net.JoinHostPort(strings.Trim(host, "[]"), port)
	}
	return host
}

func newOIDCHTTPClient() *http.Client { return secureOIDCHTTPClient(nil) }
func secureOIDCHTTPClient(input *http.Client) *http.Client {
	transport := http.DefaultTransport
	if input != nil && input.Transport != nil {
		transport = input.Transport
	}
	return &http.Client{Transport: &boundedRoundTripper{base: transport, limit: maxOIDCHTTPBodyBytes}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("OIDC redirects are not allowed") }}
}

type outboundGETState struct {
	inFlight   bool
	retryAfter time.Time
}
type boundedRoundTripper struct {
	base  http.RoundTripper
	limit int64
	mu    sync.Mutex
	gets  map[string]outboundGETState
}

func (transport *boundedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	key := ""
	if request.Method == http.MethodGet {
		key = request.URL.String()
		now := time.Now()
		transport.mu.Lock()
		if transport.gets == nil {
			transport.gets = map[string]outboundGETState{}
		}
		state := transport.gets[key]
		if state.inFlight || now.Before(state.retryAfter) {
			transport.mu.Unlock()
			return nil, errors.New("OIDC upstream GET is rate limited")
		}
		state.inFlight = true
		transport.gets[key] = state
		transport.mu.Unlock()
		defer func() {
			transport.mu.Lock()
			state := transport.gets[key]
			state.inFlight = false
			state.retryAfter = time.Now().Add(5 * time.Second)
			transport.gets[key] = state
			transport.mu.Unlock()
		}()
	}
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > transport.limit {
		response.Body.Close()
		return nil, errors.New("OIDC response exceeds limit")
	}
	response.Body = &limitReadCloser{reader: response.Body, closer: response.Body, remaining: transport.limit}
	return response, nil
}

type limitReadCloser struct {
	reader    io.Reader
	closer    io.Closer
	remaining int64
}

func (reader *limitReadCloser) Read(buffer []byte) (int, error) {
	if reader.remaining <= 0 {
		return 0, errors.New("OIDC response exceeds limit")
	}
	if int64(len(buffer)) > reader.remaining+1 {
		buffer = buffer[:reader.remaining+1]
	}
	count, err := reader.reader.Read(buffer)
	reader.remaining -= int64(count)
	if reader.remaining < 0 {
		return count, errors.New("OIDC response exceeds limit")
	}
	return count, err
}
func (reader *limitReadCloser) Close() error { return reader.closer.Close() }
