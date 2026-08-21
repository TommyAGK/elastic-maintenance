package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

const maxBearerTokenBytes = 16 << 10

// BearerOIDC validates JWT bearer access tokens against the same pinned OIDC
// issuer, audience, signing algorithms, and claim-to-role mapping as browser
// authentication.
type BearerOIDC struct{ oidc *BrowserOIDC }

func NewBearerOIDC(browser *BrowserOIDC) (*BearerOIDC, error) {
	if browser == nil {
		return nil, errors.New("OIDC service is required for bearer authentication")
	}
	return &BearerOIDC{oidc: browser}, nil
}

func (service *BearerOIDC) ValidateBearerToken(ctx context.Context, raw string) (Actor, error) {
	if service == nil || service.oidc == nil || len(raw) == 0 || len(raw) > maxBearerTokenBytes {
		return Actor{}, ErrInvalidAuthentication
	}
	if strictBearerStructure(raw) != nil {
		return Actor{}, ErrInvalidAuthentication
	}
	provider, err := service.oidc.getProvider(ctx)
	if err != nil {
		return Actor{}, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: service.oidc.config.ClientID, SupportedSigningAlgs: []string{oidc.RS256, oidc.ES256}})
	token, err := verifier.Verify(oidc.ClientContext(ctx, service.oidc.httpClient), raw)
	if err != nil {
		return Actor{}, ErrInvalidAuthentication
	}
	actor, err := service.oidc.actorFromToken(token, "", MethodBearer)
	if err != nil {
		return Actor{}, ErrInvalidAuthentication
	}
	actor.SessionExpiresAt = token.Expiry.UTC()
	return actor, nil
}

func strictBearerStructure(raw string) error {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" || len(parts[0]) > 1024 {
		return ErrInvalidAuthentication
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return ErrInvalidAuthentication
	}
	decoder := json.NewDecoder(strings.NewReader(string(decoded)))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInvalidAuthentication
	}
	seen := map[string]bool{}
	algorithm, keyID := "", ""
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return ErrInvalidAuthentication
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return ErrInvalidAuthentication
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return ErrInvalidAuthentication
		}
		if key == "alg" && json.Unmarshal(value, &algorithm) != nil {
			return ErrInvalidAuthentication
		}
		if key == "kid" && json.Unmarshal(value, &keyID) != nil {
			return ErrInvalidAuthentication
		}
	}
	if _, err := decoder.Token(); err != nil {
		return ErrInvalidAuthentication
	}
	if _, err := decoder.Token(); err != io.EOF || keyID == "" || len(keyID) > 256 || (algorithm != "RS256" && algorithm != "ES256") {
		return ErrInvalidAuthentication
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 {
		return ErrInvalidAuthentication
	}
	var claims map[string]json.RawMessage
	if json.Unmarshal(payload, &claims) != nil || claims == nil {
		return ErrInvalidAuthentication
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(signature) == 0 || len(signature) > 1024 {
		return ErrInvalidAuthentication
	}
	return nil
}

// RequestAuthenticator selects exactly one identity source. It never converts
// a browser session into a bearer credential or falls back after a presented
// credential fails validation.
type RequestAuthenticator struct {
	sessions Authenticator
	bearer   BearerTokenValidator
}

func NewRequestAuthenticator(sessions Authenticator, bearer BearerTokenValidator) Authenticator {
	return &RequestAuthenticator{sessions: sessions, bearer: bearer}
}

func (service *RequestAuthenticator) Authenticate(request *http.Request) (Actor, error) {
	if request == nil {
		return Actor{}, ErrAuthenticationRequired
	}
	authorizations := request.Header.Values("Authorization")
	hasSession := hasNamedCookie(request, SessionCookieName)
	if len(authorizations) > 1 || len(authorizations) != 0 && hasSession {
		return Actor{}, ErrAuthenticationConflict
	}
	if len(authorizations) == 1 {
		if service.bearer == nil {
			return Actor{}, ErrInvalidAuthentication
		}
		value := authorizations[0]
		scheme, token, ok := strings.Cut(value, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.TrimSpace(token) != token || strings.ContainsAny(token, " \t\r\n,") || len(token) > maxBearerTokenBytes {
			return Actor{}, ErrInvalidAuthentication
		}
		return service.bearer.ValidateBearerToken(request.Context(), token)
	}
	if service.sessions == nil {
		return Actor{}, ErrAuthenticationRequired
	}
	return service.sessions.Authenticate(request)
}
