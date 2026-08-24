package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/credentials"
)

func credentialStatusHandler(backend CredentialBackend, targetID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		status, err := backend.Status(r.Context(), targetID)
		if err != nil {
			writeCredentialError(w, r, err)
			return
		}
		writeCredentialStatus(w, r, targetID, status)
	})
}

type credentialOriginConfig interface {
	OriginConfig(context.Context) (string, []string, error)
}

func liveCredentialOrigin(ctx context.Context, backend CredentialBackend, publicURL string, trusted []string) (string, []string, bool) {
	source, ok := backend.(credentialOriginConfig)
	if !ok {
		return publicURL, trusted, publicURL != ""
	}
	livePublic, liveTrusted, err := source.OriginConfig(ctx)
	return livePublic, liveTrusted, err == nil && livePublic != ""
}

func credentialPutHandler(backend CredentialBackend, targetID, publicURL string, trusted []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodPut) {
			return
		}
		if !credentialJSON(r) {
			api.WriteError(w, r, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json", RequestID(r.Context()))
			return
		}
		livePublic, liveTrusted, originReady := liveCredentialOrigin(r.Context(), backend, publicURL, trusted)
		if !originReady || !validCredentialMutationOrigin(r, livePublic, liveTrusted) {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_origin", "credential mutation origin is invalid", RequestID(r.Context()))
			return
		}
		key, err := api.IdempotencyKey(r)
		if err != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "a valid Idempotency-Key header is required", RequestID(r.Context()))
			return
		}
		var body api.CredentialPutRequest
		if err := api.DecodeStrictJSON(r.Body, &body); err != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", RequestID(r.Context()))
			return
		}
		actor, ok := auth.ActorFromContext(r.Context())
		if !ok {
			api.WriteError(w, r, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(r.Context()))
			return
		}
		status, err := backend.Put(r.Context(), targetID, key, actor, credentials.PutRequest{APIKey: body.APIKey, CACertificatePEM: body.CACertificatePEM})
		if err != nil {
			writeCredentialError(w, r, err)
			return
		}
		if status.Created {
			setCredentialAuditAction(w, audit.ActionCredentialUpload)
		} else {
			setCredentialAuditAction(w, audit.ActionCredentialRotate)
		}
		writeCredentialStatus(w, r, targetID, status)
	})
}
func credentialDeleteHandler(backend CredentialBackend, targetID, publicURL string, trusted []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodDelete) {
			return
		}
		if !credentialJSON(r) {
			api.WriteError(w, r, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json", RequestID(r.Context()))
			return
		}
		livePublic, liveTrusted, originReady := liveCredentialOrigin(r.Context(), backend, publicURL, trusted)
		if !originReady || !validCredentialMutationOrigin(r, livePublic, liveTrusted) {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_origin", "credential mutation origin is invalid", RequestID(r.Context()))
			return
		}
		key, err := api.IdempotencyKey(r)
		if err != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "a valid Idempotency-Key header is required", RequestID(r.Context()))
			return
		}
		var body api.ConfirmedMutationRequest
		if err := api.DecodeStrictJSON(r.Body, &body); err != nil || !body.Confirm {
			api.WriteError(w, r, http.StatusBadRequest, "confirmation_required", "credential deletion requires explicit confirmation", RequestID(r.Context()))
			return
		}
		actor, ok := auth.ActorFromContext(r.Context())
		if !ok {
			api.WriteError(w, r, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(r.Context()))
			return
		}
		status, err := backend.Delete(r.Context(), targetID, key, actor)
		if err != nil {
			writeCredentialError(w, r, err)
			return
		}
		writeCredentialStatus(w, r, targetID, status)
	})
}
func setCredentialAuditAction(w http.ResponseWriter, action audit.Action) {
	for {
		if tracked, ok := w.(*statusWriter); ok {
			tracked.auditAction = action
			return
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = unwrapper.Unwrap()
	}
}
func credentialJSON(r *http.Request) bool {
	value, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && value == "application/json"
}
func writeCredentialStatus(w http.ResponseWriter, r *http.Request, targetID string, status credentials.Status) {
	value := api.CredentialStatus{Configured: status.Configured, SecretResourceVersion: status.SecretResourceVersion, RotatedBy: status.RotatedBy, CertificateSHA256: status.CertificateSHA256}
	if !status.RotatedAt.IsZero() {
		value.RotatedAt = &status.RotatedAt
	}
	if !status.CertificateNotAfter.IsZero() {
		value.CertificateNotAfter = &status.CertificateNotAfter
	}
	api.WriteJSON(w, r, http.StatusOK, api.CredentialStatusResponse{APIVersion: api.Version, TargetID: targetID, CredentialStatus: value})
}
func writeCredentialError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, credentials.ErrTargetNotFound):
		api.WriteError(w, r, http.StatusNotFound, "target_not_found", "target was not found", RequestID(r.Context()))
	case errors.Is(err, credentials.ErrInvalidCredential):
		api.WriteError(w, r, http.StatusUnprocessableEntity, "invalid_credential", "credential material is invalid", RequestID(r.Context()))
	case errors.Is(err, credentials.ErrPermissionDenied):
		api.WriteError(w, r, http.StatusForbidden, "permission_denied", "permission denied", RequestID(r.Context()))
	case errors.Is(err, credentials.ErrIdempotencyConflict), errors.Is(err, credentials.ErrConflict), errors.Is(err, credentials.ErrInUse):
		api.WriteError(w, r, http.StatusConflict, "credential_conflict", "credential operation conflicted", RequestID(r.Context()))
	default:
		api.WriteError(w, r, http.StatusServiceUnavailable, "credential_service_unavailable", "credential service is unavailable", RequestID(r.Context()))
	}
}
func validCredentialMutationOrigin(r *http.Request, publicURL string, trusted []string) bool {
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		return false
	}
	if publicURL == "" {
		return false
	}
	expected, err := url.Parse(publicURL)
	if err != nil || expected == nil {
		return false
	}
	expectedScheme := strings.ToLower(expected.Scheme)
	loopback := strings.EqualFold(expected.Hostname(), "localhost")
	if ip := net.ParseIP(expected.Hostname()); ip != nil && ip.IsLoopback() {
		loopback = true
	}
	port := expected.Port()
	if expected.Hostname() == "" || strings.HasSuffix(expected.Host, ":") {
		return false
	}
	if port != "" {
		number, parseErr := strconv.Atoi(port)
		if parseErr != nil || number < 1 || number > 65535 {
			return false
		}
	}
	if expected.Host == "" || expected.User != nil || (expected.Path != "" && expected.Path != "/") || expected.RawQuery != "" || expected.Fragment != "" || (expectedScheme != "https" && !(expectedScheme == "http" && loopback)) {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if requestFromTrustedNetworks(r, trusted) {
		proto := r.Header.Values("X-Forwarded-Proto")
		forwardedHost := r.Header.Values("X-Forwarded-Host")
		if len(proto) != 1 || len(forwardedHost) != 1 || strings.Contains(proto[0], ",") || strings.Contains(forwardedHost[0], ",") {
			return false
		}
		scheme = strings.ToLower(strings.TrimSpace(proto[0]))
		host = strings.TrimSpace(forwardedHost[0])
	} else if len(r.Header.Values("X-Forwarded-Proto")) != 0 || len(r.Header.Values("X-Forwarded-Host")) != 0 {
		return false
	}
	if !sameServerOrigin(&url.URL{Scheme: scheme, Host: host}, expected) {
		return false
	}
	actor, _ := auth.ActorFromContext(r.Context())
	if actor.Method == auth.MethodBearer {
		return len(r.Header.Values("Origin")) == 0
	}
	tokens := r.Header.Values(api.CSRFTokenHeader)
	if actor.CSRFToken == "" || len(tokens) != 1 || len(tokens[0]) != len(actor.CSRFToken) || subtle.ConstantTimeCompare([]byte(tokens[0]), []byte(actor.CSRFToken)) != 1 {
		return false
	}
	origins := r.Header.Values("Origin")
	if len(origins) != 1 {
		return false
	}
	origin, err := url.Parse(origins[0])
	return err == nil && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == "" && sameServerOrigin(origin, expected)
}
func requestFromTrustedNetworks(r *http.Request, values []string) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
func sameServerOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && canonicalServerHost(left) == canonicalServerHost(right)
}
func canonicalServerHost(value *url.URL) string {
	host := strings.ToLower(value.Hostname())
	port := value.Port()
	scheme := strings.ToLower(value.Scheme)
	if scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		port = ""
	}
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	return host
}
