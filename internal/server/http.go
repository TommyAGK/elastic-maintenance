package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/secretmount"
	"github.com/TommyAGK/elastic-maintenance/internal/validation"
	webui "github.com/TommyAGK/elastic-maintenance/internal/web"
)

const (
	maxRequestBodyBytes       = 1 << 20
	maxHeaderBytes            = 32 << 10
	readHeaderTimeout         = 5 * time.Second
	readTimeout               = 15 * time.Second
	writeTimeout              = 30 * time.Second
	idleTimeout               = 60 * time.Second
	validationShutdownTimeout = 10 * time.Second
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type ValidationBackend interface {
	Start(context.Context, validation.StartRequest) (jobs.Job, error)
	Get(context.Context, string) (validation.Record, error)
	List(context.Context, jobs.ListOptions) (validation.RecordPage, error)
	CurrentSnapshot(context.Context) (*manifest.SourceSnapshot, error)
}

type BreakGlassAuthenticator interface {
	Login(http.ResponseWriter, *http.Request) error
}

type BrowserAuthenticator interface {
	BeginLogin(http.ResponseWriter, *http.Request) error
	CompleteCallback(http.ResponseWriter, *http.Request) error
	Logout(http.ResponseWriter, *http.Request) error
}

type HandlerOptions struct {
	Logger            *slog.Logger
	IsReady           func() bool
	Authenticator     auth.Authenticator
	Authorizer        auth.Authorizer
	BrowserAuth       BrowserAuthenticator
	LogoutAuth        BrowserAuthenticator
	BreakGlassAuth    BreakGlassAuthenticator
	ValidationBackend ValidationBackend
}

type HTTPRuntime struct {
	listener   net.Listener
	server     *http.Server
	validation *validation.Service
	build      BuildInfo
	ready      atomic.Bool
}

func NewHTTPRuntime(cfg *config.ServerConfig, build BuildInfo) (Runtime, error) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	return newHTTPRuntime(cfg, build, logger, net.Listen)
}

func newHTTPRuntime(
	cfg *config.ServerConfig,
	build BuildInfo,
	logger *slog.Logger,
	listen func(string, string) (net.Listener, error),
) (Runtime, error) {
	if cfg == nil {
		return nil, errors.New("server config is nil")
	}
	if err := cfg.ValidateStartup(); err != nil {
		return nil, fmt.Errorf("validate server config: %w", err)
	}
	if logger == nil {
		return nil, errors.New("server logger is nil")
	}
	if listen == nil {
		return nil, errors.New("server listen function is nil")
	}

	listener, err := listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen on configured address: %w", err)
	}

	var browserAuth BrowserAuthenticator
	var logoutAuth BrowserAuthenticator
	var oidcAuth *auth.BrowserOIDC
	var bearerAuth *auth.BearerOIDC
	var breakGlassAuth *auth.BreakGlassService
	var authenticators []auth.Authenticator
	if cfg.OIDC.Enabled || cfg.BreakGlass.Enabled {
		secretReader, secretErr := secretmount.NewMountedReader(cfg.OIDC.SecretMountRoot, secretmount.DefaultMaxBytes)
		if secretErr != nil {
			listener.Close()
			return nil, fmt.Errorf("open authentication secret mounts: %w", secretErr)
		}
		if cfg.OIDC.Enabled {
			oidcAuth, err = auth.NewBrowserOIDC(auth.BrowserOIDCOptions{OIDC: cfg.OIDC, Authorization: cfg.Authorization, Secrets: secretReader, TrustedProxies: cfg.TrustedProxies})
			if err != nil {
				listener.Close()
				return nil, fmt.Errorf("initialize OIDC authentication: %w", err)
			}
			browserAuth = oidcAuth
			logoutAuth = oidcAuth
			authenticators = append(authenticators, oidcAuth)
			bearerAuth, err = auth.NewBearerOIDC(oidcAuth)
			if err != nil {
				listener.Close()
				return nil, fmt.Errorf("initialize bearer authentication: %w", err)
			}
		}
		if cfg.BreakGlass.Enabled {
			recorder := audit.LogRecorder{Logger: logger}
			liveConfig := auth.BreakGlassConfigSourceFunc(func(ctx context.Context) (*config.ServerConfig, error) {
				live, loadErr := config.LoadServerConfig(cfg.RuntimeConfigPath())
				if loadErr != nil {
					return nil, loadErr
				}
				overrides := cfg.StartupOverrides()
				if overrides.PublicURLOverride != "" {
					live.PublicURL = overrides.PublicURLOverride
				}
				return live, nil
			})
			breakGlassAuth, err = auth.NewBreakGlass(auth.BreakGlassOptions{ConfigSource: liveConfig, Secrets: secretReader, TrustedProxies: cfg.TrustedProxies, Audit: func(ctx context.Context, event auth.BreakGlassAuditEvent) error {
				outcome := audit.Outcome(event.Outcome)
				action := audit.ActionBreakGlassLogin
				if event.Action == "logout" {
					action = audit.ActionLogout
				}
				return recorder.Record(ctx, audit.Event{OccurredAt: time.Now().UTC(), Actor: event.Actor, RequestID: RequestID(ctx), Action: action, Outcome: outcome, ReasonCode: event.ReasonCode})
			}})
			if err != nil {
				listener.Close()
				return nil, fmt.Errorf("initialize break-glass authentication: %w", err)
			}
			authenticators = append(authenticators, breakGlassAuth)
			logoutAuth = breakGlassAuth
		}
	}

	validationService, err := validation.NewService(validation.Options{
		Inputs:     validation.MountedInputReader{ConfigPath: cfg.RuntimeConfigPath(), Overrides: cfg.StartupOverrides()},
		Repository: validation.NewMemoryRepository(), Workers: 1, QueueCapacity: 32,
	})
	if err != nil {
		listener.Close()
		return nil, fmt.Errorf("create validation service: %w", err)
	}
	runtime := &HTTPRuntime{listener: listener, validation: validationService, build: build.Normalized()}
	handlerOptions := HandlerOptions{Logger: logger, IsReady: runtime.ready.Load, ValidationBackend: validationService, BrowserAuth: browserAuth, LogoutAuth: logoutAuth, BreakGlassAuth: breakGlassAuth}
	if len(authenticators) != 0 {
		sessions := auth.NewCompositeAuthenticator(authenticators...)
		handlerOptions.Authenticator = auth.NewRequestAuthenticator(sessions, bearerAuth)
	}
	handler := NewHandler(handlerOptions)
	runtime.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	return runtime, nil
}

func (runtime *HTTPRuntime) Serve() error {
	runtime.ready.Store(true)
	defer runtime.ready.Store(false)
	err := runtime.server.Serve(runtime.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	if err != nil {
		_ = runtime.listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), validationShutdownTimeout)
		defer cancel()
		_ = runtime.validation.Shutdown(ctx)
	}
	return err
}

func (runtime *HTTPRuntime) Shutdown(ctx context.Context) error {
	runtime.ready.Store(false)
	serverErr := runtime.server.Shutdown(ctx)
	listenerErr := runtime.listener.Close()
	validationErr := runtime.validation.Shutdown(ctx)
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		return serverErr
	}
	if listenerErr != nil && !errors.Is(listenerErr, net.ErrClosed) {
		return listenerErr
	}
	return validationErr
}

func NewHandler(options HandlerOptions) http.Handler {
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	isReady := options.IsReady
	if isReady == nil {
		isReady = func() bool { return true }
	}
	authenticator := options.Authenticator
	if authenticator == nil {
		authenticator = auth.DenyAuthenticator{}
	}
	authorizer := options.Authorizer
	if authorizer == nil {
		authorizer = auth.RBACAuthorizer{}
	}
	if options.ValidationBackend == nil {
		options.ValidationBackend = unavailableValidationBackend{}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		api.WriteJSON(w, request, http.StatusOK, map[string]string{"status": "live"})
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		if !isReady() {
			api.WriteError(w, request, http.StatusServiceUnavailable, "not_ready", "service is not ready", RequestID(request.Context()))
			return
		}
		api.WriteJSON(w, request, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("/api/v1/openapi.json", func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if request.Method != http.MethodHead {
			_, _ = w.Write(api.OpenAPIDocument())
		}
	})
	mux.Handle("/auth/login", browserLoginHandler(options.BrowserAuth))
	mux.Handle("/auth/callback", browserCallbackHandler(options.BrowserAuth))
	logoutAuth := options.LogoutAuth
	if logoutAuth == nil {
		logoutAuth = options.BrowserAuth
	}
	mux.Handle("/auth/logout", authenticate(authenticator, browserLogoutHandler(logoutAuth)))
	mux.Handle("/auth/break-glass/login", breakGlassLoginHandler(options.BreakGlassAuth))
	mux.HandleFunc("/assets/", serveWebAsset)

	protectedMux := http.NewServeMux()
	protectedMux.Handle("/api/v1/session", authorize(authorizer, auth.PermissionSessionRead, http.HandlerFunc(sessionHandler)))
	if options.ValidationBackend == nil {
		protectedMux.Handle("/api/v1/sources", authorize(authorizer, auth.PermissionSourcesRead, readPlaceholder("source inventory")))
		protectedMux.Handle("/api/v1/sources/", detailReadHandler("/api/v1/sources/", authorizer, auth.PermissionSourcesRead, "source inventory"))
		protectedMux.Handle("/api/v1/targets", authorize(authorizer, auth.PermissionTargetsRead, readPlaceholder("target inventory")))
		protectedMux.Handle("/api/v1/targets/", targetSubresourceHandler(authorizer))
		protectedMux.Handle("/api/v1/validations", jobCollectionHandler(authorizer, auth.PermissionValidationsRead, auth.PermissionValidationsCreate, "validation"))
		protectedMux.Handle("/api/v1/validations/", detailReadHandler("/api/v1/validations/", authorizer, auth.PermissionValidationsRead, "validation job"))
	} else {
		protectedMux.Handle("/api/v1/sources", authorize(authorizer, auth.PermissionSourcesRead, sourceCollectionHandler(options.ValidationBackend)))
		protectedMux.Handle("/api/v1/sources/", authorize(authorizer, auth.PermissionSourcesRead, sourceDetailHandler(options.ValidationBackend)))
		protectedMux.Handle("/api/v1/targets", authorize(authorizer, auth.PermissionTargetsRead, targetCollectionHandler(options.ValidationBackend)))
		protectedMux.Handle("/api/v1/targets/", targetPhaseOneHandler(options.ValidationBackend, authorizer))
		protectedMux.Handle("/api/v1/validations", validationCollectionHandler(options.ValidationBackend, authorizer))
		protectedMux.Handle("/api/v1/validations/", authorize(authorizer, auth.PermissionValidationsRead, validationDetailHandler(options.ValidationBackend)))
	}
	protectedMux.Handle("/api/v1/plans", jobCollectionHandler(authorizer, auth.PermissionPlansRead, auth.PermissionPlansCreate, "plan"))
	protectedMux.Handle("/api/v1/plans/", planSubresourceHandler(authorizer))
	protectedMux.Handle("/api/v1/jobs", authorize(authorizer, auth.PermissionJobsRead, readPlaceholder("job inventory")))
	protectedMux.Handle("/api/v1/jobs/", detailReadHandler("/api/v1/jobs/", authorizer, auth.PermissionJobsRead, "job"))
	protectedMux.Handle("/api/v1/reports", authorize(authorizer, auth.PermissionReportsRead, readPlaceholder("report inventory")))
	protectedMux.Handle("/api/v1/reports/", detailReadHandler("/api/v1/reports/", authorizer, auth.PermissionReportsRead, "report"))
	protectedMux.Handle("/api/v1/audit", authorize(authorizer, auth.PermissionAuditRead, readPlaceholder("audit inventory")))
	protectedMux.HandleFunc("/api/v1", protectedNotFound)
	protectedMux.HandleFunc("/api/v1/", protectedNotFound)
	protectedAPI := authenticate(authenticator, protectedMux)
	mux.Handle("/api/v1", protectedAPI)
	mux.Handle("/api/v1/", protectedAPI)
	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
		if webui.AppRoute(request.URL.Path) {
			serveWebIndex(w, request)
			return
		}
		api.WriteError(w, request, http.StatusNotFound, "not_found", "route not found", RequestID(request.Context()))
	})

	return requestIDMiddleware(
		accessLogMiddleware(logger,
			recoveryMiddleware(logger,
				securityHeadersMiddleware(
					bodyLimitMiddleware(maxRequestBodyBytes, mux),
				),
			),
		),
	)
}

func serveWebIndex(w http.ResponseWriter, request *http.Request) {
	if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = w.Write(webui.Index())
	}
}

func serveWebAsset(w http.ResponseWriter, request *http.Request) {
	if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
		return
	}
	asset, ok := webui.Lookup(request.URL.Path)
	if !ok {
		api.WriteError(w, request, http.StatusNotFound, "not_found", "route not found", RequestID(request.Context()))
		return
	}
	w.Header().Set("Content-Type", asset.ContentType)
	w.WriteHeader(http.StatusOK)
	if request.Method != http.MethodHead {
		_, _ = w.Write(asset.Content)
	}
}

func sessionHandler(w http.ResponseWriter, request *http.Request) {
	if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
		return
	}
	actor, ok := auth.ActorFromContext(request.Context())
	if !ok {
		api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
		return
	}
	response := api.SessionResponse{APIVersion: api.Version, Authenticated: true, AuthenticationMethod: actor.Method, Actor: actor}
	if !actor.SessionExpiresAt.IsZero() {
		expires := actor.SessionExpiresAt
		response.ExpiresAt = &expires
	}
	api.WriteJSON(w, request, http.StatusOK, response)
}

func protectedNotFound(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusNotFound, "not_found", "route not found", RequestID(request.Context()))
}

func readPlaceholder(resource string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		api.WriteError(w, request, http.StatusNotImplemented, "endpoint_not_implemented", resource+" endpoint is not implemented yet", RequestID(request.Context()))
	})
}

func mutationJobPlaceholder(jobType string) http.Handler {
	return jsonMutationPlaceholder(http.MethodPost, "job_execution_not_implemented", jobType+" job execution is not implemented yet")
}

func jsonMutationPlaceholder(method, code, message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, method) {
			return
		}
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			api.WriteError(w, request, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json", RequestID(request.Context()))
			return
		}
		if _, err := api.IdempotencyKey(request); err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_idempotency_key", "a valid Idempotency-Key header is required", RequestID(request.Context()))
			return
		}
		api.WriteError(w, request, http.StatusNotImplemented, code, message, RequestID(request.Context()))
	})
}

func jobCollectionHandler(authorizer auth.Authorizer, readPermission, createPermission auth.Permission, jobType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet, http.MethodHead:
			authorize(authorizer, readPermission, readPlaceholder(jobType+" job inventory")).ServeHTTP(w, request)
		case http.MethodPost:
			authorize(authorizer, createPermission, mutationJobPlaceholder(jobType)).ServeHTTP(w, request)
		default:
			allowMethods(w, request, http.MethodGet, http.MethodHead, http.MethodPost)
		}
	})
}

func detailReadHandler(prefix string, authorizer auth.Authorizer, permission auth.Permission, resource string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		identifier := strings.TrimPrefix(request.URL.Path, prefix)
		if !requestIDPattern.MatchString(identifier) {
			protectedNotFound(w, request)
			return
		}
		authorize(authorizer, permission, readPlaceholder(resource)).ServeHTTP(w, request)
	})
}

func targetSubresourceHandler(authorizer auth.Authorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/targets/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 1 && requestIDPattern.MatchString(parts[0]) {
			authorize(authorizer, auth.PermissionTargetsRead, readPlaceholder("target inventory")).ServeHTTP(w, request)
			return
		}
		if len(parts) != 2 || !requestIDPattern.MatchString(parts[0]) {
			protectedNotFound(w, request)
			return
		}
		switch parts[1] {
		case "credential-status":
			authorize(authorizer, auth.PermissionCredentialsRead, readPlaceholder("credential status")).ServeHTTP(w, request)
		case "credentials":
			switch request.Method {
			case http.MethodPut:
				authorize(authorizer, auth.PermissionCredentialsWrite, jsonMutationPlaceholder(http.MethodPut, "endpoint_not_implemented", "credential upload is not implemented yet")).ServeHTTP(w, request)
			case http.MethodDelete:
				authorize(authorizer, auth.PermissionCredentialsWrite, jsonMutationPlaceholder(http.MethodDelete, "endpoint_not_implemented", "credential deletion is not implemented yet")).ServeHTTP(w, request)
			default:
				allowMethods(w, request, http.MethodPut, http.MethodDelete)
			}
		default:
			protectedNotFound(w, request)
		}
	})
}

func planSubresourceHandler(authorizer auth.Authorizer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/plans/")
		parts := strings.Split(remainder, "/")
		if len(parts) == 1 && requestIDPattern.MatchString(parts[0]) {
			authorize(authorizer, auth.PermissionPlansRead, readPlaceholder("plan")).ServeHTTP(w, request)
			return
		}
		if len(parts) != 2 || !requestIDPattern.MatchString(parts[0]) || parts[1] != "apply" {
			protectedNotFound(w, request)
			return
		}
		authorize(authorizer, auth.PermissionPlansApply, mutationJobPlaceholder("apply")).ServeHTTP(w, request)
	})
}

func authenticate(authenticator auth.Authenticator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		actor, err := authenticator.Authenticate(request)
		if errors.Is(err, auth.ErrOIDCUnavailable) {
			api.WriteError(w, request, http.StatusServiceUnavailable, "authentication_unavailable", "authentication provider is unavailable", RequestID(request.Context()))
			return
		}
		if errors.Is(err, auth.ErrAuthenticationConflict) {
			api.WriteError(w, request, http.StatusConflict, "authentication_conflict", "multiple authentication identities are not allowed", RequestID(request.Context()))
			return
		}
		if err != nil {
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
			return
		}
		normalized, err := actor.Normalized()
		if err != nil {
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
			return
		}
		next.ServeHTTP(w, request.WithContext(auth.WithActor(request.Context(), normalized)))
	})
}

func authorize(authorizer auth.Authorizer, permission auth.Permission, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		actor, ok := auth.ActorFromContext(request.Context())
		if !ok {
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
			return
		}
		if err := authorizer.Authorize(actor, permission); err != nil {
			api.WriteError(w, request, http.StatusForbidden, "permission_denied", "permission denied", RequestID(request.Context()))
			return
		}
		next.ServeHTTP(w, request)
	})
}

func breakGlassLoginHandler(service BreakGlassAuthenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodPost) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if service == nil {
			api.WriteError(w, request, http.StatusServiceUnavailable, "break_glass_unavailable", "emergency authentication is unavailable", RequestID(request.Context()))
			return
		}
		err := service.Login(w, request)
		if err == nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch {
		case errors.Is(err, auth.ErrAuthenticationConflict):
			api.WriteError(w, request, http.StatusConflict, "authentication_conflict", "multiple authentication identities are not allowed", RequestID(request.Context()))
		case errors.Is(err, auth.ErrBreakGlassRequestTooLarge):
			api.WriteError(w, request, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the limit", RequestID(request.Context()))
		case errors.Is(err, auth.ErrBreakGlassUnsupportedMediaType):
			api.WriteError(w, request, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", RequestID(request.Context()))
		case errors.Is(err, auth.ErrBreakGlassUnavailable), errors.Is(err, auth.ErrBreakGlassDisabled):
			api.WriteError(w, request, http.StatusServiceUnavailable, "break_glass_unavailable", "emergency authentication is unavailable", RequestID(request.Context()))
		case errors.Is(err, auth.ErrBreakGlassThrottled):
			w.Header().Set("Retry-After", "30")
			api.WriteError(w, request, http.StatusTooManyRequests, "authentication_throttled", "authentication is temporarily unavailable", RequestID(request.Context()))
		case errors.Is(err, auth.ErrBreakGlassInvalidRequest), errors.Is(err, auth.ErrBreakGlassMethodNotAllowed):
			api.WriteError(w, request, http.StatusBadRequest, "invalid_authentication_request", "authentication request is invalid", RequestID(request.Context()))
		default:
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_failed", "authentication failed", RequestID(request.Context()))
		}
	})
}

func browserLoginHandler(browser BrowserAuthenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet) {
			return
		}
		if browser == nil {
			api.WriteError(w, request, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC authentication is unavailable", RequestID(request.Context()))
			return
		}
		if err := browser.BeginLogin(w, request); err != nil {
			writeBrowserAuthError(w, request, err)
		}
	})
}
func browserCallbackHandler(browser BrowserAuthenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet) {
			return
		}
		if browser == nil {
			api.WriteError(w, request, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC authentication is unavailable", RequestID(request.Context()))
			return
		}
		if err := browser.CompleteCallback(w, request); err != nil {
			writeBrowserAuthError(w, request, err)
		}
	})
}
func browserLogoutHandler(browser BrowserAuthenticator) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodPost) {
			return
		}
		if browser == nil {
			api.WriteError(w, request, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC authentication is unavailable", RequestID(request.Context()))
			return
		}
		if err := browser.Logout(w, request); err != nil {
			if errors.Is(err, auth.ErrInvalidAuthentication) {
				api.WriteError(w, request, http.StatusBadRequest, "invalid_logout", "logout request is invalid", RequestID(request.Context()))
				return
			}
			writeBrowserAuthError(w, request, err)
		}
	})
}
func writeBrowserAuthError(w http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, auth.ErrOIDCUnavailable), errors.Is(err, auth.ErrOIDCDisabled):
		api.WriteError(w, request, http.StatusServiceUnavailable, "oidc_unavailable", "OIDC authentication is unavailable", RequestID(request.Context()))
	case errors.Is(err, auth.ErrAuthenticationConflict):
		api.WriteError(w, request, http.StatusConflict, "authentication_conflict", "multiple authentication identities are not allowed", RequestID(request.Context()))
	default:
		api.WriteError(w, request, http.StatusUnauthorized, "authentication_failed", "authentication failed", RequestID(request.Context()))
	}
}

func notImplementedAuth(method string) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, method) {
			return
		}
		api.WriteError(w, request, http.StatusNotImplemented, "not_implemented", "OIDC authentication is not implemented yet", RequestID(request.Context()))
	}
}

func allowMethods(w http.ResponseWriter, request *http.Request, methods ...string) bool {
	for _, method := range methods {
		if request.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	api.WriteError(w, request, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", RequestID(request.Context()))
	return false
}

func bodyLimitMiddleware(limit int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.ContentLength > limit {
			api.WriteError(w, request, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds the configured limit", RequestID(request.Context()))
			return
		}
		request.Body = http.MaxBytesReader(w, request.Body, limit)
		next.ServeHTTP(w, request)
	})
}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, request)
	})
}

func recoveryMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		defer func() {
			if recover() != nil {
				requestID := RequestID(request.Context())
				logger.Error("HTTP handler panic recovered", "request_id", requestID)
				if tracked, ok := w.(*statusWriter); !ok || !tracked.wroteHeader {
					api.WriteError(w, request, http.StatusInternalServerError, "internal_error", "internal server error", requestID)
				}
			}
		}()
		next.ServeHTTP(w, request)
	})
}

func accessLogMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		started := time.Now()
		tracked := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(tracked, request)
		logger.Info("HTTP request completed",
			"request_id", RequestID(request.Context()),
			"method", request.Method,
			"path", request.URL.Path,
			"status", tracked.status,
			"bytes", tracked.bytes,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requestID := newRequestID()
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(request.Context(), requestIDContextKey{}, requestID)
		next.ServeHTTP(w, request.WithContext(ctx))
	})
}

type requestIDContextKey struct{}

func RequestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey{}).(string)
	if requestIDPattern.MatchString(value) {
		return value
	}
	return "unknown"
}

var requestIDFallback atomic.Uint64

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return fmt.Sprintf("fallback-%d-%d", time.Now().UnixNano(), requestIDFallback.Add(1))
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int
	wroteHeader bool
}

func (writer *statusWriter) WriteHeader(status int) {
	if writer.wroteHeader {
		return
	}
	writer.wroteHeader = true
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusWriter) Write(body []byte) (int, error) {
	if !writer.wroteHeader {
		writer.WriteHeader(http.StatusOK)
	}
	written, err := writer.ResponseWriter.Write(body)
	writer.bytes += written
	return written, err
}

func (writer *statusWriter) Unwrap() http.ResponseWriter { return writer.ResponseWriter }
