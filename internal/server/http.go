package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"elastic-maintenance/internal/api"
	"elastic-maintenance/internal/config"
)

const (
	maxRequestBodyBytes = 1 << 20
	maxHeaderBytes      = 32 << 10
	readHeaderTimeout   = 5 * time.Second
	readTimeout         = 15 * time.Second
	writeTimeout        = 30 * time.Second
	idleTimeout         = 60 * time.Second
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type HandlerOptions struct {
	Logger  *slog.Logger
	IsReady func() bool
}

type HTTPRuntime struct {
	listener net.Listener
	server   *http.Server
	build    BuildInfo
	ready    atomic.Bool
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

	runtime := &HTTPRuntime{listener: listener, build: build.Normalized()}
	handler := NewHandler(HandlerOptions{
		Logger:  logger,
		IsReady: runtime.ready.Load,
	})
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
	return err
}

func (runtime *HTTPRuntime) Shutdown(ctx context.Context) error {
	runtime.ready.Store(false)
	return runtime.server.Shutdown(ctx)
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
	mux.HandleFunc("/auth/login", notImplementedAuth(http.MethodGet))
	mux.HandleFunc("/auth/callback", notImplementedAuth(http.MethodGet))
	mux.HandleFunc("/auth/logout", notImplementedAuth(http.MethodPost))
	protectedAPI := func(w http.ResponseWriter, request *http.Request) {
		api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
	}
	mux.HandleFunc("/api/v1", protectedAPI)
	mux.HandleFunc("/api/v1/", protectedAPI)
	mux.HandleFunc("/", func(w http.ResponseWriter, request *http.Request) {
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
		w.Header().Set("X-Content-Type-Options", "nosniff")
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
