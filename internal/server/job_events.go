package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

const (
	defaultJobEventPollInterval = 250 * time.Millisecond
	defaultJobEventMaxDuration  = 20 * time.Second
	defaultJobEventMaxEvents    = 64
	defaultJobEventMaxStreams   = 32
	maxSerializedJobEventBytes  = 4096
	maxEventAcceptBytes         = 64
)

var lastEventIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// jobEventOptions is intentionally unexported. It gives server tests a short
// bounded stream without adding mutable production configuration.
type jobEventOptions struct {
	PollInterval time.Duration
	MaxDuration  time.Duration
	MaxEvents    int

	// MaxStreams is a test-only override for the fixed per-handler admission
	// bound. MaxConcurrentStreams is accepted as an equivalent spelling for
	// callers that describe the bound in terms of concurrency.
	MaxStreams           int
	MaxConcurrentStreams int
}

func (options jobEventOptions) normalized() jobEventOptions {
	if options.PollInterval <= 0 {
		options.PollInterval = defaultJobEventPollInterval
	}
	if options.MaxDuration <= 0 {
		options.MaxDuration = defaultJobEventMaxDuration
	}
	if options.MaxEvents <= 0 {
		options.MaxEvents = defaultJobEventMaxEvents
	}
	maxStreams := options.MaxConcurrentStreams
	if maxStreams <= 0 {
		maxStreams = options.MaxStreams
	}
	if maxStreams <= 0 {
		maxStreams = defaultJobEventMaxStreams
	}
	options.MaxStreams = maxStreams
	options.MaxConcurrentStreams = maxStreams
	return options
}

type jobEventLimiter struct {
	slots chan struct{}
}

func newJobEventLimiter(maxStreams int) *jobEventLimiter {
	if maxStreams <= 0 {
		maxStreams = defaultJobEventMaxStreams
	}
	return &jobEventLimiter{slots: make(chan struct{}, maxStreams)}
}

func (limiter *jobEventLimiter) tryAcquire() bool {
	if limiter == nil {
		return false
	}
	select {
	case limiter.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (limiter *jobEventLimiter) release() {
	if limiter == nil {
		return
	}
	select {
	case <-limiter.slots:
	default:
	}
}

func newJobEventsHandler(backend JobReadBackend, options jobEventOptions) http.Handler {
	options = options.normalized()
	return newJobEventsHandlerWithLimiter(backend, options, newJobEventLimiter(options.MaxStreams))
}

func newJobEventsHandlerWithLimiter(backend JobReadBackend, options jobEventOptions, limiter *jobEventLimiter) http.Handler {
	if backend == nil {
		backend = unavailableJobReadBackend{}
	}
	options = options.normalized()
	if limiter == nil {
		limiter = newJobEventLimiter(options.MaxStreams)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet) {
			return
		}
		id, ok := exactJobActionID(request.URL.Path, "events")
		if !ok || !requestIDPattern.MatchString(id) {
			writeJobNotFound(w, request)
			return
		}
		if request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_job_query", "job query parameters are invalid", RequestID(request.Context()))
			return
		}
		if !requestBodyIsEmpty(request) {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_job_request", "job events request is invalid", RequestID(request.Context()))
			return
		}
		if !validEventAccept(request) {
			api.WriteError(w, request, http.StatusNotAcceptable, "event_stream_required", "Accept must contain exactly text/event-stream", RequestID(request.Context()))
			return
		}
		lastID, ok := requestLastEventID(request)
		if !ok {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_last_event_id", "Last-Event-ID is invalid", RequestID(request.Context()))
			return
		}
		if !limiter.tryAcquire() {
			w.Header().Set("Retry-After", "1")
			api.WriteError(w, request, http.StatusTooManyRequests, "job_event_limit", "job event streaming is temporarily at capacity", RequestID(request.Context()))
			return
		}
		defer limiter.release()

		streamContext, cancel := context.WithTimeout(request.Context(), options.MaxDuration)
		defer cancel()
		record, err := backend.Get(streamContext, id)
		if streamContext.Err() != nil {
			writeJobsUnavailable(w, request)
			return
		}
		if err != nil {
			writeJobEventReadError(w, request, err)
			return
		}
		if record.Job.ID != id || record.Job.Validate() != nil {
			writeJobsUnavailable(w, request)
			return
		}
		data, eventID, projected := marshalJobEvent(record.Job)
		if len(data) == 0 || len(data) > maxSerializedJobEventBytes {
			writeJobsUnavailable(w, request)
			return
		}
		if !responseSupportsFlush(w) {
			writeJobsUnavailable(w, request)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)
		if flushResponse(w) != nil {
			return
		}

		emitted := 0
		if eventID != lastID {
			if !writeJobEvent(w, eventID, data) {
				return
			}
			emitted++
			if projected.Terminal() || emitted >= options.MaxEvents {
				return
			}
		} else if projected.Terminal() {
			return
		}

		ticker := time.NewTicker(options.PollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-streamContext.Done():
				return
			case <-ticker.C:
				record, err := backend.Get(streamContext, id)
				if streamContext.Err() != nil {
					return
				}
				if err != nil {
					// Headers are already committed. Do not turn backend or
					// storage diagnostics into an SSE event.
					return
				}
				if record.Job.ID != id || record.Job.Validate() != nil {
					return
				}
				nextData, nextID, nextProjected := marshalJobEvent(record.Job)
				if len(nextData) == 0 || len(nextData) > maxSerializedJobEventBytes {
					// The stream is already committed. Close without exposing a
					// backend diagnostic or emitting an unbounded frame.
					return
				}
				if nextID == eventID {
					if nextProjected.Terminal() {
						return
					}
					continue
				}
				if !writeJobEvent(w, nextID, nextData) {
					return
				}
				emitted++
				eventID = nextID
				if nextProjected.Terminal() || emitted >= options.MaxEvents {
					return
				}
			}
		}
	})
}

func validEventAccept(request *http.Request) bool {
	if request == nil {
		return false
	}
	values := request.Header.Values("Accept")
	if len(values) != 1 {
		return false
	}
	if len(values[0]) > maxEventAcceptBytes {
		return false
	}
	value := strings.TrimSpace(values[0])
	if value == "" || strings.Contains(value, ",") {
		return false
	}
	parts := strings.Split(value, ";")
	if len(parts) > 2 || !strings.EqualFold(strings.TrimSpace(parts[0]), "text/event-stream") {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	parameter := strings.TrimSpace(parts[1])
	name, quality, found := strings.Cut(parameter, "=")
	if !found || !strings.EqualFold(strings.TrimSpace(name), "q") || strings.Contains(quality, "=") {
		return false
	}
	return validEventQuality(strings.TrimSpace(quality))
}

func validEventQuality(value string) bool {
	if value == "1" {
		return true
	}
	if len(value) >= 3 && len(value) <= 5 && value[0:2] == "1." {
		for _, character := range value[2:] {
			if character != '0' {
				return false
			}
		}
		return true
	}
	if len(value) < 3 || len(value) > 5 || value[0:2] != "0." {
		return false
	}
	decimal := value[2:]
	if len(decimal) < 1 || len(decimal) > 3 {
		return false
	}
	nonzero := false
	for _, character := range decimal {
		if character < '0' || character > '9' {
			return false
		}
		if character != '0' {
			nonzero = true
		}
	}
	return nonzero
}

func requestLastEventID(request *http.Request) (string, bool) {
	if request == nil {
		return "", false
	}
	values := request.Header.Values("Last-Event-ID")
	if len(values) == 0 {
		return "", true
	}
	if len(values) != 1 || !lastEventIDPattern.MatchString(values[0]) {
		return "", false
	}
	return values[0], true
}

func marshalJobEvent(value state.Job) ([]byte, string, jobs.Job) {
	projected := publicJob(value)
	response := api.JobResponse{APIVersion: api.Version, Job: projected}
	data, err := json.Marshal(response)
	if err != nil {
		return nil, "", projected
	}
	digest := sha256.Sum256(data)
	return data, hex.EncodeToString(digest[:]), projected
}

func writeJobEvent(w http.ResponseWriter, eventID string, data []byte) bool {
	frame := make([]byte, 0, len(data)+len(eventID)+24)
	frame = append(frame, "event: job\nid: "...)
	frame = append(frame, eventID...)
	frame = append(frame, "\ndata: "...)
	frame = append(frame, data...)
	frame = append(frame, '\n', '\n')
	written, err := w.Write(frame)
	if err != nil || written != len(frame) {
		return false
	}
	return flushResponse(w) == nil
}

func responseSupportsFlush(w http.ResponseWriter) bool {
	for steps := 0; steps < 16 && w != nil; steps++ {
		if _, ok := w.(http.Flusher); ok {
			return true
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = unwrapper.Unwrap()
	}
	return false
}

func flushResponse(w http.ResponseWriter) error {
	return http.NewResponseController(w).Flush()
}

func writeJobEventReadError(w http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, jobs.ErrNotFound) {
		writeJobNotFound(w, request)
		return
	}
	writeJobsUnavailable(w, request)
}
