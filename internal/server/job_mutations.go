package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/jobscheduler"
)

// JobCancellationBackend is the narrow mutation capability exposed to HTTP.
// It is deliberately separate from JobReadBackend so a read-only adapter can
// never be used to mutate durable jobs.
type JobCancellationBackend interface {
	RequestCancellation(context.Context, jobs.CancellationRequest) (jobs.Job, error)
}

var _ JobCancellationBackend = (*jobscheduler.Scheduler)(nil)

var errJobCancellationUnavailable = errors.New("job cancellation backend unavailable")

type unavailableJobCancellationBackend struct{}

func (unavailableJobCancellationBackend) RequestCancellation(context.Context, jobs.CancellationRequest) (jobs.Job, error) {
	return jobs.Job{}, errJobCancellationUnavailable
}

// defaultJobCancellationPolicy is the status portion of the existing generic
// cancellation policy. Role authorization is intentionally kept separate and
// is selected from the durable job type below.
type defaultJobCancellationPolicy struct{}

func (defaultJobCancellationPolicy) CanCancel(job jobs.Job) bool {
	return job.Status == jobs.StatusQueued || job.Status == jobs.StatusRunning || job.Status == jobs.StatusCanceled
}

func jobSubresourceHandler(readBackend JobReadBackend, cancellationBackend JobCancellationBackend, policy jobs.CancellationPolicy, authorizer auth.Authorizer, eventOptions jobEventOptions, originBackend CredentialBackend, publicURL string, trustedProxies []string, limiters ...*jobEventLimiter) http.Handler {
	if readBackend == nil {
		readBackend = unavailableJobReadBackend{}
	}
	if cancellationBackend == nil {
		cancellationBackend = unavailableJobCancellationBackend{}
	}
	if policy == nil {
		policy = defaultJobCancellationPolicy{}
	}
	if authorizer == nil {
		authorizer = auth.RBACAuthorizer{}
	}
	eventOptions = eventOptions.normalized()
	var eventLimiter *jobEventLimiter
	if len(limiters) != 0 {
		eventLimiter = limiters[0]
	}
	if eventLimiter == nil {
		eventLimiter = newJobEventLimiter(eventOptions.MaxStreams)
	}
	detail := authorize(authorizer, auth.PermissionJobsRead, jobDetailHandler(readBackend))
	events := authorize(authorizer, auth.PermissionJobsRead, newJobEventsHandlerWithLimiter(readBackend, eventOptions, eventLimiter))
	cancel := jobCancellationHandler(readBackend, cancellationBackend, policy, authorizer, originBackend, publicURL, trustedProxies)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if _, ok := exactJobActionID(request.URL.Path, "events"); ok {
			events.ServeHTTP(w, request)
			return
		}
		if _, ok := exactJobActionID(request.URL.Path, "cancel"); ok {
			cancel.ServeHTTP(w, request)
			return
		}
		detail.ServeHTTP(w, request)
	})
}

func exactJobActionID(path, action string) (string, bool) {
	const prefix = "/api/v1/jobs/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != action {
		return "", false
	}
	return parts[0], true
}

func jobCancellationHandler(readBackend JobReadBackend, cancellationBackend JobCancellationBackend, policy jobs.CancellationPolicy, authorizer auth.Authorizer, originBackend CredentialBackend, publicURL string, trustedProxies []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodPost) {
			return
		}
		id, ok := exactJobActionID(request.URL.Path, "cancel")
		if !ok || !requestIDPattern.MatchString(id) {
			writeJobNotFound(w, request)
			return
		}
		setJobAuditID(w, id)
		if request.URL.RawQuery != "" || request.URL.ForceQuery || request.URL.Fragment != "" {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_job_query", "job query parameters are invalid", RequestID(request.Context()))
			return
		}

		actor, ok := auth.ActorFromContext(request.Context())
		if !ok {
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
			return
		}
		if !requestBodyIsEmpty(request) {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_job_request", "job cancellation request is invalid", RequestID(request.Context()))
			return
		}
		livePublic, liveTrusted, originReady := liveCredentialOrigin(request.Context(), originBackend, publicURL, trustedProxies)
		if !originReady || !validCredentialMutationOrigin(request, livePublic, liveTrusted) {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_origin", "job cancellation origin is invalid", RequestID(request.Context()))
			return
		}

		// Read before selecting the role permission. This preserves the same
		// safe not-found behavior as job detail while avoiding a type oracle for
		// malformed or missing durable records.
		record, err := readBackend.Get(request.Context(), id)
		if err != nil {
			if errors.Is(err, jobs.ErrNotFound) {
				writeJobNotFound(w, request)
				return
			}
			writeJobsUnavailable(w, request)
			return
		}
		if record.Job.ID != id || record.Job.Validate() != nil {
			writeJobsUnavailable(w, request)
			return
		}
		current := publicJob(record.Job)
		permission, knownType := jobCancellationPermission(current.Type)
		if !knownType {
			writeJobsUnavailable(w, request)
			return
		}
		if authorizer.Authorize(actor, permission) != nil {
			api.WriteError(w, request, http.StatusForbidden, "permission_denied", "permission denied", RequestID(request.Context()))
			return
		}
		if current.Status == jobs.StatusCanceled && !record.Job.CancellationRequested {
			writeJobCancellationUnsupported(w, request)
			return
		}
		if policy == nil || !policy.CanCancel(current) {
			writeJobCancellationUnsupported(w, request)
			return
		}
		if cancellationBackend == nil {
			writeJobCancellationUnavailable(w, request)
			return
		}
		result, err := cancellationBackend.RequestCancellation(request.Context(), jobs.CancellationRequest{JobID: id, ActorSubject: actor.Subject, RequestID: RequestID(request.Context())})
		if err != nil {
			writeJobCancellationError(w, request, err)
			return
		}
		if !validPublicCancellationResult(result, id, current) {
			writeJobCancellationUnavailable(w, request)
			return
		}
		api.WriteJSON(w, request, http.StatusAccepted, api.JobResponse{APIVersion: api.Version, Job: result})
	})
}

func setJobAuditID(w http.ResponseWriter, id string) {
	for {
		if tracked, ok := w.(*statusWriter); ok {
			tracked.auditJobID = id
			return
		}
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return
		}
		w = unwrapper.Unwrap()
	}
}

func validPublicCancellationResult(result jobs.Job, id string, before jobs.Job) bool {
	if result.ID != id || result.Type != before.Type || !result.Type.Valid() || !result.Status.Valid() || result.ActorSubject == "" || result.RequestID == "" || !result.CreatedAt.Equal(before.CreatedAt) || result.ActorSubject != before.ActorSubject || result.RequestID != before.RequestID || result.FailureCode != "" {
		return false
	}
	if result.CreatedAt.IsZero() || (result.StartedAt != nil && result.StartedAt.Before(result.CreatedAt)) || (result.FinishedAt != nil && result.FinishedAt.Before(result.CreatedAt)) {
		return false
	}
	if result.StartedAt != nil && result.FinishedAt != nil && result.FinishedAt.Before(*result.StartedAt) {
		return false
	}
	switch before.Status {
	case jobs.StatusQueued:
		switch result.Status {
		case jobs.StatusQueued:
			// A scheduler may return its queued requested projection before the
			// claim becomes visible to the pre-read. It must remain unchanged.
			return result.StartedAt == nil && result.FinishedAt == nil
		case jobs.StatusRunning:
			// The pre-read can race a scheduler claim. Accept only an
			// authoritative running lifecycle with a safe start time.
			return result.StartedAt != nil && !result.StartedAt.Before(result.CreatedAt) && result.FinishedAt == nil
		case jobs.StatusCanceled:
			// Cancellation may win after the scheduler claims the queued job, so
			// a terminal result may carry the claim's start time. The finish must
			// be at or after creation and, when present, the start time.
			return result.FinishedAt != nil && !result.FinishedAt.Before(result.CreatedAt) && (result.StartedAt == nil || !result.StartedAt.Before(result.CreatedAt)) && (result.StartedAt == nil || !result.FinishedAt.Before(*result.StartedAt))
		default:
			return false
		}
	case jobs.StatusRunning:
		if result.Status != jobs.StatusRunning && result.Status != jobs.StatusCanceled {
			return false
		}
		if !samePublicJobTime(result.StartedAt, before.StartedAt) {
			return false
		}
		if result.Status == jobs.StatusRunning {
			return result.FinishedAt == nil
		}
		return result.FinishedAt != nil
	case jobs.StatusCanceled:
		return result.Status == jobs.StatusCanceled && samePublicJobTime(result.StartedAt, before.StartedAt) && samePublicJobTime(result.FinishedAt, before.FinishedAt)
	default:
		return false
	}
}

func samePublicJobTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Equal(*right)
}

func jobCancellationPermission(jobType jobs.Type) (auth.Permission, bool) {
	switch jobType {
	case jobs.TypeValidation:
		return auth.PermissionValidationsCreate, true
	case jobs.TypePlan:
		return auth.PermissionPlansCreate, true
	case jobs.TypeApply:
		return auth.PermissionPlansApply, true
	case jobs.TypeTargetInventory:
		return auth.PermissionTargetsRead, true
	default:
		return "", false
	}
}

// requestBodyIsEmpty rejects both explicit bodies and ambiguous transfer
// framing. Reading one byte also catches malformed test/server requests which
// claim Content-Length: 0 while still providing body bytes; unknown-length
// requests are rejected as ambiguous framing.
func requestBodyIsEmpty(request *http.Request) bool {
	if request == nil || len(request.TransferEncoding) != 0 || len(request.Header.Values("Transfer-Encoding")) != 0 || request.ContentLength < 0 || request.ContentLength > 0 {
		return false
	}
	contentLengths := request.Header.Values("Content-Length")
	if len(contentLengths) != 0 && (len(contentLengths) != 1 || strings.TrimSpace(contentLengths[0]) != "0") {
		return false
	}
	if request.Body == nil {
		return true
	}
	var one [1]byte
	n, err := request.Body.Read(one[:])
	return n == 0 && errors.Is(err, io.EOF)
}

func writeJobCancellationConflict(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusConflict, "job_cancellation_conflict", "job cancellation conflicted", RequestID(request.Context()))
}

func writeJobCancellationUnsupported(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusConflict, "job_cancellation_unsupported", "job cancellation is not supported for this job", RequestID(request.Context()))
}

func writeJobCancellationUnavailable(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusServiceUnavailable, "job_cancellation_unavailable", "job cancellation is temporarily unavailable", RequestID(request.Context()))
}

func writeJobCancellationError(w http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, jobscheduler.ErrInvalidCancellationRequest):
		api.WriteError(w, request, http.StatusBadRequest, "invalid_job_request", "job cancellation request is invalid", RequestID(request.Context()))
	case errors.Is(err, jobs.ErrNotFound):
		writeJobNotFound(w, request)
	case errors.Is(err, jobs.ErrCancellationUnsupported):
		writeJobCancellationUnsupported(w, request)
	case errors.Is(err, jobs.ErrInvalidTransition), errors.Is(err, jobs.ErrConflict):
		writeJobCancellationConflict(w, request)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, jobs.ErrQueueClosed), errors.Is(err, jobs.ErrQueueFull), errors.Is(err, jobs.ErrNotImplemented), errors.Is(err, errJobCancellationUnavailable):
		writeJobCancellationUnavailable(w, request)
	default:
		writeJobCancellationUnavailable(w, request)
	}
}
