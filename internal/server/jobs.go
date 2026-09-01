package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/jobrecord"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

// JobReadBackend is the intentionally minimal read-only HTTP boundary for
// durable jobs. The HTTP layer cannot create, transition, cancel, or schedule
// a job through this contract.
type JobReadBackend interface {
	Get(context.Context, string) (jobrecord.Record, error)
	List(context.Context, jobs.ListOptions) (jobrecord.Page, error)
}

var _ JobReadBackend = (*jobrecord.FileRepository)(nil)

type unavailableJobReadBackend struct{}

func (unavailableJobReadBackend) Get(context.Context, string) (jobrecord.Record, error) {
	return jobrecord.Record{}, errors.New("job read backend unavailable")
}

func (unavailableJobReadBackend) List(context.Context, jobs.ListOptions) (jobrecord.Page, error) {
	return jobrecord.Page{}, errors.New("job read backend unavailable")
}

var (
	errInvalidJobQuery     = errors.New("invalid job query")
	errInvalidJobFilter    = errors.New("invalid job filter")
	errInvalidJobPageToken = errors.New("invalid job page token")
)

// parseJobListOptions parses the raw query rather than URL.Query so malformed
// percent escapes and semicolon-separated queries are rejected instead of
// silently discarded. PageToken remains opaque and is passed to the
// repository without wrapping, hashing, or decoding.
func parseJobListOptions(request *http.Request) (jobs.ListOptions, error) {
	if request == nil || request.URL == nil {
		return jobs.ListOptions{}, errInvalidJobQuery
	}
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return jobs.ListOptions{}, errInvalidJobQuery
	}

	for key, entries := range values {
		switch key {
		case "pageSize", "pageToken":
			if len(entries) != 1 {
				if key == "pageToken" {
					return jobs.ListOptions{}, errInvalidJobPageToken
				}
				return jobs.ListOptions{}, errInvalidJobQuery
			}
		case "type", "status":
			if len(entries) > 16 {
				return jobs.ListOptions{}, errInvalidJobFilter
			}
		default:
			return jobs.ListOptions{}, errInvalidJobQuery
		}
	}

	options := jobs.ListOptions{PageSize: api.DefaultPageSize}
	if entries, ok := values["pageSize"]; ok {
		raw := entries[0]
		if !asciiDigits(raw) {
			return jobs.ListOptions{}, errInvalidJobQuery
		}
		pageSize, parseErr := strconv.Atoi(raw)
		if parseErr != nil || pageSize < 1 || pageSize > api.MaxPageSize {
			return jobs.ListOptions{}, errInvalidJobQuery
		}
		options.PageSize = pageSize
	}
	if entries, ok := values["pageToken"]; ok {
		token := entries[0]
		if token == "" || len(token) > 512 {
			return jobs.ListOptions{}, errInvalidJobPageToken
		}
		// Repository tokens are opaque transport cursors: never log or reflect
		// them on errors. The state format is non-secret and is not redesigned
		// in this increment.
		options.PageToken = token
	}

	if entries, ok := values["type"]; ok {
		options.Types = make([]jobs.Type, 0, len(entries))
		seen := make(map[jobs.Type]struct{}, len(entries))
		for _, entry := range entries {
			value := jobs.Type(entry)
			if entry == "" || !value.Valid() {
				return jobs.ListOptions{}, errInvalidJobFilter
			}
			if _, duplicate := seen[value]; duplicate {
				return jobs.ListOptions{}, errInvalidJobFilter
			}
			seen[value] = struct{}{}
			options.Types = append(options.Types, value)
		}
	}
	if entries, ok := values["status"]; ok {
		options.Statuses = make([]jobs.Status, 0, len(entries))
		seen := make(map[jobs.Status]struct{}, len(entries))
		for _, entry := range entries {
			value := jobs.Status(entry)
			if entry == "" || !value.Valid() {
				return jobs.ListOptions{}, errInvalidJobFilter
			}
			if _, duplicate := seen[value]; duplicate {
				return jobs.ListOptions{}, errInvalidJobFilter
			}
			seen[value] = struct{}{}
			options.Statuses = append(options.Statuses, value)
		}
	}
	return options, nil
}

func asciiDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func jobCollectionReadHandler(backend JobReadBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		options, err := parseJobListOptions(request)
		if err != nil {
			writeJobQueryError(w, request, err)
			return
		}
		page, err := backend.List(request.Context(), options)
		if err != nil {
			writeJobListError(w, request, err)
			return
		}
		if len(page.NextPageToken) > 512 {
			writeJobsUnavailable(w, request)
			return
		}
		projected := make([]jobs.Job, 0, len(page.Records))
		for _, record := range page.Records {
			projected = append(projected, publicJob(record.Job))
		}
		api.WriteJSON(w, request, http.StatusOK, api.JobListResponse{
			APIVersion:    api.Version,
			Jobs:          projected,
			NextPageToken: page.NextPageToken,
		})
	})
}

func jobDetailHandler(backend JobReadBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		id, ok := singlePathID(request.URL.Path, "/api/v1/jobs/")
		if !ok || !requestIDPattern.MatchString(id) {
			writeJobNotFound(w, request)
			return
		}
		if request.URL.RawQuery != "" {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_job_query", "job query parameters are invalid", RequestID(request.Context()))
			return
		}
		record, err := backend.Get(request.Context(), id)
		if err != nil {
			if errors.Is(err, jobs.ErrNotFound) {
				writeJobNotFound(w, request)
				return
			}
			writeJobsUnavailable(w, request)
			return
		}
		api.WriteJSON(w, request, http.StatusOK, api.JobResponse{APIVersion: api.Version, Job: publicJob(record.Job)})
	})
}

// publicJob is the single durable-to-HTTP projection boundary. Do not add
// fields here without reviewing the public jobs contract: state.Job also
// contains actor method/roles, idempotency and digest data, result links, and
// cancellation state that must never leave the server through this endpoint.
func publicJob(value state.Job) jobs.Job {
	projected := jobs.Job{
		ID:           value.ID,
		Type:         value.Type,
		Status:       value.Status,
		CreatedAt:    value.CreatedAt,
		ActorSubject: value.Actor.Subject,
		RequestID:    value.RequestID,
		FailureCode:  value.FailureCode,
	}
	if value.StartedAt != nil {
		started := *value.StartedAt
		projected.StartedAt = &started
	}
	if value.FinishedAt != nil {
		finished := *value.FinishedAt
		projected.FinishedAt = &finished
	}
	return projected
}

func writeJobNotFound(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusNotFound, "job_not_found", "job was not found", RequestID(request.Context()))
}

func writeJobQueryError(w http.ResponseWriter, request *http.Request, err error) {
	code := "invalid_job_query"
	message := "job query parameters are invalid"
	switch {
	case errors.Is(err, errInvalidJobFilter):
		code = "invalid_job_filter"
		message = "job filters are invalid"
	case errors.Is(err, errInvalidJobPageToken):
		code = "invalid_page_token"
		message = "page token is invalid"
	}
	api.WriteError(w, request, http.StatusBadRequest, code, message, RequestID(request.Context()))
}

func writeJobListError(w http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, jobrecord.ErrPageChanged):
		api.WriteError(w, request, http.StatusConflict, "job_page_changed", "job page changed; restart pagination from the first page", RequestID(request.Context()))
	case errors.Is(err, jobrecord.ErrInvalidOptions):
		api.WriteError(w, request, http.StatusBadRequest, "invalid_job_options", "job list options are invalid", RequestID(request.Context()))
	case errors.Is(err, jobrecord.ErrInvalidPageToken):
		api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
	default:
		writeJobsUnavailable(w, request)
	}
}

func writeJobsUnavailable(w http.ResponseWriter, request *http.Request) {
	api.WriteError(w, request, http.StatusServiceUnavailable, "jobs_unavailable", "jobs are temporarily unavailable", RequestID(request.Context()))
}
