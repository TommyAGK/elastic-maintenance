package server

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
	"github.com/TommyAGK/elastic-maintenance/internal/validation"
)

var errValidationBackendUnavailable = errors.New("validation backend is unavailable")

type unavailableValidationBackend struct{}

func (unavailableValidationBackend) Start(context.Context, validation.StartRequest) (jobs.Job, error) {
	return jobs.Job{}, errValidationBackendUnavailable
}
func (unavailableValidationBackend) Get(context.Context, string) (validation.Record, error) {
	return validation.Record{}, errValidationBackendUnavailable
}
func (unavailableValidationBackend) List(context.Context, jobs.ListOptions) (validation.RecordPage, error) {
	return validation.RecordPage{}, errValidationBackendUnavailable
}
func (unavailableValidationBackend) CurrentSnapshot(context.Context) (*manifest.SourceSnapshot, error) {
	return nil, errValidationBackendUnavailable
}

func sourceCollectionHandler(backend ValidationBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		pageSize, last, err := api.ParsePagination(request.URL.Query(), "sources")
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		snapshot, err := backend.CurrentSnapshot(request.Context())
		if err != nil {
			writeValidationBackendError(w, request, err)
			return
		}
		summaries := make([]api.SourceSummary, 0, len(snapshot.ResourceSets))
		for _, set := range snapshot.ResourceSets {
			summaries = append(summaries, api.SourceSummary{ID: set.ID, Revision: set.Revision, DesiredDigest: set.DesiredDigest, FileCount: len(set.Files), ResourceCount: len(set.Resources)})
		}
		sort.SliceStable(summaries, func(i, j int) bool { return summaries[i].ID < summaries[j].ID })
		start, ok := pageStartSource(summaries, "sources", last)
		if !ok {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
			return
		}
		end := min(start+pageSize, len(summaries))
		next := ""
		if end < len(summaries) {
			next = api.PageToken("sources", summaries[end-1].ID)
		}
		api.WriteJSON(w, request, http.StatusOK, api.SourceListResponse{APIVersion: api.Version, Sources: append([]api.SourceSummary{}, summaries[start:end]...), NextPageToken: next})
	})
}

func sourceDetailHandler(backend ValidationBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		id, ok := singlePathID(request.URL.Path, "/api/v1/sources/")
		if !ok {
			protectedNotFound(w, request)
			return
		}
		allowed := map[string]bool{"filePageSize": true, "filePageToken": true, "resourcePageSize": true, "resourcePageToken": true}
		fileSize, fileLast, err := api.ParseNamedPagination(request.URL.Query(), "source-files:"+id, "filePageSize", "filePageToken", allowed)
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		resourceSize, resourceLast, err := api.ParseNamedPagination(request.URL.Query(), "source-resources:"+id, "resourcePageSize", "resourcePageToken", allowed)
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		snapshot, err := backend.CurrentSnapshot(request.Context())
		if err != nil {
			writeValidationBackendError(w, request, err)
			return
		}
		for _, set := range snapshot.ResourceSets {
			if set.ID == id {
				fileStart, valid := pageStartRawFiles(set.Files, "source-files:"+id, fileLast)
				if !valid {
					api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
					return
				}
				resourceStart, valid := pageStartResources(set.Resources, "source-resources:"+id, resourceLast)
				if !valid {
					api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
					return
				}
				fileEnd, resourceEnd := min(fileStart+fileSize, len(set.Files)), min(resourceStart+resourceSize, len(set.Resources))
				response := api.SourceDetailResponse{APIVersion: api.Version, Source: set}
				response.Source.Files = append([]source.RawFileDigest{}, set.Files[fileStart:fileEnd]...)
				response.Source.Resources = append([]manifest.ResourceSnapshot{}, set.Resources[resourceStart:resourceEnd]...)
				if fileEnd < len(set.Files) {
					response.NextFilePageToken = api.PageToken("source-files:"+id, set.Files[fileEnd-1].RelativePath)
				}
				if resourceEnd < len(set.Resources) {
					response.NextResourcePageToken = api.PageToken("source-resources:"+id, identityKeyForPage(set.Resources[resourceEnd-1].Resource))
				}
				api.WriteJSON(w, request, http.StatusOK, response)
				return
			}
		}
		api.WriteError(w, request, http.StatusNotFound, "source_not_found", "source was not found", RequestID(request.Context()))
	})
}

func targetCollectionHandler(backend ValidationBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		pageSize, last, err := api.ParsePagination(request.URL.Query(), "targets")
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		snapshot, err := backend.CurrentSnapshot(request.Context())
		if err != nil {
			writeValidationBackendError(w, request, err)
			return
		}
		summaries := make([]api.TargetSummary, 0, len(snapshot.Targets))
		for _, target := range snapshot.Targets {
			summaries = append(summaries, api.TargetSummary{Identity: target.Identity, Labels: target.Labels, ResourceSetID: target.ResourceSetID, Revision: target.Revision, DesiredDigest: target.DesiredDigest, ResourceCount: len(target.Resources)})
		}
		sort.SliceStable(summaries, func(i, j int) bool { return summaries[i].Identity.Name < summaries[j].Identity.Name })
		start, ok := pageStartTarget(summaries, "targets", last)
		if !ok {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
			return
		}
		end := min(start+pageSize, len(summaries))
		next := ""
		if end < len(summaries) {
			next = api.PageToken("targets", summaries[end-1].Identity.Name)
		}
		api.WriteJSON(w, request, http.StatusOK, api.TargetListResponse{APIVersion: api.Version, Targets: append([]api.TargetSummary{}, summaries[start:end]...), NextPageToken: next})
	})
}

func targetPhaseOneHandler(backend ValidationBackend, authorizer auth.Authorizer) http.Handler {
	detail := authorize(authorizer, auth.PermissionTargetsRead, targetDetailHandler(backend))
	fallback := targetSubresourceHandler(authorizer)
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/targets/")
		if remainder != "" && !strings.Contains(remainder, "/") {
			detail.ServeHTTP(w, request)
			return
		}
		fallback.ServeHTTP(w, request)
	})
}

func targetDetailHandler(backend ValidationBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		id, ok := singlePathID(request.URL.Path, "/api/v1/targets/")
		if !ok {
			protectedNotFound(w, request)
			return
		}
		pageSize, last, err := api.ParsePagination(request.URL.Query(), "target-resources:"+id)
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		snapshot, err := backend.CurrentSnapshot(request.Context())
		if err != nil {
			writeValidationBackendError(w, request, err)
			return
		}
		for _, target := range snapshot.Targets {
			if target.Identity.Name == id {
				start, valid := pageStartResources(target.Resources, "target-resources:"+id, last)
				if !valid {
					api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
					return
				}
				end := min(start+pageSize, len(target.Resources))
				response := api.TargetDetailResponse{APIVersion: api.Version, Target: target}
				response.Target.Resources = append([]manifest.ResourceSnapshot{}, target.Resources[start:end]...)
				if end < len(target.Resources) {
					response.NextResourcePageToken = api.PageToken("target-resources:"+id, identityKeyForPage(target.Resources[end-1].Resource))
				}
				api.WriteJSON(w, request, http.StatusOK, response)
				return
			}
		}
		api.WriteError(w, request, http.StatusNotFound, "target_not_found", "target was not found", RequestID(request.Context()))
	})
}

func validationCollectionHandler(backend ValidationBackend, authorizer auth.Authorizer) http.Handler {
	read := authorize(authorizer, auth.PermissionValidationsRead, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		pageSize, last, err := api.ParsePagination(request.URL.Query(), "validations")
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		page, err := backend.List(request.Context(), jobs.ListOptions{Types: []jobs.Type{jobs.TypeValidation}, PageSize: pageSize, PageToken: last})
		if errors.Is(err, errValidationBackendUnavailable) {
			api.WriteError(w, request, http.StatusServiceUnavailable, "validation_unavailable", "validation service is unavailable", RequestID(request.Context()))
			return
		}
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
			return
		}
		items := make([]jobs.Job, 0, len(page.Records))
		for _, record := range page.Records {
			items = append(items, record.Job)
		}
		next := api.PageToken("validations", page.NextPageToken)
		api.WriteJSON(w, request, http.StatusOK, api.ValidationListResponse{APIVersion: api.Version, Jobs: items, NextPageToken: next})
	}))
	create := authorize(authorizer, auth.PermissionValidationsCreate, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			api.WriteError(w, request, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json", RequestID(request.Context()))
			return
		}
		key, err := api.IdempotencyKey(request)
		if err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_idempotency_key", "a valid unique Idempotency-Key header is required", RequestID(request.Context()))
			return
		}
		var body api.ValidationCreateRequest
		if err := api.DecodeStrictJSON(request.Body, &body); err != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_json", "request body is invalid", RequestID(request.Context()))
			return
		}
		actor, ok := auth.ActorFromContext(request.Context())
		if !ok {
			api.WriteError(w, request, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(request.Context()))
			return
		}
		job, err := backend.Start(request.Context(), validation.StartRequest{ActorSubject: actor.Subject, RequestID: RequestID(request.Context()), IdempotencyKey: key, Selection: validation.Selection{ResourceSetIDs: body.ResourceSetIDs, TargetIDs: body.TargetIDs}})
		if err != nil {
			writeValidationStartError(w, request, err)
			return
		}
		api.WriteJSON(w, request, http.StatusAccepted, api.JobAcceptedResponse{APIVersion: api.Version, Job: job})
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.Method {
		case http.MethodGet, http.MethodHead:
			read.ServeHTTP(w, request)
		case http.MethodPost:
			create.ServeHTTP(w, request)
		default:
			allowMethods(w, request, http.MethodGet, http.MethodHead, http.MethodPost)
		}
	})
}

func validationDetailHandler(backend ValidationBackend) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if !allowMethods(w, request, http.MethodGet, http.MethodHead) {
			return
		}
		id, ok := singlePathID(request.URL.Path, "/api/v1/validations/")
		if !ok {
			protectedNotFound(w, request)
			return
		}
		allowed := map[string]bool{"diagnosticPageSize": true, "diagnosticPageToken": true, "sourcePageSize": true, "sourcePageToken": true, "targetPageSize": true, "targetPageToken": true}
		diagnosticSize, diagnosticLast, parseErr := api.ParseNamedPagination(request.URL.Query(), "validation-diagnostics:"+id, "diagnosticPageSize", "diagnosticPageToken", allowed)
		if parseErr != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		sourceSize, sourceLast, parseErr := api.ParseNamedPagination(request.URL.Query(), "validation-sources:"+id, "sourcePageSize", "sourcePageToken", allowed)
		if parseErr != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		targetSize, targetLast, parseErr := api.ParseNamedPagination(request.URL.Query(), "validation-targets:"+id, "targetPageSize", "targetPageToken", allowed)
		if parseErr != nil {
			api.WriteError(w, request, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(request.Context()))
			return
		}
		record, err := backend.Get(request.Context(), id)
		if errors.Is(err, jobs.ErrNotFound) {
			api.WriteError(w, request, http.StatusNotFound, "validation_not_found", "validation was not found", RequestID(request.Context()))
			return
		}
		if err != nil {
			api.WriteError(w, request, http.StatusServiceUnavailable, "validation_unavailable", "validation service is unavailable", RequestID(request.Context()))
			return
		}
		response := api.ValidationRecordResponse{APIVersion: api.Version, Job: record.Job, Selection: record.Selection}
		if record.Result != nil {
			page := &api.ValidationResultPage{APIVersion: record.Result.APIVersion, Valid: record.Result.Valid, Counts: record.Result.Counts, Diagnostics: make([]validation.Diagnostic, 0), Sources: make([]api.SourceSummary, 0), Targets: make([]api.TargetSummary, 0)}
			diagnosticStart, valid := pageStartIndex(len(record.Result.Diagnostics), diagnosticLast)
			if !valid {
				api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
				return
			}
			diagnosticEnd := min(diagnosticStart+diagnosticSize, len(record.Result.Diagnostics))
			page.Diagnostics = append(page.Diagnostics, record.Result.Diagnostics[diagnosticStart:diagnosticEnd]...)
			if diagnosticEnd < len(record.Result.Diagnostics) {
				page.NextDiagnosticPageToken = api.PageToken("validation-diagnostics:"+id, strconv.Itoa(diagnosticEnd))
			}
			if record.Result.Snapshot != nil {
				sourceSummaries := sourceSummaries(record.Result.Snapshot)
				sourceStart, valid := pageStartSource(sourceSummaries, "validation-sources:"+id, sourceLast)
				if !valid {
					api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
					return
				}
				sourceEnd := min(sourceStart+sourceSize, len(sourceSummaries))
				page.Sources = append(page.Sources, sourceSummaries[sourceStart:sourceEnd]...)
				if sourceEnd < len(sourceSummaries) {
					page.NextSourcePageToken = api.PageToken("validation-sources:"+id, sourceSummaries[sourceEnd-1].ID)
				}
				targetSummaries := targetSummaries(record.Result.Snapshot)
				targetStart, valid := pageStartTarget(targetSummaries, "validation-targets:"+id, targetLast)
				if !valid {
					api.WriteError(w, request, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(request.Context()))
					return
				}
				targetEnd := min(targetStart+targetSize, len(targetSummaries))
				page.Targets = append(page.Targets, targetSummaries[targetStart:targetEnd]...)
				if targetEnd < len(targetSummaries) {
					page.NextTargetPageToken = api.PageToken("validation-targets:"+id, targetSummaries[targetEnd-1].Identity.Name)
				}
			}
			response.Result = page
		}
		api.WriteJSON(w, request, http.StatusOK, response)
	})
}

func singlePathID(path, prefix string) (string, bool) {
	value := strings.TrimPrefix(path, prefix)
	return value, value != "" && value != path && !strings.Contains(value, "/")
}
func pageStartSource(values []api.SourceSummary, endpoint, last string) (int, bool) {
	if last == "" {
		return 0, true
	}
	for i := range values {
		if api.PageCursorMatches(endpoint, values[i].ID, last) {
			return i + 1, true
		}
	}
	return 0, false
}
func pageStartTarget(values []api.TargetSummary, endpoint, last string) (int, bool) {
	if last == "" {
		return 0, true
	}
	for i := range values {
		if api.PageCursorMatches(endpoint, values[i].Identity.Name, last) {
			return i + 1, true
		}
	}
	return 0, false
}
func pageStartRawFiles(values []source.RawFileDigest, endpoint, last string) (int, bool) {
	if last == "" {
		return 0, true
	}
	for i := range values {
		if api.PageCursorMatches(endpoint, values[i].RelativePath, last) {
			return i + 1, true
		}
	}
	return 0, false
}
func pageStartResources(values []manifest.ResourceSnapshot, endpoint, last string) (int, bool) {
	if last == "" {
		return 0, true
	}
	for i := range values {
		if api.PageCursorMatches(endpoint, identityKeyForPage(values[i].Resource), last) {
			return i + 1, true
		}
	}
	return 0, false
}
func pageStartIndex(length int, last string) (int, bool) {
	if last == "" {
		return 0, true
	}
	value, err := strconv.Atoi(last)
	return value, err == nil && value >= 0 && value <= length
}
func identityKeyForPage(identity manifest.ResourceIdentity) string {
	return string(identity.Kind) + "/" + identity.ID
}
func sourceSummaries(snapshot *manifest.SourceSnapshot) []api.SourceSummary {
	result := make([]api.SourceSummary, 0, len(snapshot.ResourceSets))
	for _, set := range snapshot.ResourceSets {
		result = append(result, api.SourceSummary{ID: set.ID, Revision: set.Revision, DesiredDigest: set.DesiredDigest, FileCount: len(set.Files), ResourceCount: len(set.Resources)})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}
func targetSummaries(snapshot *manifest.SourceSnapshot) []api.TargetSummary {
	result := make([]api.TargetSummary, 0, len(snapshot.Targets))
	for _, target := range snapshot.Targets {
		result = append(result, api.TargetSummary{Identity: target.Identity, Labels: target.Labels, ResourceSetID: target.ResourceSetID, Revision: target.Revision, DesiredDigest: target.DesiredDigest, ResourceCount: len(target.Resources)})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Identity.Name < result[j].Identity.Name })
	return result
}

func writeValidationBackendError(w http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, errValidationBackendUnavailable) || errors.Is(err, jobs.ErrQueueClosed) {
		api.WriteError(w, request, http.StatusServiceUnavailable, "validation_unavailable", "validation service is unavailable", RequestID(request.Context()))
		return
	}
	api.WriteError(w, request, http.StatusUnprocessableEntity, "mounted_inputs_invalid", "mounted inputs could not be validated", RequestID(request.Context()))
}
func writeValidationStartError(w http.ResponseWriter, request *http.Request, err error) {
	switch {
	case errors.Is(err, jobs.ErrConflict):
		api.WriteError(w, request, http.StatusConflict, "idempotency_conflict", "idempotency key was used with a different request", RequestID(request.Context()))
	case errors.Is(err, jobs.ErrQueueFull):
		api.WriteError(w, request, http.StatusTooManyRequests, "validation_queue_full", "validation queue is full", RequestID(request.Context()))
	case errors.Is(err, jobs.ErrQueueClosed), errors.Is(err, errValidationBackendUnavailable):
		api.WriteError(w, request, http.StatusServiceUnavailable, "validation_unavailable", "validation service is unavailable", RequestID(request.Context()))
	default:
		api.WriteError(w, request, http.StatusBadRequest, "invalid_validation_request", "validation request is invalid", RequestID(request.Context()))
	}
}
