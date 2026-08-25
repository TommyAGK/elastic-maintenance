package server

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/liveinventory"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
)

type LiveInventoryBackend interface {
	Probe(context.Context, config.TargetIdentity) liveinventory.Probe
	Start(context.Context, liveinventory.StartRequest) (jobs.Job, error)
	Get(context.Context, string) (liveinventory.Record, error)
}
type unavailableLiveInventory struct{}

func (unavailableLiveInventory) Probe(context.Context, config.TargetIdentity) liveinventory.Probe {
	return liveinventory.Probe{CheckedAt: time.Now().UTC(), FailureCode: "target_inventory_unavailable"}
}
func (unavailableLiveInventory) Start(context.Context, liveinventory.StartRequest) (jobs.Job, error) {
	return jobs.Job{}, liveinventory.ErrUnavailable
}
func (unavailableLiveInventory) Get(context.Context, string) (liveinventory.Record, error) {
	return liveinventory.Record{}, liveinventory.ErrUnavailable
}

func targetLiveSubresourceHandler(targets ValidationBackend, backend LiveInventoryBackend, originBackend CredentialBackend, targetID, publicURL string, trusted []string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, exists, lookupErr := targetIdentity(r.Context(), targets, targetID)
		if lookupErr != nil {
			api.WriteError(w, r, http.StatusServiceUnavailable, "target_inventory_unavailable", "target inventory is unavailable", RequestID(r.Context()))
			return
		}
		if !exists {
			api.WriteError(w, r, http.StatusNotFound, "target_not_found", "target was not found", RequestID(r.Context()))
			return
		}
		remainder := strings.TrimPrefix(r.URL.Path, "/api/v1/targets/"+targetID+"/")
		parts := strings.Split(remainder, "/")
		switch {
		case len(parts) == 1 && parts[0] == "readiness":
			targetReadinessHandler(backend, identity).ServeHTTP(w, r)
		case len(parts) == 1 && parts[0] == "version":
			targetVersionHandler(backend, identity).ServeHTTP(w, r)
		case len(parts) == 1 && parts[0] == "inventory":
			targetInventoryStartHandler(backend, originBackend, identity, publicURL, trusted).ServeHTTP(w, r)
		case len(parts) == 2 && parts[0] == "inventory" && requestIDPattern.MatchString(parts[1]):
			targetInventoryRecordHandler(backend, targetID, parts[1]).ServeHTTP(w, r)
		default:
			protectedNotFound(w, r)
		}
	})
}
func targetIdentity(ctx context.Context, backend ValidationBackend, targetID string) (config.TargetIdentity, bool, error) {
	snapshot, err := backend.CurrentSnapshot(ctx)
	if err != nil {
		return config.TargetIdentity{}, false, err
	}
	for _, target := range snapshot.Targets {
		if target.Identity.Name == targetID {
			identity := target.Identity
			return config.TargetIdentity{StateID: identity.StateID, Name: identity.Name, URL: identity.URL, Space: identity.Space}, true, nil
		}
	}
	return config.TargetIdentity{}, false, nil
}
func targetReadinessHandler(backend LiveInventoryBackend, identity config.TargetIdentity) http.Handler {
	targetID := identity.Name
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		probe := backend.Probe(ctx, identity)
		api.WriteJSON(w, r, http.StatusOK, api.TargetReadinessResponse{APIVersion: api.Version, TargetID: targetID, Ready: probe.Ready, KibanaVersion: probe.Version, CheckedAt: probe.CheckedAt, FailureCode: probe.FailureCode})
	})
}
func targetVersionHandler(backend LiveInventoryBackend, identity config.TargetIdentity) http.Handler {
	targetID := identity.Name
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		probe := backend.Probe(ctx, identity)
		if !probe.Ready {
			api.WriteError(w, r, http.StatusServiceUnavailable, "target_unready", "target version is unavailable", RequestID(r.Context()))
			return
		}
		api.WriteJSON(w, r, http.StatusOK, api.TargetVersionResponse{APIVersion: api.Version, TargetID: targetID, KibanaVersion: probe.Version, CheckedAt: probe.CheckedAt})
	})
}
func targetInventoryStartHandler(backend LiveInventoryBackend, originBackend CredentialBackend, identity config.TargetIdentity, publicURL string, trusted []string) http.Handler {
	targetID := identity.Name
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodPost) {
			return
		}
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" {
			api.WriteError(w, r, http.StatusUnsupportedMediaType, "json_required", "Content-Type must be application/json", RequestID(r.Context()))
			return
		}
		key, err := api.IdempotencyKey(r)
		if err != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_idempotency_key", "a valid Idempotency-Key header is required", RequestID(r.Context()))
			return
		}
		var body struct{}
		if api.DecodeStrictJSON(r.Body, &body) != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_json", "request body is invalid", RequestID(r.Context()))
			return
		}
		actor, ok := auth.ActorFromContext(r.Context())
		if !ok {
			api.WriteError(w, r, http.StatusUnauthorized, "authentication_required", "authentication is required", RequestID(r.Context()))
			return
		}
		livePublic, liveTrusted, originReady := liveCredentialOrigin(r.Context(), originBackend, publicURL, trusted)
		if !originReady || !validCredentialMutationOrigin(r, livePublic, liveTrusted) {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_origin", "inventory mutation origin is invalid", RequestID(r.Context()))
			return
		}
		job, err := backend.Start(r.Context(), liveinventory.StartRequest{TargetID: targetID, Identity: identity, RequestID: RequestID(r.Context()), IdempotencyKey: key, Actor: actor})
		if err != nil {
			writeLiveStartError(w, r, err)
			return
		}
		setInventoryAuditJobID(w, job.ID)
		api.WriteJSON(w, r, http.StatusAccepted, api.JobAcceptedResponse{APIVersion: api.Version, Job: job})
	})
}
func targetInventoryRecordHandler(backend LiveInventoryBackend, targetID, jobID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		pageSize, last, err := api.ParsePagination(r.URL.Query(), "target-inventory:"+targetID+":"+jobID)
		if err != nil {
			api.WriteError(w, r, http.StatusBadRequest, "invalid_pagination", "pagination parameters are invalid", RequestID(r.Context()))
			return
		}
		record, err := backend.Get(r.Context(), jobID)
		if errors.Is(err, jobs.ErrNotFound) || err == nil && record.TargetID != targetID {
			api.WriteError(w, r, http.StatusNotFound, "inventory_not_found", "live inventory was not found", RequestID(r.Context()))
			return
		}
		if err != nil {
			api.WriteError(w, r, http.StatusServiceUnavailable, "inventory_unavailable", "live inventory service is unavailable", RequestID(r.Context()))
			return
		}
		response:=api.TargetInventoryRecordResponse{APIVersion:api.Version,TargetID:targetID,Job:record.Job,Resources:[]liveinventory.Resource{}};captured:=record.ExpectedIdentity;if captured.Name!=""{identity:=manifest.InventoryTargetIdentity{StateID:captured.StateID,Name:captured.Name,URL:captured.URL,Space:captured.Space};response.Identity=&identity}
		if record.Result != nil {
			resources := append([]liveinventory.Resource{}, record.Result.Resources...)
			sort.Slice(resources, func(i, j int) bool {
				if resources[i].Kind != resources[j].Kind {
					return resources[i].Kind < resources[j].Kind
				}
				return resources[i].ID < resources[j].ID
			})
			start := 0
			if last != "" {
				found := false
				for index, item := range resources {
					if api.PageCursorMatches("target-inventory:"+targetID+":"+jobID, string(item.Kind)+"/"+item.ID, last) {
						start = index + 1
						found = true
						break
					}
				}
				if !found {
					api.WriteError(w, r, http.StatusBadRequest, "invalid_page_token", "page token is invalid", RequestID(r.Context()))
					return
				}
			}
			end := min(start+pageSize, len(resources))
			response.Resources = append(response.Resources, resources[start:end]...)
			response.KibanaVersion = record.Result.KibanaVersion
			checked := record.Result.CheckedAt
			response.CheckedAt = &checked
			if end < len(resources) {
				item := resources[end-1]
				response.NextPageToken = api.PageToken("target-inventory:"+targetID+":"+jobID, string(item.Kind)+"/"+item.ID)
			}
		}
		api.WriteJSON(w, r, http.StatusOK, response)
	})
}
func setInventoryAuditJobID(w http.ResponseWriter, id string) {
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
func writeLiveStartError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, jobs.ErrConflict):
		api.WriteError(w, r, http.StatusConflict, "idempotency_conflict", "idempotency key was used with a different request", RequestID(r.Context()))
	case errors.Is(err, jobs.ErrQueueFull):
		api.WriteError(w, r, http.StatusTooManyRequests, "inventory_queue_full", "live inventory queue is full", RequestID(r.Context()))
	case errors.Is(err, auth.ErrPermissionDenied):
		api.WriteError(w, r, http.StatusForbidden, "permission_denied", "permission is denied", RequestID(r.Context()))
	default:
		api.WriteError(w, r, http.StatusServiceUnavailable, "inventory_unavailable", "live inventory service is unavailable", RequestID(r.Context()))
	}
}
