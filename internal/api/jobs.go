package api

import (
	"errors"
	"net/http"

	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
)

const IdempotencyKeyHeader = "Idempotency-Key"

type ValidationCreateRequest struct {
	ResourceSetIDs []string `json:"resourceSetIds,omitempty"`
	TargetIDs      []string `json:"targetIds,omitempty"`
}

type PlanCreateRequest struct {
	TargetIDs []string `json:"targetIds"`
}

type ApplyCreateRequest struct {
	Confirm bool `json:"confirm"`
}

type JobAcceptedResponse struct {
	APIVersion string   `json:"apiVersion"`
	Job        jobs.Job `json:"job"`
}

type JobListResponse struct {
	APIVersion    string     `json:"apiVersion"`
	Jobs          []jobs.Job `json:"jobs"`
	NextPageToken string     `json:"nextPageToken,omitempty"`
}

func IdempotencyKey(request *http.Request) (string, error) {
	if request == nil {
		return "", errors.New("request is required")
	}
	values := request.Header.Values(IdempotencyKeyHeader)
	if len(values) != 1 {
		return "", errors.New("exactly one idempotency key is required")
	}
	value := values[0]
	if err := jobs.ValidateIdempotencyKey(value); err != nil {
		return "", err
	}
	return value, nil
}
