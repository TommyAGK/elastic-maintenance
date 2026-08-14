package api

import (
	"errors"
	"net/http"

	"elastic-maintenance/internal/jobs"
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
	Job jobs.Job `json:"job"`
}

type JobListResponse struct {
	Jobs          []jobs.Job `json:"jobs"`
	NextPageToken string     `json:"nextPageToken,omitempty"`
}

func IdempotencyKey(request *http.Request) (string, error) {
	if request == nil {
		return "", errors.New("request is required")
	}
	value := request.Header.Get(IdempotencyKeyHeader)
	if err := jobs.ValidateIdempotencyKey(value); err != nil {
		return "", err
	}
	return value, nil
}
