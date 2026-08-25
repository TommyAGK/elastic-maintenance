package api

import (
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/liveinventory"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"time"
)

type TargetReadinessResponse struct {
	APIVersion    string    `json:"apiVersion"`
	TargetID      string    `json:"targetId"`
	Ready         bool      `json:"ready"`
	KibanaVersion string    `json:"kibanaVersion,omitempty"`
	CheckedAt     time.Time `json:"checkedAt"`
	FailureCode   string    `json:"failureCode,omitempty"`
}
type TargetVersionResponse struct {
	APIVersion    string    `json:"apiVersion"`
	TargetID      string    `json:"targetId"`
	KibanaVersion string    `json:"kibanaVersion"`
	CheckedAt     time.Time `json:"checkedAt"`
}
type TargetInventoryRecordResponse struct {
	APIVersion    string                            `json:"apiVersion"`
	TargetID      string                            `json:"targetId"`
	Job           jobs.Job                          `json:"job"`
	Identity      *manifest.InventoryTargetIdentity `json:"identity,omitempty"`
	KibanaVersion string                            `json:"kibanaVersion,omitempty"`
	CheckedAt     *time.Time                        `json:"checkedAt,omitempty"`
	Resources     []liveinventory.Resource          `json:"resources"`
	NextPageToken string                            `json:"nextPageToken,omitempty"`
}
