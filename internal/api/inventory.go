package api

import (
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/validation"
)

type SourceSummary struct {
	ID            string                       `json:"id"`
	Revision      *manifest.RevisionProvenance `json:"revision,omitempty"`
	DesiredDigest manifest.DesiredDigest       `json:"desiredDigest"`
	FileCount     int                          `json:"fileCount"`
	ResourceCount int                          `json:"resourceCount"`
}

type SourceListResponse struct {
	APIVersion    string          `json:"apiVersion"`
	Sources       []SourceSummary `json:"sources"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
}

type SourceDetailResponse struct {
	APIVersion            string                       `json:"apiVersion"`
	Source                manifest.ResourceSetSnapshot `json:"source"`
	NextFilePageToken     string                       `json:"nextFilePageToken,omitempty"`
	NextResourcePageToken string                       `json:"nextResourcePageToken,omitempty"`
}

type TargetSummary struct {
	Identity      manifest.InventoryTargetIdentity `json:"identity"`
	Labels        []manifest.Label                 `json:"labels"`
	ResourceSetID string                           `json:"resourceSetID"`
	Revision      string                           `json:"revision,omitempty"`
	DesiredDigest manifest.DesiredDigest           `json:"desiredDigest"`
	ResourceCount int                              `json:"resourceCount"`
}

type TargetListResponse struct {
	APIVersion    string          `json:"apiVersion"`
	Targets       []TargetSummary `json:"targets"`
	NextPageToken string          `json:"nextPageToken,omitempty"`
}

type TargetDetailResponse struct {
	APIVersion            string                  `json:"apiVersion"`
	Target                manifest.TargetSnapshot `json:"target"`
	NextResourcePageToken string                  `json:"nextResourcePageToken,omitempty"`
}

type ValidationResultPage struct {
	APIVersion              string                  `json:"apiVersion"`
	Valid                   bool                    `json:"valid"`
	Counts                  validation.Counts       `json:"counts"`
	Diagnostics             []validation.Diagnostic `json:"diagnostics"`
	Sources                 []SourceSummary         `json:"sources"`
	Targets                 []TargetSummary         `json:"targets"`
	NextDiagnosticPageToken string                  `json:"nextDiagnosticPageToken,omitempty"`
	NextSourcePageToken     string                  `json:"nextSourcePageToken,omitempty"`
	NextTargetPageToken     string                  `json:"nextTargetPageToken,omitempty"`
}

type ValidationRecordResponse struct {
	APIVersion string                `json:"apiVersion"`
	Job        jobs.Job              `json:"job"`
	Selection  validation.Selection  `json:"selection"`
	Result     *ValidationResultPage `json:"result,omitempty"`
}

type ValidationListResponse struct {
	APIVersion    string     `json:"apiVersion"`
	Jobs          []jobs.Job `json:"jobs"`
	NextPageToken string     `json:"nextPageToken,omitempty"`
}
