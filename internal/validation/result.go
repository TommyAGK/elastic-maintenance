package validation

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

const ResultAPIVersion = "elastic-maintainer/validation-result/v1"

const maxDiagnostics = 10_000

type Counts struct {
	ResourceSets int `json:"resourceSets"`
	Targets      int `json:"targets"`
	Resources    int `json:"resources"`
	Files        int `json:"files"`
}

type Diagnostic struct {
	Code          string           `json:"code"`
	Message       string           `json:"message"`
	ResourceSetID string           `json:"resourceSetID,omitempty"`
	Target        string           `json:"target,omitempty"`
	Field         string           `json:"field,omitempty"`
	Location      *source.Location `json:"location,omitempty"`
	Related       *source.Location `json:"related,omitempty"`
}

type Result struct {
	APIVersion  string                   `json:"apiVersion"`
	Valid       bool                     `json:"valid"`
	Counts      Counts                   `json:"counts"`
	Diagnostics []Diagnostic             `json:"diagnostics"`
	Snapshot    *manifest.SourceSnapshot `json:"snapshot,omitempty"`
}

func scopeSuccessfulResult(snapshot *manifest.SourceSnapshot, selection Selection) (*Result, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, errors.New("copy validation snapshot")
	}
	var copy manifest.SourceSnapshot
	if err := json.Unmarshal(encoded, &copy); err != nil {
		return nil, errors.New("copy validation snapshot")
	}
	setsByID := make(map[string]manifest.ResourceSetSnapshot, len(copy.ResourceSets))
	for _, set := range copy.ResourceSets {
		setsByID[set.ID] = set
	}
	targetsByID := make(map[string]manifest.TargetSnapshot, len(copy.Targets))
	for _, target := range copy.Targets {
		targetsByID[target.Identity.Name] = target
	}
	selectedSets := make(map[string]struct{})
	for _, id := range selection.ResourceSetIDs {
		if _, exists := setsByID[id]; !exists {
			return nil, errors.New("selected resource set does not exist")
		}
		selectedSets[id] = struct{}{}
	}
	selectedTargetIDs := make(map[string]struct{})
	for _, id := range selection.TargetIDs {
		target, exists := targetsByID[id]
		if !exists {
			return nil, errors.New("selected target does not exist")
		}
		if len(selection.ResourceSetIDs) != 0 {
			if _, selected := selectedSets[target.ResourceSetID]; !selected {
				return nil, errors.New("selected target is outside selected resource sets")
			}
		} else {
			selectedSets[target.ResourceSetID] = struct{}{}
		}
		selectedTargetIDs[id] = struct{}{}
	}
	if len(selection.ResourceSetIDs) == 0 && len(selection.TargetIDs) == 0 {
		for id := range setsByID {
			selectedSets[id] = struct{}{}
		}
	}
	copy.ResourceSets = copy.ResourceSets[:0]
	for _, set := range snapshot.ResourceSets {
		if _, selected := selectedSets[set.ID]; selected {
			copy.ResourceSets = append(copy.ResourceSets, set)
		}
	}
	copy.Targets = copy.Targets[:0]
	for _, target := range snapshot.Targets {
		if _, selectedSet := selectedSets[target.ResourceSetID]; !selectedSet {
			continue
		}
		if len(selectedTargetIDs) != 0 {
			if _, selected := selectedTargetIDs[target.Identity.Name]; !selected {
				continue
			}
		}
		copy.Targets = append(copy.Targets, target)
	}
	return successfulResult(&copy), nil
}

func successfulResult(snapshot *manifest.SourceSnapshot) *Result {
	result := &Result{APIVersion: ResultAPIVersion, Valid: true, Diagnostics: make([]Diagnostic, 0), Snapshot: snapshot}
	result.Counts.ResourceSets = len(snapshot.ResourceSets)
	result.Counts.Targets = len(snapshot.Targets)
	for _, set := range snapshot.ResourceSets {
		result.Counts.Resources += len(set.Resources)
		result.Counts.Files += len(set.Files)
	}
	return result
}

func failedResult(err error) *Result {
	return &Result{APIVersion: ResultAPIVersion, Valid: false, Diagnostics: diagnosticsFromError(err)}
}

func diagnosticsFromError(err error) []Diagnostic {
	result := make([]Diagnostic, 0)
	add := func(diagnostic Diagnostic) {
		if len(result) < maxDiagnostics-1 {
			result = append(result, diagnostic)
		} else if len(result) == maxDiagnostics-1 {
			result = append(result, Diagnostic{Code: "diagnostics_truncated", Message: "additional validation diagnostics were omitted"})
		}
	}
	var manifestErr *manifest.DiagnosticsError
	if errors.As(err, &manifestErr) {
		for _, issue := range manifestErr.Diagnostics {
			location := issue.Location
			add(Diagnostic{Code: issue.Code, Message: issue.Message, Field: issue.Field, ResourceSetID: location.ResourceSetID, Location: &location, Related: issue.Related})
		}
	} else {
		var inventoryErr *manifest.InventoryError
		if errors.As(err, &inventoryErr) {
			for _, issue := range inventoryErr.Diagnostics {
				add(Diagnostic{Code: issue.Code, Message: issue.Message, ResourceSetID: issue.ResourceSetID, Target: issue.Target, Location: issue.Location, Related: issue.Related})
			}
		} else {
			var dagErr *manifest.DAGError
			if errors.As(err, &dagErr) {
				for _, issue := range dagErr.Diagnostics {
					add(Diagnostic{Code: issue.Code, Message: issue.Message, Field: issue.Field, ResourceSetID: issue.ResourceSetID, Target: issue.Target, Location: issue.Location, Related: issue.Related})
				}
			} else {
				var discoveryErr *source.DiscoveryError
				if errors.As(err, &discoveryErr) {
					location := source.Location{ResourceSetID: discoveryErr.ResourceSetID, RelativePath: discoveryErr.RelativePath}
					add(Diagnostic{Code: discoveryErr.Code, Message: "mounted source discovery failed", ResourceSetID: discoveryErr.ResourceSetID, Location: &location})
				} else {
					add(Diagnostic{Code: "invalid_inputs", Message: "mounted inputs are invalid"})
				}
			}
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := result[i], result[j]
		if left.ResourceSetID != right.ResourceSetID {
			return left.ResourceSetID < right.ResourceSetID
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if compareLocation(left.Location, right.Location) != 0 {
			return compareLocation(left.Location, right.Location) < 0
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Field < right.Field
	})
	return result
}

func compareLocation(left, right *source.Location) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if left.RelativePath < right.RelativePath {
		return -1
	}
	if left.RelativePath > right.RelativePath {
		return 1
	}
	if left.Document != right.Document {
		if left.Document < right.Document {
			return -1
		}
		return 1
	}
	if left.Line != right.Line {
		if left.Line < right.Line {
			return -1
		}
		return 1
	}
	if left.Column != right.Column {
		if left.Column < right.Column {
			return -1
		}
		return 1
	}
	return 0
}
