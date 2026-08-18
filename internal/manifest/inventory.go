package manifest

import (
	"errors"
	"fmt"
	"sort"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

const (
	maxInventoryResourceSets = 10_000
	maxInventoryTargets      = 10_000
	maxInventoryResources    = 100_000
	maxInventoryDiagnostics  = 10_000
	maxSelectorEvaluations   = 1_000_000
)

type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type InventoryTargetIdentity struct {
	StateID string `json:"stateID"`
	Name    string `json:"name"`
	URL     string `json:"url"`
	Space   string `json:"space"`
}

type ResourceIdentity struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
}

type ResourceInventory struct {
	Kind              Kind            `json:"kind"`
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Source            source.Location `json:"source"`
	ApplicableTargets []string        `json:"applicableTargets"`
}

type ResourceSetInventory struct {
	ID        string              `json:"id"`
	Revision  string              `json:"revision,omitempty"`
	Targets   []string            `json:"targets"`
	Resources []ResourceInventory `json:"resources"`
}

type TargetInventory struct {
	Identity      InventoryTargetIdentity `json:"identity"`
	Labels        []Label                 `json:"labels"`
	ResourceSetID string                  `json:"resourceSetID"`
	Revision      string                  `json:"revision,omitempty"`
	Resources     []ResourceIdentity      `json:"resources"`
}

type Inventory struct {
	APIVersion   string                 `json:"apiVersion"`
	StateID      string                 `json:"stateID"`
	ResourceSets []ResourceSetInventory `json:"resourceSets"`
	Targets      []TargetInventory      `json:"targets"`
}

type InventoryDiagnostic struct {
	Code          string            `json:"code"`
	Message       string            `json:"message"`
	ResourceSetID string            `json:"resourceSetID,omitempty"`
	Target        string            `json:"target,omitempty"`
	Resource      *ResourceIdentity `json:"resource,omitempty"`
	Location      *source.Location  `json:"location,omitempty"`
	Related       *source.Location  `json:"related,omitempty"`
}

type InventoryError struct {
	Diagnostics []InventoryDiagnostic `json:"diagnostics"`
}

func (err *InventoryError) Error() string {
	if len(err.Diagnostics) == 0 {
		return "assignment inventory validation failed"
	}
	first := err.Diagnostics[0]
	return fmt.Sprintf("assignment inventory: %s: %s", first.Code, first.Message)
}

// BuildInventory maps targets to decoded resources without resolving resource
// references. The caller must supply a startup-validated server configuration
// and strictly decoded resource sets.
func BuildInventory(cfg *config.ServerConfig, decoded []*ResourceSet) (*Inventory, error) {
	if cfg == nil {
		return nil, errors.New("build assignment inventory: server config is nil")
	}
	if len(decoded) > maxInventoryResourceSets || len(cfg.ResourceSets) > maxInventoryResourceSets {
		return nil, newInventoryError([]InventoryDiagnostic{inventoryDiagnostic("too_many_resource_sets", "assignment inventory contains too many resource sets", "", "")})
	}
	if len(cfg.Targets) > maxInventoryTargets {
		return nil, newInventoryError([]InventoryDiagnostic{inventoryDiagnostic("too_many_targets", "assignment inventory contains too many targets", "", "")})
	}
	var diagnostics []InventoryDiagnostic
	addDiagnostic := func(issue InventoryDiagnostic) {
		if len(diagnostics) < maxInventoryDiagnostics {
			diagnostics = append(diagnostics, issue)
		}
	}
	sets := make(map[string]*ResourceSet, len(decoded))
	totalResources := 0
	for _, set := range decoded {
		if set == nil {
			addDiagnostic(inventoryDiagnostic("decoded_resource_set_nil", "decoded resource set must not be nil", "", ""))
			continue
		}
		if set.ID == "" {
			addDiagnostic(inventoryDiagnostic("decoded_resource_set_missing_id", "decoded resource set must have an id", "", ""))
			continue
		}
		if _, configured := cfg.ResourceSets[set.ID]; !configured {
			addDiagnostic(inventoryDiagnostic("extra_decoded_resource_set", "decoded resource set is not configured", set.ID, ""))
			continue
		}
		if _, duplicate := sets[set.ID]; duplicate {
			addDiagnostic(inventoryDiagnostic("duplicate_decoded_resource_set", "decoded resource-set ids must be unique", set.ID, ""))
			continue
		}
		sets[set.ID] = set
		if len(set.Resources) > maxInventoryResources-totalResources {
			addDiagnostic(inventoryDiagnostic("too_many_resources", "assignment inventory contains too many resources", set.ID, ""))
			continue
		}
		totalResources += len(set.Resources)
		seenResources := make(map[string]source.Location, len(set.Resources))
		for _, resource := range set.Resources {
			key := string(resource.Kind) + "/" + resource.Metadata.ID
			if resource.Source.ResourceSetID != set.ID {
				identity := ResourceIdentity{Kind: resource.Kind, ID: resource.Metadata.ID}
				location := resource.Source
				issue := inventoryDiagnostic("resource_source_set_mismatch", "resource source provenance does not match its resource set", set.ID, "")
				issue.Resource = &identity
				issue.Location = &location
				addDiagnostic(issue)
			}
			if prior, duplicate := seenResources[key]; duplicate {
				identity := ResourceIdentity{Kind: resource.Kind, ID: resource.Metadata.ID}
				location := resource.Source
				issue := inventoryDiagnostic("duplicate_decoded_resource", "decoded resource identities must be unique", set.ID, "")
				issue.Resource = &identity
				issue.Location = &location
				issue.Related = &prior
				addDiagnostic(issue)
				continue
			}
			seenResources[key] = resource.Source
		}
	}
	for _, setID := range sortedResourceSetConfigIDs(cfg.ResourceSets) {
		if sets[setID] == nil {
			addDiagnostic(inventoryDiagnostic("missing_decoded_resource_set", "configured resource set was not decoded", setID, ""))
		}
	}
	if len(diagnostics) != 0 {
		return nil, newInventoryError(diagnostics)
	}

	assignedTargets := make(map[string][]string, len(sets))
	targets := make(map[string]TargetInventory, len(cfg.Targets))
	for _, name := range sortedTargetConfigNames(cfg.Targets) {
		targetConfig := cfg.Targets[name]
		if sets[targetConfig.ResourceSet] == nil {
			addDiagnostic(inventoryDiagnostic("target_resource_set_unknown", "target references a resource set without decoded resources", targetConfig.ResourceSet, name))
			continue
		}
		identity, err := cfg.TargetIdentity(name)
		if err != nil {
			addDiagnostic(inventoryDiagnostic("invalid_target_identity", "target identity could not be normalized", targetConfig.ResourceSet, name))
			continue
		}
		assignedTargets[targetConfig.ResourceSet] = append(assignedTargets[targetConfig.ResourceSet], name)
		targets[name] = TargetInventory{
			Identity:      InventoryTargetIdentity{StateID: identity.StateID, Name: identity.Name, URL: identity.URL, Space: identity.Space},
			Labels:        sortedLabels(targetConfig.Labels),
			ResourceSetID: targetConfig.ResourceSet,
			Revision:      sets[targetConfig.ResourceSet].Revision,
			Resources:     make([]ResourceIdentity, 0),
		}
	}
	if len(diagnostics) != 0 {
		return nil, newInventoryError(diagnostics)
	}
	selectorEvaluations := 0
	for _, setID := range sortedResourceSetConfigIDs(cfg.ResourceSets) {
		set := sets[setID]
		targetCount := len(assignedTargets[setID])
		if targetCount != 0 && len(set.Resources) > (maxSelectorEvaluations-selectorEvaluations)/targetCount {
			return nil, newInventoryError([]InventoryDiagnostic{inventoryDiagnostic("too_many_selector_evaluations", "assignment inventory selector matrix is too large", setID, "")})
		}
		selectorEvaluations += len(set.Resources) * targetCount
	}

	inventory := &Inventory{
		APIVersion:   APIVersion,
		StateID:      cfg.StateID,
		ResourceSets: make([]ResourceSetInventory, 0, len(sets)),
		Targets:      make([]TargetInventory, 0, len(targets)),
	}
	prebuiltByTarget := make(map[string]source.Location)
	for _, setID := range sortedResourceSetConfigIDs(cfg.ResourceSets) {
		set := sets[setID]
		setTargets := append([]string{}, assignedTargets[setID]...)
		sort.Strings(setTargets)
		resources := append([]Resource(nil), set.Resources...)
		sort.SliceStable(resources, func(i, j int) bool {
			if resources[i].Kind != resources[j].Kind {
				return resources[i].Kind < resources[j].Kind
			}
			return resources[i].Metadata.ID < resources[j].Metadata.ID
		})
		setInventory := ResourceSetInventory{ID: setID, Revision: set.Revision, Targets: setTargets, Resources: make([]ResourceInventory, 0, len(resources))}
		for _, resource := range resources {
			applicable := make([]string, 0)
			identity := ResourceIdentity{Kind: resource.Kind, ID: resource.Metadata.ID}
			for _, targetName := range setTargets {
				if SelectorMatches(resource.Metadata.TargetSelector, cfg.Targets[targetName].Labels) {
					if resource.Kind == KindPrebuiltRules {
						if prior, duplicate := prebuiltByTarget[targetName]; duplicate {
							location := resource.Source
							issue := inventoryDiagnostic("multiple_applicable_prebuilt_rules", "only one PrebuiltRules resource may apply to a target", setID, targetName)
							issue.Resource = &identity
							issue.Location = &location
							issue.Related = &prior
							addDiagnostic(issue)
						} else {
							prebuiltByTarget[targetName] = resource.Source
						}
					}
					applicable = append(applicable, targetName)
					targetInventory := targets[targetName]
					targetInventory.Resources = append(targetInventory.Resources, identity)
					targets[targetName] = targetInventory
				}
			}
			setInventory.Resources = append(setInventory.Resources, ResourceInventory{
				Kind: resource.Kind, ID: resource.Metadata.ID, Name: resource.Metadata.Name,
				Source: resource.Source, ApplicableTargets: applicable,
			})
		}
		inventory.ResourceSets = append(inventory.ResourceSets, setInventory)
	}
	if len(diagnostics) != 0 {
		return nil, newInventoryError(diagnostics)
	}
	for _, name := range sortedTargetInventoryNames(targets) {
		target := targets[name]
		sort.SliceStable(target.Resources, func(i, j int) bool {
			if target.Resources[i].Kind != target.Resources[j].Kind {
				return target.Resources[i].Kind < target.Resources[j].Kind
			}
			return target.Resources[i].ID < target.Resources[j].ID
		})
		inventory.Targets = append(inventory.Targets, target)
	}
	return inventory, nil
}

func inventoryDiagnostic(code, message, resourceSetID, target string) InventoryDiagnostic {
	return InventoryDiagnostic{Code: code, Message: message, ResourceSetID: resourceSetID, Target: target}
}

func newInventoryError(diagnostics []InventoryDiagnostic) *InventoryError {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.ResourceSetID != right.ResourceSetID {
			return left.ResourceSetID < right.ResourceSetID
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		if comparison := compareResourceIdentities(left.Resource, right.Resource); comparison != 0 {
			return comparison < 0
		}
		if comparison := compareLocations(left.Location, right.Location); comparison != 0 {
			return comparison < 0
		}
		if comparison := compareLocations(left.Related, right.Related); comparison != 0 {
			return comparison < 0
		}
		return left.Message < right.Message
	})
	return &InventoryError{Diagnostics: diagnostics}
}

func compareResourceIdentities(left, right *ResourceIdentity) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if left.Kind < right.Kind {
		return -1
	}
	if left.Kind > right.Kind {
		return 1
	}
	if left.ID < right.ID {
		return -1
	}
	if left.ID > right.ID {
		return 1
	}
	return 0
}

func compareLocations(left, right *source.Location) int {
	if left == nil && right == nil {
		return 0
	}
	if left == nil {
		return -1
	}
	if right == nil {
		return 1
	}
	if left.ResourceSetID != right.ResourceSetID {
		if left.ResourceSetID < right.ResourceSetID {
			return -1
		}
		return 1
	}
	if left.RelativePath != right.RelativePath {
		if left.RelativePath < right.RelativePath {
			return -1
		}
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

func sortedResourceSetConfigIDs(values map[string]config.ResourceSetConfig) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedTargetConfigNames(values map[string]config.TargetConfig) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedTargetInventoryNames(values map[string]TargetInventory) []string {
	result := make([]string, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedLabels(values map[string]string) []Label {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]Label, 0, len(keys))
	for _, key := range keys {
		result = append(result, Label{Key: key, Value: values[key]})
	}
	return result
}
