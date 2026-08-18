package manifest

import (
	"container/heap"
	"errors"
	"fmt"
	"sort"

	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

const (
	maxDAGEdges           = 1_000_000
	maxDAGProjectionEdges = 1_000_000
	maxDAGDiagnostics     = 10_000
	maxCyclePath          = 32
)

type DependencyOrigin string

const (
	DependencyExplicit           DependencyOrigin = "explicit"
	DependencyPackageIntegration DependencyOrigin = "packagePolicy.integrationRef"
	DependencyPackageAgentPolicy DependencyOrigin = "packagePolicy.agentPolicyRef"
)

type DependencyEdge struct {
	Dependent    ResourceIdentity `json:"dependent"`
	Prerequisite ResourceIdentity `json:"prerequisite"`
	Origin       DependencyOrigin `json:"origin"`
}

type DAGNode struct {
	Resource ResourceIdentity `json:"resource"`
	Source   source.Location  `json:"source"`
}

type TargetDAG struct {
	Target        string           `json:"target"`
	ResourceSetID string           `json:"resourceSetID"`
	Revision      string           `json:"revision,omitempty"`
	Nodes         []DAGNode        `json:"nodes"`
	Edges         []DependencyEdge `json:"edges"`
}

type DAGSet struct {
	APIVersion string      `json:"apiVersion"`
	Targets    []TargetDAG `json:"targets"`
}

type DAGDiagnostic struct {
	Code          string             `json:"code"`
	Message       string             `json:"message"`
	Field         string             `json:"field,omitempty"`
	ResourceSetID string             `json:"resourceSetID,omitempty"`
	Target        string             `json:"target,omitempty"`
	Resource      *ResourceIdentity  `json:"resource,omitempty"`
	Dependency    *ResourceIdentity  `json:"dependency,omitempty"`
	Location      *source.Location   `json:"location,omitempty"`
	Related       *source.Location   `json:"related,omitempty"`
	Cycle         []ResourceIdentity `json:"cycle,omitempty"`
}

type DAGError struct {
	Diagnostics []DAGDiagnostic `json:"diagnostics"`
}

func (err *DAGError) Error() string {
	if len(err.Diagnostics) == 0 {
		return "dependency graph validation failed"
	}
	first := err.Diagnostics[0]
	return fmt.Sprintf("dependency graph: %s: %s", first.Code, first.Message)
}

type indexedResource struct {
	resource Resource
	identity ResourceIdentity
}

type setGraph struct {
	revision         string
	resources        map[string]indexedResource
	edges            []DependencyEdge
	edgesByDependent map[string][]DependencyEdge
}

// ResolveTargetDAGs validates resource references and builds a stable
// prerequisite-first DAG for every target in an assignment inventory.
func ResolveTargetDAGs(decoded []*ResourceSet, inventory *Inventory) (*DAGSet, error) {
	if inventory == nil {
		return nil, errors.New("resolve target DAGs: inventory is nil")
	}
	if len(decoded) > maxInventoryResourceSets || len(inventory.Targets) > maxInventoryTargets {
		return nil, newDAGError([]DAGDiagnostic{dagDiagnostic("dag_input_too_large", "dependency graph input exceeds configured limits", "", "")})
	}
	var diagnostics []DAGDiagnostic
	addDiagnostic := func(issue DAGDiagnostic) {
		appendDAGDiagnostic(&diagnostics, issue)
	}

	sets := append([]*ResourceSet(nil), decoded...)
	sort.SliceStable(sets, func(i, j int) bool {
		if sets[i] == nil {
			return sets[j] != nil
		}
		if sets[j] == nil {
			return false
		}
		return sets[i].ID < sets[j].ID
	})
	graphs := make(map[string]*setGraph, len(sets))
	totalResources := 0
	for _, set := range sets {
		if set == nil || set.ID == "" {
			addDiagnostic(dagDiagnostic("invalid_decoded_resource_set", "decoded resource set is invalid", "", ""))
			continue
		}
		if graphs[set.ID] != nil {
			addDiagnostic(dagDiagnostic("duplicate_decoded_resource_set", "decoded resource-set ids must be unique", set.ID, ""))
			continue
		}
		if len(set.Resources) > maxInventoryResources-totalResources {
			addDiagnostic(dagDiagnostic("dag_input_too_large", "dependency graph contains too many resources", set.ID, ""))
			continue
		}
		totalResources += len(set.Resources)
		graph := &setGraph{revision: set.Revision, resources: make(map[string]indexedResource, len(set.Resources)), edges: make([]DependencyEdge, 0), edgesByDependent: make(map[string][]DependencyEdge)}
		resources := append([]Resource(nil), set.Resources...)
		sort.SliceStable(resources, func(i, j int) bool {
			return lessIdentity(resourceIdentity(resources[i]), resourceIdentity(resources[j]))
		})
		for _, resource := range resources {
			identity := resourceIdentity(resource)
			key := identityKey(identity)
			if _, duplicate := graph.resources[key]; duplicate {
				issue := dagDiagnostic("duplicate_decoded_resource", "decoded resource identities must be unique", set.ID, "")
				issue.Resource = identityPointer(identity)
				location := resource.Source
				issue.Location = &location
				addDiagnostic(issue)
				continue
			}
			graph.resources[key] = indexedResource{resource: resource, identity: identity}
		}
		graphs[set.ID] = graph
	}

	for _, issue := range validateDAGInventory(graphs, inventory) {
		addDiagnostic(issue)
	}
	if len(diagnostics) != 0 {
		return nil, newDAGError(diagnostics)
	}

	totalEdges := 0
	totalReferences := 0
	for _, setID := range sortedGraphSetIDs(graphs) {
		graph := graphs[setID]
		for _, key := range sortedIndexedResourceKeys(graph.resources) {
			indexed := graph.resources[key]
			seen := make(map[string]DependencyOrigin)
			for _, reference := range indexed.resource.Metadata.DependsOn {
				totalReferences++
				if totalReferences > maxDAGEdges || totalEdges >= maxDAGEdges {
					return nil, newDAGError([]DAGDiagnostic{dagDiagnostic("too_many_dependency_edges", "dependency graph contains too many edges", setID, "")})
				}
				if addDependencyEdge(setID, indexed, reference, DependencyExplicit, "metadata.dependsOn", graph, seen, &diagnostics) {
					totalEdges++
				}
			}
			if indexed.identity.Kind != KindPackagePolicy {
				continue
			}
			spec, ok := indexed.resource.Spec.(PackagePolicySpec)
			if !ok {
				issue := dagDiagnostic("invalid_package_policy_spec", "PackagePolicy has an invalid decoded spec", setID, "")
				issue.Resource = identityPointer(indexed.identity)
				location := indexed.resource.Source
				issue.Location = &location
				addDiagnostic(issue)
				continue
			}
			for _, automatic := range []struct {
				reference Reference
				origin    DependencyOrigin
				field     string
			}{
				{spec.IntegrationRef, DependencyPackageIntegration, "spec.integrationRef"},
				{spec.AgentPolicyRef, DependencyPackageAgentPolicy, "spec.agentPolicyRef"},
			} {
				totalReferences++
				if totalReferences > maxDAGEdges || totalEdges >= maxDAGEdges {
					return nil, newDAGError([]DAGDiagnostic{dagDiagnostic("too_many_dependency_edges", "dependency graph contains too many edges", setID, "")})
				}
				if addDependencyEdge(setID, indexed, automatic.reference, automatic.origin, automatic.field, graph, seen, &diagnostics) {
					totalEdges++
				}
			}
		}
		if cycle := findDependencyCycle(graph); len(cycle) != 0 {
			first := graph.resources[identityKey(cycle[0])]
			issue := dagDiagnostic("dependency_cycle", "resource dependencies contain a cycle", setID, "")
			issue.Resource = identityPointer(cycle[0])
			location := first.resource.Source
			issue.Location = &location
			if len(cycle) > maxCyclePath {
				cycle = cycle[:maxCyclePath]
			}
			issue.Cycle = append([]ResourceIdentity(nil), cycle...)
			addDiagnostic(issue)
		}
	}

	inventoryTargets := append([]TargetInventory(nil), inventory.Targets...)
	sort.SliceStable(inventoryTargets, func(i, j int) bool { return inventoryTargets[i].Identity.Name < inventoryTargets[j].Identity.Name })
	activeByTarget := make(map[string]map[string]struct{}, len(inventoryTargets))
	projectedEdges := 0
	for _, target := range inventoryTargets {
		active := make(map[string]struct{}, len(target.Resources))
		for _, identity := range target.Resources {
			active[identityKey(identity)] = struct{}{}
		}
		activeByTarget[target.Identity.Name] = active
		graph := graphs[target.ResourceSetID]
		if graph == nil {
			addDiagnostic(dagDiagnostic("target_resource_set_unknown", "target inventory references an unknown resource set", target.ResourceSetID, target.Identity.Name))
			continue
		}
		for _, dependentKey := range sortedActiveResourceKeys(active, graph.resources) {
			edges := graph.edgesByDependent[dependentKey]
			if len(edges) > maxDAGProjectionEdges-projectedEdges {
				return nil, newDAGError([]DAGDiagnostic{dagDiagnostic("dag_projection_too_large", "per-target dependency graph projection is too large", target.ResourceSetID, target.Identity.Name)})
			}
			projectedEdges += len(edges)
			for _, edge := range edges {
				if _, prerequisiteActive := active[identityKey(edge.Prerequisite)]; prerequisiteActive {
					continue
				}
				dependent := graph.resources[identityKey(edge.Dependent)]
				prerequisite := graph.resources[identityKey(edge.Prerequisite)]
				issue := dagDiagnostic("cross_selector_reference", "applicable resource depends on a resource that is not applicable to the same target", target.ResourceSetID, target.Identity.Name)
				issue.Field = string(edge.Origin)
				issue.Resource = identityPointer(edge.Dependent)
				issue.Dependency = identityPointer(edge.Prerequisite)
				location, related := dependent.resource.Source, prerequisite.resource.Source
				issue.Location, issue.Related = &location, &related
				addDiagnostic(issue)
			}
		}
	}
	if len(diagnostics) != 0 {
		return nil, newDAGError(diagnostics)
	}

	result := &DAGSet{APIVersion: APIVersion, Targets: make([]TargetDAG, 0, len(inventoryTargets))}
	for _, target := range inventoryTargets {
		graph := graphs[target.ResourceSetID]
		active := activeByTarget[target.Identity.Name]
		nodes := topologicalNodes(graph, active)
		edges := make([]DependencyEdge, 0)
		for _, dependentKey := range sortedActiveResourceKeys(active, graph.resources) {
			for _, edge := range graph.edgesByDependent[dependentKey] {
				if _, ok := active[identityKey(edge.Prerequisite)]; ok {
					edges = append(edges, edge)
				}
			}
		}
		sortDependencyEdges(edges)
		result.Targets = append(result.Targets, TargetDAG{Target: target.Identity.Name, ResourceSetID: target.ResourceSetID, Revision: graph.revision, Nodes: nodes, Edges: edges})
	}
	return result, nil
}

func validateDAGInventory(graphs map[string]*setGraph, inventory *Inventory) []DAGDiagnostic {
	var diagnostics []DAGDiagnostic
	add := func(issue DAGDiagnostic) { appendDAGDiagnostic(&diagnostics, issue) }
	if inventory.APIVersion != APIVersion {
		add(dagDiagnostic("stale_inventory_version", "assignment inventory API version is not supported", "", ""))
	}
	if len(inventory.ResourceSets) > maxInventoryResourceSets || len(inventory.Targets) > maxInventoryTargets {
		return []DAGDiagnostic{dagDiagnostic("dag_input_too_large", "assignment inventory exceeds dependency graph limits", "", "")}
	}
	targets := make(map[string]TargetInventory, len(inventory.Targets))
	targetLabels := make(map[string]map[string]string, len(inventory.Targets))
	expectedByTarget := make(map[string]map[string]struct{}, len(inventory.Targets))
	for _, target := range inventory.Targets {
		name := target.Identity.Name
		if name == "" || targets[name].Identity.Name != "" {
			add(dagDiagnostic("invalid_inventory_target", "target inventory identities must be present and unique", target.ResourceSetID, name))
			continue
		}
		targets[name] = target
		expectedByTarget[name] = make(map[string]struct{})
		labels := make(map[string]string, len(target.Labels))
		for _, label := range target.Labels {
			if _, duplicate := labels[label.Key]; duplicate {
				add(dagDiagnostic("duplicate_inventory_label", "target inventory label keys must be unique", target.ResourceSetID, name))
				continue
			}
			labels[label.Key] = label.Value
		}
		targetLabels[name] = labels
		if target.Identity.StateID != inventory.StateID {
			add(dagDiagnostic("stale_inventory_identity", "target identity state does not match assignment inventory", target.ResourceSetID, name))
		}
		graph := graphs[target.ResourceSetID]
		if graph == nil {
			add(dagDiagnostic("target_resource_set_unknown", "target inventory references an unknown resource set", target.ResourceSetID, name))
		} else if target.Revision != graph.revision {
			add(dagDiagnostic("stale_inventory_revision", "target inventory revision does not match decoded resources", target.ResourceSetID, name))
		}
	}

	inventorySets := make(map[string]ResourceSetInventory, len(inventory.ResourceSets))
	totalMemberships := 0
	totalSelectorEvaluations := 0
	for _, setInventory := range inventory.ResourceSets {
		setID := setInventory.ID
		if setID == "" || inventorySets[setID].ID != "" {
			add(dagDiagnostic("invalid_inventory_resource_set", "resource-set inventory ids must be present and unique", setID, ""))
			continue
		}
		inventorySets[setID] = setInventory
		graph := graphs[setID]
		if graph == nil {
			add(dagDiagnostic("inventory_resource_set_unknown", "assignment inventory contains an unknown resource set", setID, ""))
			continue
		}
		if setInventory.Revision != graph.revision {
			add(dagDiagnostic("stale_inventory_revision", "resource-set inventory revision does not match decoded resources", setID, ""))
		}
		expectedSetTargets := make([]string, 0)
		for name, target := range targets {
			if target.ResourceSetID == setID {
				expectedSetTargets = append(expectedSetTargets, name)
			}
		}
		sort.Strings(expectedSetTargets)
		actualSetTargets := append([]string(nil), setInventory.Targets...)
		sort.Strings(actualSetTargets)
		if !equalStrings(expectedSetTargets, actualSetTargets) {
			add(dagDiagnostic("stale_inventory_targets", "resource-set target membership is inconsistent", setID, ""))
		}
		seenResources := make(map[string]struct{}, len(setInventory.Resources))
		for _, resourceInventory := range setInventory.Resources {
			identity := ResourceIdentity{Kind: resourceInventory.Kind, ID: resourceInventory.ID}
			key := identityKey(identity)
			if _, duplicate := seenResources[key]; duplicate {
				issue := dagDiagnostic("duplicate_inventory_resource", "resource inventory identities must be unique", setID, "")
				issue.Resource = identityPointer(identity)
				add(issue)
				continue
			}
			seenResources[key] = struct{}{}
			indexed, exists := graph.resources[key]
			if !exists {
				issue := dagDiagnostic("unknown_inventory_resource", "resource inventory identity is not present in decoded resources", setID, "")
				issue.Resource = identityPointer(identity)
				add(issue)
				continue
			}
			if resourceInventory.Source != indexed.resource.Source {
				issue := dagDiagnostic("stale_inventory_source", "resource inventory source does not match decoded resources", setID, "")
				issue.Resource = identityPointer(identity)
				add(issue)
			}
			actualApplicable := make(map[string]struct{}, len(resourceInventory.ApplicableTargets))
			for _, targetName := range resourceInventory.ApplicableTargets {
				totalMemberships++
				if totalMemberships > maxSelectorEvaluations {
					return []DAGDiagnostic{dagDiagnostic("dag_input_too_large", "assignment inventory applicability matrix is too large", setID, "")}
				}
				target, targetExists := targets[targetName]
				if !targetExists || target.ResourceSetID != setID {
					issue := dagDiagnostic("invalid_inventory_applicability", "resource applicability references an invalid target", setID, targetName)
					issue.Resource = identityPointer(identity)
					add(issue)
					continue
				}
				if _, duplicate := actualApplicable[targetName]; duplicate {
					issue := dagDiagnostic("duplicate_inventory_applicability", "resource applicability target names must be unique", setID, targetName)
					issue.Resource = identityPointer(identity)
					add(issue)
					continue
				}
				actualApplicable[targetName] = struct{}{}
			}
			computedApplicable := make(map[string]struct{})
			for _, targetName := range sortedTargetInventoryNames(targets) {
				target := targets[targetName]
				if target.ResourceSetID != setID {
					continue
				}
				totalSelectorEvaluations++
				if totalSelectorEvaluations > maxSelectorEvaluations {
					return []DAGDiagnostic{dagDiagnostic("dag_input_too_large", "selector applicability matrix is too large", setID, "")}
				}
				if SelectorMatches(indexed.resource.Metadata.TargetSelector, targetLabels[targetName]) {
					computedApplicable[targetName] = struct{}{}
					expectedByTarget[targetName][key] = struct{}{}
				}
			}
			if !equalStringSets(actualApplicable, computedApplicable) {
				issue := dagDiagnostic("stale_inventory_selector", "resource applicability does not match its selector", setID, "")
				issue.Resource = identityPointer(identity)
				add(issue)
			}
		}
		for key, indexed := range graph.resources {
			if _, exists := seenResources[key]; !exists {
				issue := dagDiagnostic("missing_inventory_resource", "decoded resource is missing from assignment inventory", setID, "")
				issue.Resource = identityPointer(indexed.identity)
				add(issue)
			}
		}
	}
	for setID := range graphs {
		if _, exists := inventorySets[setID]; !exists {
			add(dagDiagnostic("missing_inventory_resource_set", "decoded resource set is missing from assignment inventory", setID, ""))
		}
	}
	for name, target := range targets {
		actual := make(map[string]struct{}, len(target.Resources))
		graph := graphs[target.ResourceSetID]
		for _, identity := range target.Resources {
			key := identityKey(identity)
			if _, duplicate := actual[key]; duplicate {
				issue := dagDiagnostic("duplicate_inventory_target_resource", "target resource identities must be unique", target.ResourceSetID, name)
				issue.Resource = identityPointer(identity)
				add(issue)
				continue
			}
			actual[key] = struct{}{}
			if graph == nil || graph.resources[key].identity != identity {
				issue := dagDiagnostic("unknown_inventory_target_resource", "target resource identity is not present in decoded resources", target.ResourceSetID, name)
				issue.Resource = identityPointer(identity)
				add(issue)
			}
		}
		if !equalStringSets(actual, expectedByTarget[name]) {
			add(dagDiagnostic("stale_inventory_applicability", "target resource membership is inconsistent with resource applicability", target.ResourceSetID, name))
		}
	}
	return diagnostics
}

func addDependencyEdge(setID string, dependent indexedResource, reference Reference, origin DependencyOrigin, field string, graph *setGraph, seen map[string]DependencyOrigin, diagnostics *[]DAGDiagnostic) bool {
	prerequisite := ResourceIdentity{Kind: reference.Kind, ID: reference.ID}
	issue := dagDiagnostic("", "", setID, "")
	issue.Field, issue.Resource, issue.Dependency = field, identityPointer(dependent.identity), identityPointer(prerequisite)
	location := dependent.resource.Source
	issue.Location = &location
	if identityKey(dependent.identity) == identityKey(prerequisite) {
		issue.Code, issue.Message = "self_reference", "resource must not depend on itself"
		appendDAGDiagnostic(diagnostics, issue)
		return false
	}
	resolved, exists := graph.resources[identityKey(prerequisite)]
	if !exists {
		issue.Code, issue.Message = "dangling_reference", "dependency does not resolve within the resource set"
		appendDAGDiagnostic(diagnostics, issue)
		return false
	}
	if _, duplicate := seen[identityKey(prerequisite)]; duplicate {
		issue.Code, issue.Message = "duplicate_reference", "dependency edge is declared more than once"
		related := resolved.resource.Source
		issue.Related = &related
		appendDAGDiagnostic(diagnostics, issue)
		return false
	}
	seen[identityKey(prerequisite)] = origin
	edge := DependencyEdge{Dependent: dependent.identity, Prerequisite: prerequisite, Origin: origin}
	graph.edges = append(graph.edges, edge)
	graph.edgesByDependent[identityKey(dependent.identity)] = append(graph.edgesByDependent[identityKey(dependent.identity)], edge)
	return true
}

func appendDAGDiagnostic(diagnostics *[]DAGDiagnostic, issue DAGDiagnostic) {
	if len(*diagnostics) < maxDAGDiagnostics-1 {
		*diagnostics = append(*diagnostics, issue)
		return
	}
	if len(*diagnostics) == maxDAGDiagnostics-1 {
		*diagnostics = append(*diagnostics, dagDiagnostic("diagnostics_truncated", "additional dependency diagnostics were omitted", "", ""))
	}
}

func findDependencyCycle(graph *setGraph) []ResourceIdentity {
	adjacency := make(map[string][]string, len(graph.resources))
	for _, edge := range graph.edges {
		adjacency[identityKey(edge.Dependent)] = append(adjacency[identityKey(edge.Dependent)], identityKey(edge.Prerequisite))
	}
	for key := range adjacency {
		sort.Strings(adjacency[key])
	}
	colors := make(map[string]uint8, len(graph.resources))
	type frame struct {
		key  string
		next int
	}
	for _, start := range sortedIndexedResourceKeys(graph.resources) {
		if colors[start] != 0 {
			continue
		}
		stack := []frame{{key: start}}
		colors[start] = 1
		for len(stack) != 0 {
			top := &stack[len(stack)-1]
			neighbors := adjacency[top.key]
			if top.next >= len(neighbors) {
				colors[top.key] = 2
				stack = stack[:len(stack)-1]
				continue
			}
			next := neighbors[top.next]
			top.next++
			if colors[next] == 0 {
				colors[next] = 1
				stack = append(stack, frame{key: next})
				continue
			}
			if colors[next] == 1 {
				begin := 0
				for index := range stack {
					if stack[index].key == next {
						begin = index
						break
					}
				}
				cycle := make([]ResourceIdentity, 0, len(stack)-begin+1)
				for _, item := range stack[begin:] {
					cycle = append(cycle, graph.resources[item.key].identity)
				}
				cycle = append(cycle, graph.resources[next].identity)
				return cycle
			}
		}
	}
	return nil
}

func topologicalNodes(graph *setGraph, active map[string]struct{}) []DAGNode {
	indegree := make(map[string]int, len(active))
	dependents := make(map[string][]string)
	for key := range active {
		indegree[key] = 0
	}
	for _, dependentKey := range sortedActiveResourceKeys(active, graph.resources) {
		for _, edge := range graph.edgesByDependent[dependentKey] {
			prerequisite := identityKey(edge.Prerequisite)
			if _, ok := active[prerequisite]; !ok {
				continue
			}
			indegree[dependentKey]++
			dependents[prerequisite] = append(dependents[prerequisite], dependentKey)
		}
	}
	ready := &resourceKeyHeap{resources: graph.resources}
	for key, count := range indegree {
		if count == 0 {
			heap.Push(ready, key)
		}
	}
	result := make([]DAGNode, 0, len(active))
	for ready.Len() != 0 {
		key := heap.Pop(ready).(string)
		indexed := graph.resources[key]
		result = append(result, DAGNode{Resource: indexed.identity, Source: indexed.resource.Source})
		for _, dependent := range dependents[key] {
			indegree[dependent]--
			if indegree[dependent] == 0 {
				heap.Push(ready, dependent)
			}
		}
	}
	return result
}

type resourceKeyHeap struct {
	keys      []string
	resources map[string]indexedResource
}

func (values resourceKeyHeap) Len() int { return len(values.keys) }
func (values resourceKeyHeap) Less(i, j int) bool {
	return executionIdentityLess(values.resources[values.keys[i]].identity, values.resources[values.keys[j]].identity)
}
func (values resourceKeyHeap) Swap(i, j int) {
	values.keys[i], values.keys[j] = values.keys[j], values.keys[i]
}
func (values *resourceKeyHeap) Push(value any) { values.keys = append(values.keys, value.(string)) }
func (values *resourceKeyHeap) Pop() any {
	last := len(values.keys) - 1
	value := values.keys[last]
	values.keys = values.keys[:last]
	return value
}

func sortDependencyEdges(edges []DependencyEdge) {
	sort.SliceStable(edges, func(i, j int) bool {
		if edges[i].Dependent != edges[j].Dependent {
			return lessIdentity(edges[i].Dependent, edges[j].Dependent)
		}
		if edges[i].Prerequisite != edges[j].Prerequisite {
			return lessIdentity(edges[i].Prerequisite, edges[j].Prerequisite)
		}
		return edges[i].Origin < edges[j].Origin
	})
}

func sortResourceKeys(keys []string, resources map[string]indexedResource) {
	sort.SliceStable(keys, func(i, j int) bool {
		return executionIdentityLess(resources[keys[i]].identity, resources[keys[j]].identity)
	})
}
func executionIdentityLess(left, right ResourceIdentity) bool {
	leftRank, rightRank := kindRank(left.Kind), kindRank(right.Kind)
	if leftRank != rightRank {
		return leftRank < rightRank
	}
	return lessIdentity(left, right)
}
func kindRank(kind Kind) int {
	switch kind {
	case KindIntegrationPackage:
		return 0
	case KindAgentPolicy:
		return 1
	case KindPackagePolicy:
		return 2
	case KindDetectionRule:
		return 3
	case KindPrebuiltRules:
		return 4
	default:
		return 5
	}
}
func resourceIdentity(resource Resource) ResourceIdentity {
	return ResourceIdentity{Kind: resource.Kind, ID: resource.Metadata.ID}
}
func identityKey(identity ResourceIdentity) string                { return string(identity.Kind) + "/" + identity.ID }
func identityPointer(identity ResourceIdentity) *ResourceIdentity { copy := identity; return &copy }
func lessIdentity(left, right ResourceIdentity) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	return left.ID < right.ID
}
func sortedGraphSetIDs(graphs map[string]*setGraph) []string {
	result := make([]string, 0, len(graphs))
	for key := range graphs {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
func sortedIndexedResourceKeys(resources map[string]indexedResource) []string {
	result := make([]string, 0, len(resources))
	for key := range resources {
		result = append(result, key)
	}
	sortResourceKeys(result, resources)
	return result
}
func sortedActiveResourceKeys(active map[string]struct{}, resources map[string]indexedResource) []string {
	result := make([]string, 0, len(active))
	for key := range active {
		result = append(result, key)
	}
	sortResourceKeys(result, resources)
	return result
}
func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
func equalStringSets(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, exists := right[key]; !exists {
			return false
		}
	}
	return true
}
func dagDiagnostic(code, message, setID, target string) DAGDiagnostic {
	return DAGDiagnostic{Code: code, Message: message, ResourceSetID: setID, Target: target}
}

func newDAGError(diagnostics []DAGDiagnostic) *DAGError {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		left, right := diagnostics[i], diagnostics[j]
		if left.ResourceSetID != right.ResourceSetID {
			return left.ResourceSetID < right.ResourceSetID
		}
		if left.Target != right.Target {
			return left.Target < right.Target
		}
		if comparison := compareResourceIdentities(left.Resource, right.Resource); comparison != 0 {
			return comparison < 0
		}
		if comparison := compareResourceIdentities(left.Dependency, right.Dependency); comparison != 0 {
			return comparison < 0
		}
		if left.Field != right.Field {
			return left.Field < right.Field
		}
		if comparison := compareLocations(left.Location, right.Location); comparison != 0 {
			return comparison < 0
		}
		if left.Code != right.Code {
			return left.Code < right.Code
		}
		return left.Message < right.Message
	})
	return &DAGError{Diagnostics: diagnostics}
}
