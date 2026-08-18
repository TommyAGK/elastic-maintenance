package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

func TestResolveTargetDAGsBuildsExplicitAndAutomaticEdges(t *testing.T) {
	cfg := dagConfig()
	integration := dagResource(KindIntegrationPackage, "endpoint")
	agent := dagResource(KindAgentPolicy, "agents")
	policy := dagResource(KindPackagePolicy, "policy")
	policy.Spec = PackagePolicySpec{
		IntegrationRef: Reference{Kind: KindIntegrationPackage, ID: "endpoint"},
		AgentPolicyRef: Reference{Kind: KindAgentPolicy, ID: "agents"},
	}
	rule := dagResource(KindDetectionRule, "rule")
	rule.Metadata.DependsOn = []Reference{{Kind: KindPackagePolicy, ID: "policy"}}
	set := &ResourceSet{ID: "set", Revision: "revision-1", Resources: []Resource{rule, policy, agent, integration}}
	inventory := mustBuildInventory(t, cfg, set)

	dags, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	if err != nil {
		t.Fatalf("ResolveTargetDAGs() error = %v", err)
	}
	if len(dags.Targets) != 1 || dags.Targets[0].Target != "target" || dags.Targets[0].Revision != "revision-1" {
		t.Fatalf("DAG set = %#v", dags)
	}
	gotNodes := nodeIDs(dags.Targets[0].Nodes)
	wantNodes := []string{"IntegrationPackage/endpoint", "AgentPolicy/agents", "PackagePolicy/policy", "DetectionRule/rule"}
	if !reflect.DeepEqual(gotNodes, wantNodes) {
		t.Fatalf("topological nodes = %#v, want %#v", gotNodes, wantNodes)
	}
	gotEdges := edgeStrings(dags.Targets[0].Edges)
	wantEdges := []string{
		"DetectionRule/rule->PackagePolicy/policy:explicit",
		"PackagePolicy/policy->AgentPolicy/agents:packagePolicy.agentPolicyRef",
		"PackagePolicy/policy->IntegrationPackage/endpoint:packagePolicy.integrationRef",
	}
	if !reflect.DeepEqual(gotEdges, wantEdges) {
		t.Fatalf("edges = %#v, want %#v", gotEdges, wantEdges)
	}
}

func TestResolveTargetDAGsRejectsReferenceFailures(t *testing.T) {
	tests := []struct {
		name      string
		resources []Resource
		code      string
	}{
		{
			name:      "dangling",
			resources: []Resource{withDependencies(dagResource(KindDetectionRule, "rule"), Reference{Kind: KindAgentPolicy, ID: "missing"})},
			code:      "dangling_reference",
		},
		{
			name:      "self",
			resources: []Resource{withDependencies(dagResource(KindDetectionRule, "rule"), Reference{Kind: KindDetectionRule, ID: "rule"})},
			code:      "self_reference",
		},
		{
			name:      "explicit duplicates automatic",
			resources: duplicatePackageDependencies(),
			code:      "duplicate_reference",
		},
		{
			name:      "cycle",
			resources: cyclicResources(),
			code:      "dependency_cycle",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := dagConfig()
			set := &ResourceSet{ID: "set", Resources: test.resources}
			inventory := mustBuildInventory(t, cfg, set)
			_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
			assertDAGDiagnostic(t, err, test.code)
		})
	}
}

func TestResolveTargetDAGsRejectsCrossSelectorReferences(t *testing.T) {
	cfg := dagConfig()
	cfg.Targets["target"] = targetConfig("set", "http://localhost:5601", "", map[string]string{"environment": "production"})
	integration := dagResource(KindIntegrationPackage, "endpoint")
	integration.Metadata.TargetSelector = &TargetSelector{MatchLabels: map[string]string{"environment": "staging"}}
	agent := dagResource(KindAgentPolicy, "agents")
	policy := dagResource(KindPackagePolicy, "policy")
	policy.Metadata.TargetSelector = &TargetSelector{MatchLabels: map[string]string{"environment": "production"}}
	policy.Spec = PackagePolicySpec{IntegrationRef: Reference{Kind: KindIntegrationPackage, ID: "endpoint"}, AgentPolicyRef: Reference{Kind: KindAgentPolicy, ID: "agents"}}
	set := &ResourceSet{ID: "set", Resources: []Resource{integration, agent, policy}}
	inventory := mustBuildInventory(t, cfg, set)

	_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	assertDAGDiagnostic(t, err, "cross_selector_reference")
}

func TestResolveTargetDAGsValidatesDormantResourcesButOmitsValidDormantNodes(t *testing.T) {
	cfg := dagConfig()
	cfg.Targets["target"] = targetConfig("set", "http://localhost:5601", "", map[string]string{"environment": "production"})
	dormant := dagResource(KindDetectionRule, "dormant")
	dormant.Metadata.TargetSelector = &TargetSelector{MatchLabels: map[string]string{"environment": "future"}}
	active := dagResource(KindAgentPolicy, "active")
	set := &ResourceSet{ID: "set", Resources: []Resource{dormant, active}}
	inventory := mustBuildInventory(t, cfg, set)
	dags, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	if got := nodeIDs(dags.Targets[0].Nodes); !reflect.DeepEqual(got, []string{"AgentPolicy/active"}) {
		t.Fatalf("nodes = %#v", got)
	}

	dormant.Metadata.DependsOn = []Reference{{Kind: KindAgentPolicy, ID: "missing"}}
	set = &ResourceSet{ID: "set", Resources: []Resource{dormant, active}}
	inventory = mustBuildInventory(t, cfg, set)
	_, err = ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	assertDAGDiagnostic(t, err, "dangling_reference")
}

func TestResolveTargetDAGsDoesNotResolveAcrossResourceSets(t *testing.T) {
	cfg := dagConfig()
	cfg.ResourceSets["other"] = config.ResourceSetConfig{}
	cfg.Targets["other-target"] = targetConfig("other", "http://localhost:5602", "", nil)
	dependent := withDependencies(dagResource(KindDetectionRule, "rule"), Reference{Kind: KindAgentPolicy, ID: "shared"})
	set := &ResourceSet{ID: "set", Resources: []Resource{dependent}}
	other := dagResourceForSet("other", KindAgentPolicy, "shared")
	otherSet := &ResourceSet{ID: "other", Resources: []Resource{other}}
	inventory := mustBuildInventoryMany(t, cfg, set, otherSet)
	_, err := ResolveTargetDAGs([]*ResourceSet{otherSet, set}, inventory)
	assertDAGDiagnostic(t, err, "dangling_reference")
}

func TestResolveTargetDAGsRejectsStaleInventory(t *testing.T) {
	cfg := dagConfig()
	resource := dagResource(KindAgentPolicy, "agents")
	set := &ResourceSet{ID: "set", Revision: "current", Resources: []Resource{resource}}

	t.Run("unknown membership", func(t *testing.T) {
		inventory := mustBuildInventory(t, cfg, set)
		inventory.Targets[0].Resources = append(inventory.Targets[0].Resources, ResourceIdentity{Kind: KindAgentPolicy, ID: "unknown"})
		_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
		assertDAGDiagnostic(t, err, "unknown_inventory_target_resource")
	})
	t.Run("omitted membership", func(t *testing.T) {
		inventory := mustBuildInventory(t, cfg, set)
		inventory.Targets[0].Resources = []ResourceIdentity{}
		_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
		assertDAGDiagnostic(t, err, "stale_inventory_applicability")
	})
	t.Run("selector applicability changed consistently in both projections", func(t *testing.T) {
		inventory := mustBuildInventory(t, cfg, set)
		inventory.ResourceSets[0].Resources[0].ApplicableTargets = []string{}
		inventory.Targets[0].Resources = []ResourceIdentity{}
		_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
		assertDAGDiagnostic(t, err, "stale_inventory_selector")
	})
	t.Run("revision", func(t *testing.T) {
		inventory := mustBuildInventory(t, cfg, set)
		inventory.Targets[0].Revision = "stale"
		_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
		assertDAGDiagnostic(t, err, "stale_inventory_revision")
	})
}

func TestResolveTargetDAGsBoundsAggregateProjection(t *testing.T) {
	cfg := dagConfig()
	cfg.Targets = make(map[string]config.TargetConfig, 1000)
	for index := 0; index < 1000; index++ {
		name := fmt.Sprintf("target-%04d", index)
		cfg.Targets[name] = targetConfig("set", "http://localhost:5601", "", nil)
	}
	resources := []Resource{
		dagResource(KindAgentPolicy, "base-a"),
		dagResource(KindAgentPolicy, "base-b"),
		dagResource(KindAgentPolicy, "base-c"),
	}
	for index := 0; index < 500; index++ {
		resource := dagResource(KindDetectionRule, fmt.Sprintf("rule-%04d", index))
		resource.Metadata.DependsOn = []Reference{
			{Kind: KindAgentPolicy, ID: "base-a"},
			{Kind: KindAgentPolicy, ID: "base-b"},
			{Kind: KindAgentPolicy, ID: "base-c"},
		}
		resources = append(resources, resource)
	}
	set := &ResourceSet{ID: "set", Resources: resources}
	inventory := mustBuildInventory(t, cfg, set)
	_, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	assertDAGDiagnostic(t, err, "dag_projection_too_large")
}

func TestResolveTargetDAGsIsDeterministicAndCredentialSafe(t *testing.T) {
	cfg := dagConfig()
	cfg.Targets["target"] = config.TargetConfig{
		URL: "http://localhost:5601", ResourceSet: "set",
		CredentialSecret: config.SecretReference{Namespace: "credential-sentinel", Name: "credential-sentinel"},
	}
	firstResource := dagResource(KindAgentPolicy, "a")
	secondResource := withDependencies(dagResource(KindDetectionRule, "b"), Reference{Kind: KindAgentPolicy, ID: "a"})
	set := &ResourceSet{ID: "set", Resources: []Resource{secondResource, firstResource}}
	inventory := mustBuildInventory(t, cfg, set)
	before, _ := json.Marshal(set)
	first, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	set.Resources[0], set.Resources[1] = set.Resources[1], set.Resources[0]
	second, err := ResolveTargetDAGs([]*ResourceSet{set}, inventory)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("DAG output is nondeterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	for _, forbidden := range []string{"credential-sentinel", `"spec"`, "dependsOn", "targetSelector"} {
		if strings.Contains(string(firstJSON), forbidden) {
			t.Fatalf("safe DAG contains %q: %s", forbidden, firstJSON)
		}
	}
	set.Resources[0], set.Resources[1] = set.Resources[1], set.Resources[0]
	after, _ := json.Marshal(set)
	if string(before) != string(after) {
		t.Fatal("ResolveTargetDAGs() mutated decoded resources")
	}
}

func dagConfig() *config.ServerConfig {
	return &config.ServerConfig{
		StateID:      "state",
		ResourceSets: map[string]config.ResourceSetConfig{"set": {}},
		Targets:      map[string]config.TargetConfig{"target": targetConfig("set", "http://localhost:5601", "", nil)},
	}
}

func dagResource(kind Kind, id string) Resource { return dagResourceForSet("set", kind, id) }
func dagResourceForSet(setID string, kind Kind, id string) Resource {
	resource := testInventoryResourceForSet(setID, kind, id, nil)
	switch kind {
	case KindIntegrationPackage:
		resource.Spec = IntegrationPackageSpec{Name: id, Version: "1.0.0"}
	case KindAgentPolicy:
		resource.Spec = AgentPolicySpec{Namespace: "default"}
	case KindDetectionRule:
		resource.Spec = DetectionRuleSpec{Type: "query"}
	case KindPrebuiltRules:
		resource.Spec = PrebuiltRulesSpec{}
	}
	return resource
}

func withDependencies(resource Resource, references ...Reference) Resource {
	resource.Metadata.DependsOn = references
	return resource
}

func duplicatePackageDependencies() []Resource {
	integration := dagResource(KindIntegrationPackage, "endpoint")
	agent := dagResource(KindAgentPolicy, "agents")
	policy := dagResource(KindPackagePolicy, "policy")
	policy.Metadata.DependsOn = []Reference{{Kind: KindIntegrationPackage, ID: "endpoint"}}
	policy.Spec = PackagePolicySpec{IntegrationRef: Reference{Kind: KindIntegrationPackage, ID: "endpoint"}, AgentPolicyRef: Reference{Kind: KindAgentPolicy, ID: "agents"}}
	return []Resource{integration, agent, policy}
}

func cyclicResources() []Resource {
	first := withDependencies(dagResource(KindDetectionRule, "a"), Reference{Kind: KindDetectionRule, ID: "b"})
	second := withDependencies(dagResource(KindDetectionRule, "b"), Reference{Kind: KindDetectionRule, ID: "a"})
	return []Resource{first, second}
}

func mustBuildInventory(t *testing.T, cfg *config.ServerConfig, set *ResourceSet) *Inventory {
	t.Helper()
	return mustBuildInventoryMany(t, cfg, set)
}
func mustBuildInventoryMany(t *testing.T, cfg *config.ServerConfig, sets ...*ResourceSet) *Inventory {
	t.Helper()
	inventory, err := BuildInventory(cfg, sets)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	return inventory
}

func assertDAGDiagnostic(t *testing.T, err error, code string) {
	t.Helper()
	var dagErr *DAGError
	if !errors.As(err, &dagErr) {
		t.Fatalf("ResolveTargetDAGs() error = %#v", err)
	}
	for _, diagnostic := range dagErr.Diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want %q", dagErr.Diagnostics, code)
}

func nodeIDs(nodes []DAGNode) []string {
	result := make([]string, len(nodes))
	for i, node := range nodes {
		result[i] = identityKey(node.Resource)
	}
	return result
}
func edgeStrings(edges []DependencyEdge) []string {
	result := make([]string, len(edges))
	for i, edge := range edges {
		result[i] = identityKey(edge.Dependent) + "->" + identityKey(edge.Prerequisite) + ":" + string(edge.Origin)
	}
	return result
}
