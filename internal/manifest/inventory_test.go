package manifest

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

func TestSelectorMatchesExactConjunction(t *testing.T) {
	labels := map[string]string{"environment": "production", "region": "eu", "empty": ""}
	tests := []struct {
		name     string
		selector *TargetSelector
		want     bool
	}{
		{name: "omitted", selector: nil, want: true},
		{name: "exact", selector: &TargetSelector{MatchLabels: map[string]string{"environment": "production", "region": "eu"}}, want: true},
		{name: "wrong value", selector: &TargetSelector{MatchLabels: map[string]string{"environment": "staging"}}, want: false},
		{name: "missing key", selector: &TargetSelector{MatchLabels: map[string]string{"missing": ""}}, want: false},
		{name: "present empty", selector: &TargetSelector{MatchLabels: map[string]string{"empty": ""}}, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := cloneStringMap(labels)
			if got := SelectorMatches(test.selector, labels); got != test.want {
				t.Fatalf("SelectorMatches() = %v, want %v", got, test.want)
			}
			if !reflect.DeepEqual(labels, before) {
				t.Fatal("SelectorMatches() mutated labels")
			}
		})
	}
}

func TestBuildInventoryAssignsOnlyWithinResourceSet(t *testing.T) {
	cfg := inventoryConfig()
	cfg.Targets["prod-eu"] = targetConfig("set-a", "HTTP://LOCALHOST:5601", "", map[string]string{"environment": "production", "region": "eu"})
	cfg.Targets["prod-us"] = targetConfig("set-a", "http://localhost:5602", "default", map[string]string{"environment": "production", "region": "us"})
	cfg.Targets["other-eu"] = targetConfig("set-b", "http://localhost:5603", "default", map[string]string{"environment": "production", "region": "eu"})

	all := testInventoryResource(KindAgentPolicy, "all", nil)
	eu := testInventoryResource(KindDetectionRule, "eu-only", map[string]string{"environment": "production", "region": "eu"})
	dormant := testInventoryResource(KindPrebuiltRules, "future", map[string]string{"environment": "future"})
	sets := []*ResourceSet{
		{ID: "set-b", Revision: "rev-b", Resources: []Resource{testInventoryResourceForSet("set-b", KindAgentPolicy, "other", nil)}},
		{ID: "set-a", Revision: "rev-a", Resources: []Resource{dormant, eu, all}},
	}
	beforeTargets := cloneTargets(cfg.Targets)
	beforeSets, err := json.Marshal(sets)
	if err != nil {
		t.Fatal(err)
	}

	inventory, err := BuildInventory(cfg, sets)
	if err != nil {
		t.Fatalf("BuildInventory() error = %v", err)
	}
	if inventory.APIVersion != APIVersion || inventory.StateID != "review-state" {
		t.Fatalf("inventory header = %#v", inventory)
	}
	if got := resourceSetIDs(inventory.ResourceSets); !reflect.DeepEqual(got, []string{"set-a", "set-b"}) {
		t.Fatalf("resource set order = %#v", got)
	}
	setA := inventory.ResourceSets[0]
	if !reflect.DeepEqual(setA.Targets, []string{"prod-eu", "prod-us"}) || setA.Revision != "rev-a" {
		t.Fatalf("set-a inventory = %#v", setA)
	}
	resources := inventoryResourcesByID(setA.Resources)
	if !reflect.DeepEqual(resources["all"].ApplicableTargets, []string{"prod-eu", "prod-us"}) {
		t.Fatalf("all targets = %#v", resources["all"].ApplicableTargets)
	}
	if !reflect.DeepEqual(resources["eu-only"].ApplicableTargets, []string{"prod-eu"}) {
		t.Fatalf("eu targets = %#v", resources["eu-only"].ApplicableTargets)
	}
	if len(resources["future"].ApplicableTargets) != 0 {
		t.Fatalf("zero-match selector targets = %#v", resources["future"].ApplicableTargets)
	}
	prodEU := inventoryTargetByName(inventory.Targets, "prod-eu")
	if prodEU.Identity.URL != "http://localhost:5601" || prodEU.Identity.Space != "default" || prodEU.Revision != "rev-a" {
		t.Fatalf("prod-eu identity = %#v", prodEU)
	}
	if resourceIdentityPresent(prodEU.Resources, "other") {
		t.Fatalf("target matched resource from another set: %#v", prodEU.Resources)
	}
	otherEU := inventoryTargetByName(inventory.Targets, "other-eu")
	if resourceIdentityPresent(otherEU.Resources, "eu-only") {
		t.Fatalf("other-set target matched set-a selector: %#v", otherEU.Resources)
	}
	afterSets, err := json.Marshal(sets)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Targets, beforeTargets) || string(afterSets) != string(beforeSets) {
		t.Fatal("BuildInventory() mutated caller inputs")
	}
}

func TestBuildInventoryProducesDeterministicCredentialSafeProjection(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"z-set": {}, "a-set": {}}
	cfg.Targets["z-target"] = targetConfig("z-set", "http://localhost:5602", "", map[string]string{"z": "last", "a": "first"})
	cfg.Targets["a-target"] = targetConfig("a-set", "http://localhost:5601", "", nil)
	cfg.Targets["z-target"] = config.TargetConfig{
		URL: "http://localhost:5602", ResourceSet: "z-set", Labels: map[string]string{"z": "last", "a": "first"},
		CredentialSecret: config.SecretReference{Namespace: "credential-sentinel-namespace", Name: "credential-sentinel-name"},
	}
	sets := []*ResourceSet{
		{ID: "z-set", Resources: []Resource{testInventoryResourceForSet("z-set", KindPrebuiltRules, "z-resource", nil), testInventoryResourceForSet("z-set", KindAgentPolicy, "a-resource", nil)}},
		{ID: "a-set", Resources: []Resource{}},
	}
	first, err := BuildInventory(cfg, sets)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildInventory(cfg, []*ResourceSet{sets[1], sets[0]})
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
		t.Fatalf("inventory is nondeterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	serialized := string(firstJSON)
	for _, forbidden := range []string{"credential-sentinel", "credentialSecret", `"spec"`, "dependsOn", "targetSelector"} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("safe inventory contains %q: %s", forbidden, serialized)
		}
	}
	zTarget := inventoryTargetByName(first.Targets, "z-target")
	if !reflect.DeepEqual(zTarget.Labels, []Label{{Key: "a", Value: "first"}, {Key: "z", Value: "last"}}) {
		t.Fatalf("sorted labels = %#v", zTarget.Labels)
	}
}

func TestBuildInventoryRejectsInvalidDecodedSetStructure(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"configured": {}}
	tests := []struct {
		name string
		sets []*ResourceSet
		code string
	}{
		{name: "nil", sets: []*ResourceSet{nil}, code: "decoded_resource_set_nil"},
		{name: "missing id", sets: []*ResourceSet{{}}, code: "decoded_resource_set_missing_id"},
		{name: "missing configured", sets: nil, code: "missing_decoded_resource_set"},
		{name: "extra", sets: []*ResourceSet{{ID: "extra"}}, code: "extra_decoded_resource_set"},
		{name: "duplicate", sets: []*ResourceSet{{ID: "configured"}, {ID: "configured"}}, code: "duplicate_decoded_resource_set"},
		{name: "duplicate resource", sets: []*ResourceSet{{ID: "configured", Resources: []Resource{testInventoryResourceForSet("configured", KindAgentPolicy, "same", nil), testInventoryResourceForSet("configured", KindAgentPolicy, "same", nil)}}}, code: "duplicate_decoded_resource"},
		{name: "source mismatch", sets: []*ResourceSet{{ID: "configured", Resources: []Resource{testInventoryResource(KindAgentPolicy, "resource", nil)}}}, code: "resource_source_set_mismatch"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := BuildInventory(cfg, test.sets)
			assertInventoryDiagnostic(t, err, test.code)
		})
	}
}

func TestBuildInventoryRejectsUnknownAssignmentAndInvalidIdentity(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"configured": {}}
	cfg.Targets["target"] = targetConfig("missing", "http://localhost:5601", "", nil)
	_, err := BuildInventory(cfg, []*ResourceSet{{ID: "configured"}})
	assertInventoryDiagnostic(t, err, "target_resource_set_unknown")

	cfg.Targets["target"] = targetConfig("configured", "https://user:secret@example.test", "", nil)
	_, err = BuildInventory(cfg, []*ResourceSet{{ID: "configured"}})
	assertInventoryDiagnostic(t, err, "invalid_target_identity")
	if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "user") {
		t.Fatalf("identity diagnostic leaked URL material: %v", err)
	}
}

func TestBuildInventoryUsesStableEmptyCollections(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"unused": {}}
	inventory, err := BuildInventory(cfg, []*ResourceSet{{ID: "unused", Resources: []Resource{}}})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), `"targets":null`) || strings.Contains(string(encoded), `"resources":null`) {
		t.Fatalf("inventory contains null collections: %s", encoded)
	}
}

func TestBuildInventoryBoundsSelectorMatrixAndDiagnostics(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"large": {}}
	cfg.Targets = make(map[string]config.TargetConfig, 1000)
	for index := 0; index < 1000; index++ {
		name := fmt.Sprintf("target-%04d", index)
		cfg.Targets[name] = targetConfig("large", "http://localhost:5601", "", nil)
	}
	resources := make([]Resource, 1001)
	for index := range resources {
		resources[index] = testInventoryResourceForSet("large", KindAgentPolicy, fmt.Sprintf("resource-%04d", index), nil)
	}
	_, err := BuildInventory(cfg, []*ResourceSet{{ID: "large", Resources: resources}})
	assertInventoryDiagnostic(t, err, "too_many_selector_evaluations")

	cfg.Targets = nil
	duplicates := make([]Resource, maxInventoryDiagnostics+1)
	for index := range duplicates {
		duplicates[index] = testInventoryResourceForSet("large", KindAgentPolicy, "same", nil)
	}
	_, err = BuildInventory(cfg, []*ResourceSet{{ID: "large", Resources: duplicates}})
	var inventoryErr *InventoryError
	if !errors.As(err, &inventoryErr) || len(inventoryErr.Diagnostics) != maxInventoryDiagnostics {
		t.Fatalf("bounded diagnostics = %#v", err)
	}
}

func TestBuildInventoryRejectsMultipleApplicablePrebuiltResourcesDefensively(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"configured": {}}
	cfg.Targets["target"] = targetConfig("configured", "http://localhost:5601", "", map[string]string{"environment": "production"})
	resources := []Resource{
		testInventoryResourceForSet("configured", KindPrebuiltRules, "first", nil),
		testInventoryResourceForSet("configured", KindPrebuiltRules, "second", map[string]string{"environment": "production"}),
	}
	_, err := BuildInventory(cfg, []*ResourceSet{{ID: "configured", Resources: resources}})
	assertInventoryDiagnostic(t, err, "multiple_applicable_prebuilt_rules")
}

func TestBuildInventoryDefersReferenceGraphValidation(t *testing.T) {
	cfg := inventoryConfig()
	cfg.ResourceSets = map[string]config.ResourceSetConfig{"configured": {}}
	cfg.Targets["target"] = targetConfig("configured", "http://localhost:5601", "", map[string]string{"environment": "production"})
	resource := testInventoryResourceForSet("configured", KindPackagePolicy, "policy", map[string]string{"environment": "production"})
	resource.Metadata.DependsOn = []Reference{{Kind: KindPackagePolicy, ID: "policy"}, {Kind: KindAgentPolicy, ID: "missing"}}
	resource.Spec = PackagePolicySpec{IntegrationRef: Reference{Kind: KindIntegrationPackage, ID: "missing"}, AgentPolicyRef: Reference{Kind: KindAgentPolicy, ID: "missing"}}
	inventory, err := BuildInventory(cfg, []*ResourceSet{{ID: "configured", Resources: []Resource{resource}}})
	if err != nil {
		t.Fatalf("Phase 1.4 resolved deferred references: %v", err)
	}
	if len(inventory.Targets[0].Resources) != 1 {
		t.Fatalf("target resources = %#v", inventory.Targets[0].Resources)
	}
}

func inventoryConfig() *config.ServerConfig {
	return &config.ServerConfig{
		StateID:      "review-state",
		ResourceSets: map[string]config.ResourceSetConfig{"set-a": {}, "set-b": {}},
		Targets:      make(map[string]config.TargetConfig),
	}
}

func targetConfig(resourceSet, url, space string, labels map[string]string) config.TargetConfig {
	return config.TargetConfig{URL: url, Space: space, ResourceSet: resourceSet, Labels: labels}
}

func testInventoryResourceForSet(resourceSetID string, kind Kind, id string, labels map[string]string) Resource {
	resource := testInventoryResource(kind, id, labels)
	resource.Source.ResourceSetID = resourceSetID
	return resource
}

func testInventoryResource(kind Kind, id string, labels map[string]string) Resource {
	var selector *TargetSelector
	if labels != nil {
		selector = &TargetSelector{MatchLabels: labels}
	}
	return Resource{APIVersion: APIVersion, Kind: kind, Metadata: Metadata{ID: id, Name: id + " name", TargetSelector: selector}, Source: source.Location{ResourceSetID: "set-a", RelativePath: id + ".yaml", Document: 1, Line: 1, Column: 1}}
}

func assertInventoryDiagnostic(t *testing.T, err error, code string) {
	t.Helper()
	var inventoryErr *InventoryError
	if !errors.As(err, &inventoryErr) {
		t.Fatalf("BuildInventory() error = %#v", err)
	}
	for _, diagnostic := range inventoryErr.Diagnostics {
		if diagnostic.Code == code {
			return
		}
	}
	t.Fatalf("diagnostics = %#v, want code %q", inventoryErr.Diagnostics, code)
}

func resourceSetIDs(values []ResourceSetInventory) []string {
	result := make([]string, len(values))
	for index := range values {
		result[index] = values[index].ID
	}
	return result
}

func inventoryResourcesByID(values []ResourceInventory) map[string]ResourceInventory {
	result := make(map[string]ResourceInventory, len(values))
	for _, value := range values {
		result[value.ID] = value
	}
	return result
}

func inventoryTargetByName(values []TargetInventory, name string) TargetInventory {
	for _, value := range values {
		if value.Identity.Name == name {
			return value
		}
	}
	return TargetInventory{}
}

func resourceIdentityPresent(values []ResourceIdentity, id string) bool {
	for _, value := range values {
		if value.ID == id {
			return true
		}
	}
	return false
}

func cloneStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func cloneTargets(values map[string]config.TargetConfig) map[string]config.TargetConfig {
	result := make(map[string]config.TargetConfig, len(values))
	for key, value := range values {
		value.Labels = cloneStringMap(value.Labels)
		result[key] = value
	}
	return result
}
