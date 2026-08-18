package manifest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

func TestDecodeResourceSetAcceptsAllKindsAndMultipleDocuments(t *testing.T) {
	contents := `apiVersion: elastic-maintainer/v1alpha1
kind: IntegrationPackage
metadata:
  id: endpoint
  name: Endpoint package
spec:
  name: endpoint
  version: 9.2.0
---
apiVersion: elastic-maintainer/v1alpha1
kind: AgentPolicy
metadata:
  id: endpoint-agents
  name: Endpoint agents
  targetSelector:
    matchLabels:
      environment: production
  dependsOn:
    - IntegrationPackage/endpoint
spec: {}
---
apiVersion: elastic-maintainer/v1alpha1
kind: PackagePolicy
metadata:
  id: endpoint-policy
  name: Endpoint policy
spec:
  integrationRef: IntegrationPackage/endpoint
  agentPolicyRef: AgentPolicy/endpoint-agents
---
apiVersion: elastic-maintainer/v1alpha1
kind: DetectionRule
metadata:
  id: suspicious-process
  name: Suspicious process
spec:
  type: query
  enabled: true
  query: process.name:bad
  severity: high
  interval: 5m
  language: kuery
  index:
    - logs-endpoint.events.process-*
---
apiVersion: elastic-maintainer/v1alpha1
kind: PrebuiltRules
metadata:
  id: elastic-prebuilt
  name: Elastic prebuilt rules
spec: {}
`
	decoded, err := DecodeResourceSet(testResourceSet("resources.yaml", contents))
	if err != nil {
		t.Fatalf("DecodeResourceSet() error = %v", err)
	}
	if decoded.ID != "production" || decoded.Revision != "abc123" || len(decoded.Resources) != 5 {
		t.Fatalf("DecodeResourceSet() = %#v", decoded)
	}
	if decoded.Resources[0].Kind != KindIntegrationPackage || decoded.Resources[4].Kind != KindPrebuiltRules {
		t.Fatalf("resource kinds = %#v", decoded.Resources)
	}
	agent := decoded.Resources[1]
	if got := agent.Spec.(AgentPolicySpec).Namespace; got != "default" {
		t.Fatalf("AgentPolicy namespace = %q", got)
	}
	if agent.Source.RelativePath != "resources.yaml" || agent.Source.Document != 2 || agent.Source.Line != 10 || agent.Source.Column != 1 {
		t.Fatalf("AgentPolicy source = %#v", agent.Source)
	}
	policy := decoded.Resources[2].Spec.(PackagePolicySpec)
	if policy.Namespace != "default" || policy.IntegrationRef.ID != "endpoint" || policy.AgentPolicyRef.ID != "endpoint-agents" {
		t.Fatalf("PackagePolicy spec = %#v", policy)
	}
}

func TestDecodeResourceSetAcceptsSameIDForDifferentKinds(t *testing.T) {
	contents := validAgent("shared") + "---\n" + validPrebuilt("shared")
	decoded, err := DecodeResourceSet(testResourceSet("same-id.yaml", contents))
	if err != nil {
		t.Fatalf("DecodeResourceSet() error = %v", err)
	}
	if len(decoded.Resources) != 2 {
		t.Fatalf("resource count = %d", len(decoded.Resources))
	}
}

func TestDecodeResourceSetStrictRejections(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		code     string
	}{
		{name: "empty file", contents: "", code: "empty_document"},
		{name: "comment only", contents: "# no resource\n", code: "empty_document"},
		{name: "null", contents: "null\n", code: "empty_document"},
		{name: "scalar root", contents: "hello\n", code: "invalid_type"},
		{name: "unknown envelope field", contents: strings.Replace(validAgent("agents"), "spec:", "unexpected: value\nspec:", 1), code: "unknown_field"},
		{name: "unknown spec field", contents: strings.Replace(validAgent("agents"), "spec: {}", "spec:\n  description: unsupported", 1), code: "unknown_field"},
		{name: "credential field", contents: strings.Replace(validAgent("agents"), "spec: {}", "spec:\n  apiKey: credential-sentinel", 1), code: "credential_field"},
		{name: "duplicate key", contents: strings.Replace(validAgent("agents"), "  id: agents", "  id: agents\n  id: other", 1), code: "duplicate_key"},
		{name: "anchor", contents: strings.Replace(validAgent("agents"), "metadata:", "metadata: &metadata", 1), code: "yaml_indirection"},
		{name: "anchored key", contents: strings.Replace(validAgent("agents"), "  id: agents", "  &identity id: agents", 1), code: "yaml_indirection"},
		{name: "tagged mapping", contents: strings.Replace(validAgent("agents"), "spec: {}", "spec: !include {}", 1), code: "yaml_tag"},
		{name: "tagged sequence", contents: strings.Replace(validRule(), "index:", "index: !include", 1), code: "yaml_tag"},
		{name: "unsupported version", contents: strings.Replace(validAgent("agents"), APIVersion, "elastic-maintainer/v2", 1), code: "unsupported_api_version"},
		{name: "unsupported kind", contents: strings.Replace(validAgent("agents"), "AgentPolicy", "UnknownPolicy", 1), code: "unsupported_kind"},
		{name: "invalid id", contents: validAgent("Unsafe/ID"), code: "invalid_id"},
		{name: "format control in name", contents: strings.Replace(validAgent("agents"), "Agent policy", "Agent\u202epolicy", 1), code: "invalid_name"},
		{name: "latest package", contents: validPackage("latest"), code: "invalid_version"},
		{name: "version range", contents: validPackage(">=9.2.0"), code: "invalid_version"},
		{name: "partial version", contents: validPackage("9.2"), code: "invalid_version"},
		{name: "invalid semver prerelease", contents: validPackage("9.2.0-01"), code: "invalid_version"},
		{name: "unsupported rule", contents: strings.Replace(validRule(), "type: query", "type: threshold", 1), code: "unsupported_rule_type"},
		{name: "noncanonical boolean", contents: strings.Replace(validRule(), "enabled: true", "enabled: TRUE", 1), code: "invalid_type"},
		{name: "malformed explicit boolean", contents: strings.Replace(validRule(), "enabled: true", "enabled: !!bool credential-sentinel", 1), code: "invalid_type"},
		{name: "oversized interval", contents: strings.Replace(validRule(), "interval: 5m", "interval: 1234567890m", 1), code: "invalid_interval"},
		{name: "unsupported language", contents: strings.Replace(validRule(), "language: kuery", "language: eql", 1), code: "unsupported_language"},
		{name: "wrong typed reference", contents: strings.Replace(validPolicy(), "IntegrationPackage/endpoint", "AgentPolicy/endpoint", 1), code: "invalid_reference_kind"},
		{name: "duplicate dependency", contents: strings.Replace(validAgent("agents"), "spec: {}", "  dependsOn:\n    - AgentPolicy/other\n    - AgentPolicy/other\nspec: {}", 1), code: "duplicate_reference"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeResourceSet(testResourceSet("invalid.yaml", test.contents))
			assertDiagnosticCode(t, err, test.code)
			if err != nil && strings.Contains(err.Error(), "credential-sentinel") {
				t.Fatalf("error leaked scalar contents: %v", err)
			}
		})
	}
}

func TestDecodeResourceSetRejectsDuplicateResourcesAndPrebuiltDeclarations(t *testing.T) {
	tests := []struct {
		name     string
		contents string
		code     string
	}{
		{name: "duplicate identity", contents: validAgent("agents") + "---\n" + validAgent("agents"), code: "duplicate_resource"},
		{name: "multiple prebuilt", contents: validPrebuilt("first") + "---\n" + validPrebuilt("second"), code: "multiple_prebuilt_rules"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeResourceSet(testResourceSet("duplicates.yaml", test.contents))
			var diagnostics *DiagnosticsError
			if !errors.As(err, &diagnostics) || len(diagnostics.Diagnostics) != 1 {
				t.Fatalf("DecodeResourceSet() error = %#v", err)
			}
			issue := diagnostics.Diagnostics[0]
			if issue.Code != test.code || issue.Location.Document != 2 || issue.Related == nil || issue.Related.Document != 1 {
				t.Fatalf("diagnostic = %#v", issue)
			}
		})
	}
}

func TestDecodeResourceSetAggregatesInDeterministicSourceOrder(t *testing.T) {
	input := source.ResourceSet{ID: "production", Files: []source.File{
		{Location: source.Location{ResourceSetID: "production", RelativePath: "b.yaml"}, Contents: []byte("null\n")},
		{Location: source.Location{ResourceSetID: "production", RelativePath: "a.yaml"}, Contents: []byte("null\n")},
	}}
	_, err := DecodeResourceSet(input)
	var diagnostics *DiagnosticsError
	if !errors.As(err, &diagnostics) || len(diagnostics.Diagnostics) != 2 {
		t.Fatalf("DecodeResourceSet() error = %#v", err)
	}
	if diagnostics.Diagnostics[0].Location.RelativePath != "a.yaml" || diagnostics.Diagnostics[1].Location.RelativePath != "b.yaml" {
		t.Fatalf("diagnostic order = %#v", diagnostics.Diagnostics)
	}
}

func TestDecodeResourceSetSortsCallerFilesDefensively(t *testing.T) {
	input := source.ResourceSet{ID: "production", Files: []source.File{
		{Location: source.Location{ResourceSetID: "production", RelativePath: "b.yaml"}, Contents: []byte(validAgent("second"))},
		{Location: source.Location{ResourceSetID: "production", RelativePath: "a.yaml"}, Contents: []byte(validAgent("first"))},
	}}
	decoded, err := DecodeResourceSet(input)
	if err != nil {
		t.Fatalf("DecodeResourceSet() error = %v", err)
	}
	if decoded.Resources[0].Metadata.ID != "first" || decoded.Resources[1].Metadata.ID != "second" {
		t.Fatalf("resource order = %#v", decoded.Resources)
	}
	if input.Files[0].Location.RelativePath != "b.yaml" {
		t.Fatal("DecodeResourceSet() mutated caller file order")
	}
}

func TestDecodeResourceSetBoundsCollectionsAndNesting(t *testing.T) {
	indexes := strings.Repeat("    - logs-*\n", maxCollectionEntries+1)
	_, err := DecodeResourceSet(testResourceSet("indexes.yaml", strings.Replace(validRule(), "    - logs-*\n", indexes, 1)))
	assertDiagnosticCode(t, err, "too_many_values")

	deep := strings.Repeat("[", maxYAMLDepth+2) + "value" + strings.Repeat("]", maxYAMLDepth+2)
	contents := strings.Replace(validAgent("agents"), "spec: {}", "spec:\n  unsupported: "+deep, 1)
	_, err = DecodeResourceSet(testResourceSet("deep.yaml", contents))
	assertDiagnosticCode(t, err, "yaml_too_deep")
}

func TestDecodeResourceSetCapsAggregateDiagnostics(t *testing.T) {
	files := make([]source.File, maxDiagnosticsPerSet+1)
	for index := range files {
		files[index] = source.File{Location: source.Location{ResourceSetID: "production", RelativePath: fmt.Sprintf("%05d.yaml", index)}}
	}
	_, err := DecodeResourceSet(source.ResourceSet{ID: "production", Files: files})
	var diagnostics *DiagnosticsError
	if !errors.As(err, &diagnostics) || len(diagnostics.Diagnostics) != maxDiagnosticsPerSet {
		t.Fatalf("diagnostic count = %d, want %d", len(diagnostics.Diagnostics), maxDiagnosticsPerSet)
	}
}

func TestDecodeResourceSetDoesNotLeakMalformedYAMLScalars(t *testing.T) {
	const sentinel = "credential-sentinel-must-not-leak"
	contents := "apiVersion: elastic-maintainer/v1alpha1\nkind: AgentPolicy\nmetadata: [\"" + sentinel + "\"\nspec: {}\n"
	_, err := DecodeResourceSet(testResourceSet("secret.yaml", contents))
	assertDiagnosticCode(t, err, "invalid_yaml")
	var diagnostics *DiagnosticsError
	if !errors.As(err, &diagnostics) || diagnostics.Diagnostics[0].Location.Line != 2 || diagnostics.Diagnostics[0].Location.Column != 1 {
		t.Fatalf("parser diagnostic location = %#v", diagnostics)
	}
	if strings.Contains(err.Error(), sentinel) {
		t.Fatalf("error leaked malformed scalar: %v", err)
	}
}

func testResourceSet(path, contents string) source.ResourceSet {
	return source.ResourceSet{ID: "production", Revision: "abc123", Files: []source.File{{
		Location: source.Location{ResourceSetID: "production", RelativePath: path},
		Contents: []byte(contents),
	}}}
}

func assertDiagnosticCode(t *testing.T, err error, code string) {
	t.Helper()
	var diagnostics *DiagnosticsError
	if !errors.As(err, &diagnostics) || len(diagnostics.Diagnostics) == 0 {
		t.Fatalf("DecodeResourceSet() error = %#v, want diagnostics", err)
	}
	if diagnostics.Diagnostics[0].Code != code {
		t.Fatalf("diagnostic code = %q, want %q; diagnostic = %#v", diagnostics.Diagnostics[0].Code, code, diagnostics.Diagnostics[0])
	}
}

func validAgent(id string) string {
	return "apiVersion: elastic-maintainer/v1alpha1\nkind: AgentPolicy\nmetadata:\n  id: " + id + "\n  name: Agent policy\nspec: {}\n"
}

func validPackage(version string) string {
	return "apiVersion: elastic-maintainer/v1alpha1\nkind: IntegrationPackage\nmetadata:\n  id: endpoint\n  name: Endpoint\nspec:\n  name: endpoint\n  version: \"" + version + "\"\n"
}

func validPolicy() string {
	return "apiVersion: elastic-maintainer/v1alpha1\nkind: PackagePolicy\nmetadata:\n  id: endpoint-policy\n  name: Endpoint policy\nspec:\n  integrationRef: IntegrationPackage/endpoint\n  agentPolicyRef: AgentPolicy/agents\n"
}

func validRule() string {
	return "apiVersion: elastic-maintainer/v1alpha1\nkind: DetectionRule\nmetadata:\n  id: suspicious-process\n  name: Suspicious process\nspec:\n  type: query\n  enabled: true\n  query: process.name:bad\n  severity: high\n  interval: 5m\n  language: kuery\n  index:\n    - logs-*\n"
}

func validPrebuilt(id string) string {
	return "apiVersion: elastic-maintainer/v1alpha1\nkind: PrebuiltRules\nmetadata:\n  id: " + id + "\n  name: Prebuilt rules\nspec: {}\n"
}
