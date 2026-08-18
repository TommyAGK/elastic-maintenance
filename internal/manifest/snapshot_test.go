package manifest

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

func TestBuildSourceSnapshotCanonicalizesDesiredStateAndRetainsRawProvenance(t *testing.T) {
	cfg := snapshotConfig()
	firstSource := snapshotSource("external-revision-a", canonicalFixtureA())
	secondSource := snapshotSource("external-revision-b", canonicalFixtureB())

	first, err := BuildSourceSnapshot(cfg, []source.ResourceSet{firstSource})
	if err != nil {
		t.Fatalf("BuildSourceSnapshot(first) error = %v", err)
	}
	second, err := BuildSourceSnapshot(cfg, []source.ResourceSet{secondSource})
	if err != nil {
		t.Fatalf("BuildSourceSnapshot(second) error = %v", err)
	}
	if first.ResourceSets[0].DesiredDigest != second.ResourceSets[0].DesiredDigest {
		t.Fatalf("format-equivalent resource-set digests differ: %#v %#v", first.ResourceSets[0].DesiredDigest, second.ResourceSets[0].DesiredDigest)
	}
	if first.Targets[0].DesiredDigest != second.Targets[0].DesiredDigest {
		t.Fatalf("format-equivalent target digests differ: %#v %#v", first.Targets[0].DesiredDigest, second.Targets[0].DesiredDigest)
	}
	if first.ResourceSets[0].Files[0].SHA256 == second.ResourceSets[0].Files[0].SHA256 {
		t.Fatal("raw file hash did not retain formatting provenance")
	}
	if first.ResourceSets[0].Revision == nil || first.ResourceSets[0].Revision.Value != "external-revision-a" || first.ResourceSets[0].Revision.RelativePath != "REVISION" {
		t.Fatalf("revision provenance = %#v", first.ResourceSets[0].Revision)
	}
	if first.ResourceSets[0].DesiredDigest.Algorithm != "sha256" || first.ResourceSets[0].DesiredDigest.Version != DesiredDigestVersion || len(first.ResourceSets[0].DesiredDigest.Value) != 64 {
		t.Fatalf("desired digest = %#v", first.ResourceSets[0].DesiredDigest)
	}
}

func TestBuildSourceSnapshotScopesTargetDigests(t *testing.T) {
	cfg := snapshotConfig()
	base, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource("revision", canonicalFixtureA())})
	if err != nil {
		t.Fatal(err)
	}
	baseDigest := targetSnapshotByName(base, "target").DesiredDigest

	credentialChanged := snapshotConfig()
	target := credentialChanged.Targets["target"]
	target.CredentialSecret = config.SecretReference{Namespace: "credential-sentinel", Name: "credential-sentinel"}
	credentialChanged.Targets["target"] = target
	credentialSnapshot, err := BuildSourceSnapshot(credentialChanged, []source.ResourceSet{snapshotSource("different-revision", canonicalFixtureA())})
	if err != nil {
		t.Fatal(err)
	}
	if targetSnapshotByName(credentialSnapshot, "target").DesiredDigest != baseDigest {
		t.Fatal("credential reference or revision changed target desired digest")
	}

	unrelatedChanged := snapshotConfig()
	unrelatedChanged.ResourceSets["other"] = config.ResourceSetConfig{Path: "/unused/other"}
	unrelatedChanged.Targets["other-target"] = config.TargetConfig{URL: "http://localhost:5602", ResourceSet: "other", Labels: map[string]string{"unrelated": "changed"}}
	otherSource := source.ResourceSet{ID: "other", Files: []source.File{{Location: source.Location{ResourceSetID: "other", RelativePath: "other.yaml"}, Contents: []byte(validAgent("other"))}}}
	unrelatedSnapshot, err := BuildSourceSnapshot(unrelatedChanged, []source.ResourceSet{otherSource, snapshotSource("revision", canonicalFixtureA())})
	if err != nil {
		t.Fatal(err)
	}
	if targetSnapshotByName(unrelatedSnapshot, "target").DesiredDigest != baseDigest {
		t.Fatal("unrelated target or resource set changed target desired digest")
	}

	labelsChanged := snapshotConfig()
	target = labelsChanged.Targets["target"]
	target.Labels = map[string]string{"environment": "production", "region": "eu"}
	labelsChanged.Targets["target"] = target
	labelSnapshot, err := BuildSourceSnapshot(labelsChanged, []source.ResourceSet{snapshotSource("revision", canonicalFixtureA())})
	if err != nil {
		t.Fatal(err)
	}
	if targetSnapshotByName(labelSnapshot, "target").DesiredDigest == baseDigest {
		t.Fatal("assigned target config change did not change target desired digest")
	}
}

func TestBuildSourceSnapshotDormantResourceAffectsOnlyResourceSetDigest(t *testing.T) {
	cfg := snapshotConfig()
	first, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource("revision", canonicalFixtureA())})
	if err != nil {
		t.Fatal(err)
	}
	changedBody := strings.Replace(canonicalFixtureA(), "Dormant source-body-sentinel", "Changed dormant source-body-sentinel", 1)
	second, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource("revision", changedBody)})
	if err != nil {
		t.Fatal(err)
	}
	if first.ResourceSets[0].DesiredDigest == second.ResourceSets[0].DesiredDigest {
		t.Fatal("dormant resource change did not change resource-set digest")
	}
	if first.Targets[0].DesiredDigest != second.Targets[0].DesiredDigest {
		t.Fatal("dormant resource change changed target digest")
	}
}

func TestBuildSourceSnapshotIsMetadataOnlyAndDeterministic(t *testing.T) {
	cfg := snapshotConfig()
	target := cfg.Targets["target"]
	target.CredentialSecret = config.SecretReference{Namespace: "credential-sentinel", Name: "credential-sentinel"}
	cfg.Targets["target"] = target
	discovered := snapshotSource("revision", canonicalFixtureA())
	first, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered})
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
		t.Fatal("snapshot output is not deterministic")
	}
	for _, forbidden := range []string{"credential-sentinel", "source-body-sentinel", "query:process", `"spec"`, "/unused/set"} {
		if strings.Contains(string(firstJSON), forbidden) {
			t.Fatalf("snapshot leaked %q: %s", forbidden, firstJSON)
		}
	}
	if strings.Contains(string(firstJSON), "Contents") || strings.Contains(string(firstJSON), "contents") {
		t.Fatalf("snapshot contains source body field: %s", firstJSON)
	}
}

func TestBuildSourceSnapshotRejectsSourceInconsistency(t *testing.T) {
	cfg := snapshotConfig()
	tests := []struct {
		name string
		sets []source.ResourceSet
	}{
		{name: "missing", sets: nil},
		{name: "extra", sets: []source.ResourceSet{{ID: "extra"}}},
		{name: "duplicate", sets: []source.ResourceSet{snapshotSource("", canonicalFixtureA()), snapshotSource("", canonicalFixtureA())}},
		{name: "wrong provenance", sets: []source.ResourceSet{{
			ID:    "set",
			Files: []source.File{{Location: source.Location{ResourceSetID: "other", RelativePath: "resource.yaml"}, Contents: []byte(canonicalFixtureA())}},
		}}},
		{name: "unsafe path", sets: []source.ResourceSet{{
			ID:    "set",
			Files: []source.File{{Location: source.Location{ResourceSetID: "set", RelativePath: "../resource.yaml"}, Contents: []byte(canonicalFixtureA())}},
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildSourceSnapshot(cfg, test.sets); err == nil {
				t.Fatal("BuildSourceSnapshot() error = nil")
			}
		})
	}
}

func TestBuildSourceSnapshotEnforcesBoundaryLimitsAndRevisionPaths(t *testing.T) {
	t.Run("oversized file", func(t *testing.T) {
		cfg := snapshotConfig()
		discovered := snapshotSource("revision", strings.Repeat("x", int(source.DefaultMaxFileBytes)+1))
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered}); err == nil || !strings.Contains(err.Error(), "too large") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
	t.Run("too many files", func(t *testing.T) {
		cfg := snapshotConfig()
		files := make([]source.File, source.DefaultMaxFiles+1)
		for index := range files {
			files[index].Location = source.Location{ResourceSetID: "set", RelativePath: fmt.Sprintf("%05d.yaml", index)}
		}
		discovered := source.ResourceSet{ID: "set", Revision: "revision", Files: files}
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered}); err == nil || !strings.Contains(err.Error(), "too many files") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
	t.Run("absolute revision path", func(t *testing.T) {
		cfg := snapshotConfig()
		cfg.ResourceSets["set"] = config.ResourceSetConfig{RevisionFile: "/etc/passwd"}
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource("revision", canonicalFixtureA())}); err == nil || !strings.Contains(err.Error(), "revision provenance path") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
	t.Run("missing revision value", func(t *testing.T) {
		cfg := snapshotConfig()
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource("", canonicalFixtureA())}); err == nil || !strings.Contains(err.Error(), "revision provenance is inconsistent") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
	t.Run("invalid revision value", func(t *testing.T) {
		cfg := snapshotConfig()
		for _, revision := range []string{" revision", "revision\u2028second-line"} {
			if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{snapshotSource(revision, canonicalFixtureA())}); err == nil || !strings.Contains(err.Error(), "revision metadata") {
				t.Fatalf("BuildSourceSnapshot(%q) error = %v", revision, err)
			}
		}
	})
	t.Run("revision resource collision", func(t *testing.T) {
		cfg := snapshotConfig()
		discovered := source.ResourceSet{ID: "set", Revision: "revision", Files: []source.File{{Location: source.Location{ResourceSetID: "set", RelativePath: "REVISION"}, Contents: []byte(canonicalFixtureA())}}}
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered}); err == nil || !strings.Contains(err.Error(), "must not also be a resource") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
	t.Run("dot source path", func(t *testing.T) {
		cfg := snapshotConfig()
		discovered := source.ResourceSet{ID: "set", Revision: "revision", Files: []source.File{{Location: source.Location{ResourceSetID: "set", RelativePath: "."}, Contents: []byte(canonicalFixtureA())}}}
		if _, err := BuildSourceSnapshot(cfg, []source.ResourceSet{discovered}); err == nil || !strings.Contains(err.Error(), "provenance") {
			t.Fatalf("BuildSourceSnapshot() error = %v", err)
		}
	})
}

func TestCanonicalizationDoesNotMutateDecodedResources(t *testing.T) {
	resource := dagResource(KindDetectionRule, "rule")
	resource.Metadata.DependsOn = []Reference{{Kind: KindAgentPolicy, ID: "z"}, {Kind: KindAgentPolicy, ID: "a"}}
	resource.Spec = DetectionRuleSpec{Type: "query", Enabled: true, Query: "query", Severity: "medium", Interval: "5m", Language: "kuery", Index: []string{"z-*", "a-*"}}
	before := resource
	before.Metadata.DependsOn = append([]Reference(nil), resource.Metadata.DependsOn...)
	beforeSpec := resource.Spec.(DetectionRuleSpec)
	beforeSpec.Index = append([]string(nil), beforeSpec.Index...)
	before.Spec = beforeSpec
	if _, err := canonicalizeResource(resource); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(resource, before) {
		t.Fatal("canonicalization mutated decoded resource")
	}
}

func snapshotConfig() *config.ServerConfig {
	return &config.ServerConfig{
		StateID:      "snapshot-state",
		ResourceSets: map[string]config.ResourceSetConfig{"set": {Path: "/unused/set", RevisionFile: "REVISION"}},
		Targets: map[string]config.TargetConfig{
			"target": {URL: "HTTP://LOCALHOST:5601", ResourceSet: "set", Labels: map[string]string{"environment": "production"}},
		},
	}
}

func snapshotSource(revision, contents string) source.ResourceSet {
	return source.ResourceSet{ID: "set", Revision: revision, Files: []source.File{{Location: source.Location{ResourceSetID: "set", RelativePath: "resources.yaml"}, Contents: []byte(contents)}}}
}

func targetSnapshotByName(snapshot *SourceSnapshot, name string) TargetSnapshot {
	for _, target := range snapshot.Targets {
		if target.Identity.Name == name {
			return target
		}
	}
	return TargetSnapshot{}
}

func canonicalFixtureA() string {
	return `apiVersion: elastic-maintainer/v1alpha1
kind: AgentPolicy
metadata:
  id: agents
  name: Active agents
spec: {}
---
apiVersion: elastic-maintainer/v1alpha1
kind: DetectionRule
metadata:
  id: dormant
  name: Dormant source-body-sentinel
  targetSelector:
    matchLabels:
      environment: staging
  dependsOn: []
spec:
  type: query
  enabled: true
  query: "process.name:source-body-sentinel"
  severity: medium
  interval: 5m
  language: kuery
  index:
    - z-*
    - a-*
`
}

func canonicalFixtureB() string {
	return `kind: DetectionRule
apiVersion: elastic-maintainer/v1alpha1
metadata:
  dependsOn: []
  targetSelector:
    matchLabels: {environment: staging}
  name: "Dormant source-body-sentinel"
  id: dormant
spec:
  index: [a-*, z-*]
  language: kuery
  interval: 5m
  severity: medium
  query: 'process.name:source-body-sentinel'
  enabled: true
  type: query
---
kind: AgentPolicy
apiVersion: elastic-maintainer/v1alpha1
metadata: {name: Active agents, id: agents}
spec: {namespace: default}
`
}
