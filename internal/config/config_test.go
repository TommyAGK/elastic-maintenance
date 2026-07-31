package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "desired.json")
	if err := os.WriteFile(path, []byte(`{
		"integrations": [{"name":"endpoint","version":"latest"}],
		"fleet_policies": [{"name":"policy-a"}],
		"rules": [{"name":"rule-a","type":"query","enabled":true,"prebuilt":false}]
	}`), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if len(loaded.Integrations) != 1 || loaded.Integrations[0].Name != "endpoint" {
		t.Fatalf("unexpected integrations: %+v", loaded.Integrations)
	}
	if len(loaded.FleetPolicies) != 1 || loaded.FleetPolicies[0].Name != "policy-a" {
		t.Fatalf("unexpected fleet policies: %+v", loaded.FleetPolicies)
	}
	if len(loaded.Rules) != 1 || loaded.Rules[0].Name != "rule-a" {
		t.Fatalf("unexpected rules: %+v", loaded.Rules)
	}
}
