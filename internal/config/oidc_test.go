package config

import (
	"strings"
	"testing"
)

func TestDisabledOIDCMayOmitProviderConfiguration(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OIDC = OIDCConfig{Enabled: false, SecretMountRoot: DefaultOIDCSecretMountRoot}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("disabled OIDC validation error=%v", err)
	}
}

func TestEnabledOIDCRequiresExplicitEndpointOrigins(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.EndpointOrigins = nil
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "oidc.endpointOrigins must contain at least one explicit origin") {
		t.Fatalf("error=%v", err)
	}
}

func TestOIDCEnablementAndSecretMountRootValidation(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.OIDC.Enabled || cfg.OIDC.SecretMountRoot != DefaultOIDCSecretMountRoot {
		t.Fatalf("OIDC=%#v", cfg.OIDC)
	}
	cfg.OIDC.SecretMountRoot = "relative/secrets"
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "oidc.secretMountRoot must be a clean absolute path") {
		t.Fatalf("error=%v", err)
	}
}
