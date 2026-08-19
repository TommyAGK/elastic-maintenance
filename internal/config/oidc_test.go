package config

import (
	"os"
	"path/filepath"
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

func TestBreakGlassConfigRequiresOneCanonicalCredentialReference(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.BreakGlass = BreakGlassConfig{
		Enabled:          true,
		Username:         "break-glass-admin",
		CredentialSecret: SecretKeyRef{Namespace: "elastic-maintainer", Name: "elastic-maintainer-break-glass", Key: "credential"},
	}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("enabled break-glass validation error=%v", err)
	}
	// OIDC may remain disabled while break-glass reuses only its mounted root
	// and session key; those fields must not activate partial OIDC validation.
	cfg.OIDC = OIDCConfig{SecretMountRoot: DefaultOIDCSecretMountRoot, SessionSecret: cfg.OIDC.SessionSecret}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("break-glass-only validation error=%v", err)
	}
	if err := cfg.ValidateBreakGlass(); err != nil {
		t.Fatalf("ValidateBreakGlass() error=%v", err)
	}

	for name, username := range map[string]string{
		"empty":      "",
		"whitespace": " break-glass-admin",
		"separator":  "break/glass",
		"too long":   strings.Repeat("a", 129),
	} {
		t.Run(name, func(t *testing.T) {
			copy := *cfg
			copy.BreakGlass.Username = username
			if err := copy.ValidateBreakGlass(); err == nil || !strings.Contains(err.Error(), "canonical username") {
				t.Fatalf("ValidateBreakGlass() error=%v", err)
			}
		})
	}
}

func TestBreakGlassConfigurationRejectsPlaintextCredentialFields(t *testing.T) {
	contents, err := os.ReadFile("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "server.yaml")
	contents = append(contents, []byte("\nbreakGlass:\n  enabled: true\n  username: break-glass-admin\n  password: forbidden\n  credentialSecret:\n    namespace: elastic-maintainer\n    name: elastic-maintainer-break-glass\n    key: credential\n")...)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("error=%v", err)
	}
}

func TestBreakGlassDisabledRejectsStaleConfiguration(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.BreakGlass = BreakGlassConfig{Username: "break-glass-admin"}
	if err := cfg.ValidateBreakGlass(); err == nil || !strings.Contains(err.Error(), "must not configure") {
		t.Fatalf("ValidateBreakGlass() error=%v", err)
	}
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "must not configure") {
		t.Fatalf("ValidateStartup() error=%v", err)
	}
}
