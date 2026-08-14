package config

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndValidateServerConfig(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("ValidateStartup() error = %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("Listen = %q", cfg.Listen)
	}
	if cfg.Targets["production-default"].CredentialSecret.Name != "elastic-maintainer-target-production-default" {
		t.Fatalf("credential Secret reference was not decoded")
	}
}

func TestMinimalServerFixtureIsValid(t *testing.T) {
	cfg, err := LoadServerConfig(filepath.Join("..", "..", "testdata", "server-minimal.yaml"))
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("ValidateStartup() error = %v", err)
	}
	if len(cfg.ResourceSets) != 0 || len(cfg.Targets) != 0 {
		t.Fatalf("minimal fixture unexpectedly defines domain resources")
	}
}

func TestLoadServerConfigUsesSafeDefaults(t *testing.T) {
	contents := strings.ReplaceAll(readFixture(t), "listen: :8080\n", "")
	contents = strings.ReplaceAll(contents, "stateDir: /var/lib/elastic-maintainer/state\n", "")
	path := writeConfig(t, contents)

	cfg, err := LoadServerConfig(path)
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if cfg.Listen != DefaultListenAddress || cfg.StateDir != DefaultStateDir {
		t.Fatalf("defaults = listen %q, state %q", cfg.Listen, cfg.StateDir)
	}
}

func TestLoadServerConfigRejectsUnknownFields(t *testing.T) {
	path := writeConfig(t, readFixture(t)+"unexpected: true\n")
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), "field unexpected not found") {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestLoadServerConfigRejectsSensitiveTargetFields(t *testing.T) {
	contents := strings.Replace(readFixture(t), "    resourceSet: production\n", "    resourceSet: production\n    apiKey: forbidden\n", 1)
	path := writeConfig(t, contents)
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), "field apiKey not found") {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestLoadServerConfigRejectsDuplicateKeys(t *testing.T) {
	contents := strings.Replace(readFixture(t), "stateID: security-platform\n", "stateID: security-platform\nstateID: duplicate\n", 1)
	path := writeConfig(t, contents)
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), "mapping key \"stateID\" already defined") {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestLoadServerConfigRejectsMultipleDocuments(t *testing.T) {
	path := writeConfig(t, readFixture(t)+"---\napiVersion: elastic-maintainer/v1alpha1\n")
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestParseStartupOptionsDefaultsAndAllowlistedEnvironment(t *testing.T) {
	queried := map[string]bool{}
	lookup := func(key string) (string, bool) {
		queried[key] = true
		values := map[string]string{
			"ELASTIC_MAINTAINER_CONFIG":     "/mounted/server.yaml",
			"ELASTIC_MAINTAINER_LISTEN":     "127.0.0.1:9000",
			"ELASTIC_MAINTAINER_STATE_DIR":  "/state",
			"ELASTIC_MAINTAINER_PUBLIC_URL": "http://localhost:9000",
			"KIBANA_API_KEY":                "must-not-be-read",
			"KIBANA_URL":                    "https://must-not-be-read.example.test",
		}
		value, ok := values[key]
		return value, ok
	}

	options, err := ParseStartupOptions(nil, lookup)
	if err != nil {
		t.Fatalf("ParseStartupOptions() error = %v", err)
	}
	if options.ConfigPath != "/mounted/server.yaml" || options.ListenOverride != "127.0.0.1:9000" || options.StateDirOverride != "/state" || options.PublicURLOverride != "http://localhost:9000" {
		t.Fatalf("options = %#v", options)
	}
	if queried["KIBANA_API_KEY"] || queried["KIBANA_URL"] {
		t.Fatal("ParseStartupOptions queried a retired target environment variable")
	}
}

func TestParseStartupOptionsFlagsOverrideEnvironment(t *testing.T) {
	lookup := func(key string) (string, bool) {
		return map[string]string{
			"ELASTIC_MAINTAINER_CONFIG": "/env/config.yaml",
			"ELASTIC_MAINTAINER_LISTEN": "127.0.0.1:9000",
		}[key], key == "ELASTIC_MAINTAINER_CONFIG" || key == "ELASTIC_MAINTAINER_LISTEN"
	}
	options, err := ParseStartupOptions([]string{
		"--config", "/flag/config.yaml",
		"--listen", ":8081",
		"--state-dir", "/flag/state",
		"--public-url", "https://service.example.test",
		"--version",
	}, lookup)
	if err != nil {
		t.Fatalf("ParseStartupOptions() error = %v", err)
	}
	if options.ConfigPath != "/flag/config.yaml" || options.ListenOverride != ":8081" || options.StateDirOverride != "/flag/state" || options.PublicURLOverride != "https://service.example.test" || !options.ShowVersion {
		t.Fatalf("options = %#v", options)
	}
}

func TestParseStartupOptionsRejectsOperatorCommandsAndUnknownFlags(t *testing.T) {
	for name, args := range map[string][]string{
		"review subcommand": {"review"},
		"plan subcommand":   {"plan"},
		"apply subcommand":  {"apply"},
		"api key":           {"--api-key", "secret"},
		"Kibana URL":        {"--kibana-url", "https://kibana.example.test"},
		"mode":              {"--mode", "apply"},
		"namespace":         {"--namespace", "default"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseStartupOptions(args, emptyLookup)
			if err == nil {
				t.Fatal("ParseStartupOptions() error = nil")
			}
		})
	}
}

func TestParseStartupOptionsHelp(t *testing.T) {
	_, err := ParseStartupOptions([]string{"--help"}, emptyLookup)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("ParseStartupOptions() error = %v", err)
	}
}

func TestApplyStartupOverrides(t *testing.T) {
	cfg := ServerConfig{Listen: ":8080", StateDir: "/state", PublicURL: "https://old.example.test"}
	cfg.ApplyStartupOverrides(StartupOptions{
		ListenOverride:    "127.0.0.1:9000",
		StateDirOverride:  "/override/state",
		PublicURLOverride: "http://localhost:9000",
	})
	if cfg.Listen != "127.0.0.1:9000" || cfg.StateDir != "/override/state" || cfg.PublicURL != "http://localhost:9000" {
		t.Fatalf("config = %#v", cfg)
	}
}

func TestValidateStartupAggregatesSafetyErrors(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "http://public.example.test"
	cfg.Listen = "invalid"
	cfg.StateDir = "relative"
	cfg.TrustedProxies = []string{"proxy.example.test"}
	cfg.OIDC.RedirectURL = "https://other.example.test/auth/callback"
	cfg.Authorization.RoleMapping["owner"] = []string{"owners"}
	cfg.SecretPolicy.NamePrefix = "unsafe"
	cfg.Targets["production-default"] = TargetConfig{
		URL:         "https://user:password@kibana.example.test",
		Space:       "bad space",
		ResourceSet: "production",
		CredentialSecret: SecretReference{
			Namespace: "other",
			Name:      "unowned-secret",
		},
	}

	err = cfg.ValidateStartup()
	if err == nil {
		t.Fatal("ValidateStartup() error = nil")
	}
	for _, want := range []string{
		"publicURL must use HTTPS",
		"listen must be host:port",
		"stateDir must be a clean absolute path",
		"trustedProxies[0] must be a CIDR",
		"unsupported role \"owner\"",
		"namePrefix must be a valid Kubernetes Secret name prefix ending in dash",
		"without credentials",
		"space is invalid",
		"namespace must equal secretPolicy.namespace",
		"name must be a valid Kubernetes Secret name using the configured owned prefix",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateStartup() error %q does not contain %q", err, want)
		}
	}
}

func TestValidateStartupErrorsAreDeterministic(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Authorization.RoleMapping["z-invalid"] = nil
	cfg.Authorization.RoleMapping["a-invalid"] = nil
	cfg.ResourceSets["z invalid"] = ResourceSetConfig{Path: "relative"}
	cfg.ResourceSets["a invalid"] = ResourceSetConfig{Path: "relative"}

	first := cfg.ValidateStartup()
	if first == nil {
		t.Fatal("ValidateStartup() error = nil")
	}
	for range 20 {
		current := cfg.ValidateStartup()
		if current == nil || current.Error() != first.Error() {
			t.Fatalf("validation error changed:\nfirst: %v\ncurrent: %v", first, current)
		}
	}
}

func TestValidateStartupRejectsWritableStateAndSourceOverlap(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = "/var/lib/elastic-maintainer/sources/state"
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "stateDir and mountRoots[0] must not overlap") {
		t.Fatalf("ValidateStartup() error = %v", err)
	}

	cfg.StateDir = "/"
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("ValidateStartup() root error = %v", err)
	}
}

func TestValidateStartupRejectsOIDCRedirectOnAnotherOrigin(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.OIDC.RedirectURL = "https://other.example.test/auth/callback"
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "oidc.redirectURL must have the same origin") {
		t.Fatalf("ValidateStartup() error = %v", err)
	}
}

func TestValidateStartupAllowsLoopbackHTTP(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "http://127.0.0.1:8080"
	cfg.OIDC.RedirectURL = "http://127.0.0.1:8080/auth/callback"
	cfg.OIDC.IssuerURL = "http://localhost:5556"
	cfg.Targets["production-default"] = TargetConfig{
		URL:         "http://[::1]:5601",
		Space:       "default",
		ResourceSet: "production",
		CredentialSecret: SecretReference{
			Namespace: "elastic-maintainer",
			Name:      "elastic-maintainer-target-production-default",
		},
	}
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("ValidateStartup() error = %v", err)
	}
}

func emptyLookup(string) (string, bool) { return "", false }

func readFixture(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
