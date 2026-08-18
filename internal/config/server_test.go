package config

import (
	"encoding/json"
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
	if cfg.RuntimeConfigPath() != "testdata/server-valid.yaml" {
		t.Fatalf("RuntimeConfigPath() = %q", cfg.RuntimeConfigPath())
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

func TestLoadServerConfigIsReadOnly(t *testing.T) {
	path := writeConfig(t, readFixture(t))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServerConfig(path); err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("LoadServerConfig changed the mounted configuration")
	}
}

func TestLoadServerConfigRejectsNonRegularAndOversizedInputs(t *testing.T) {
	if _, err := LoadServerConfig(t.TempDir()); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory LoadServerConfig() error = %v", err)
	}
	path := writeConfig(t, strings.Repeat("x", maxServerConfigBytes+1))
	if _, err := LoadServerConfig(path); err == nil || !strings.Contains(err.Error(), "1 MiB limit") {
		t.Fatalf("oversized LoadServerConfig() error = %v", err)
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
	if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestLoadServerConfigRejectsSensitiveTargetFields(t *testing.T) {
	contents := strings.Replace(readFixture(t), "    resourceSet: production\n", "    resourceSet: production\n    apiKey: forbidden\n", 1)
	path := writeConfig(t, contents)
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), `unknown field "apiKey"`) {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
}

func TestLoadServerConfigRedactsMalformedCredentialValues(t *testing.T) {
	const sentinel = "credential-sentinel-must-not-leak"
	contents := strings.Replace(readFixture(t), "  clientSecret:\n    namespace: elastic-maintainer\n    name: elastic-maintainer-oidc\n    key: client-secret\n", "  clientSecret: "+sentinel+"\n", 1)
	_, err := LoadServerConfig(writeConfig(t, contents))
	if err == nil {
		t.Fatal("LoadServerConfig() error = nil")
	}
	if strings.Contains(err.Error(), sentinel) || strings.Contains(err.Error(), "credential-sentinel") {
		t.Fatalf("LoadServerConfig() leaked malformed credential material: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid YAML") {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}

	const crafted = "987654321"
	contents = strings.Replace(readFixture(t), "  clientSecret:\n    namespace: elastic-maintainer\n    name: elastic-maintainer-oidc\n    key: client-secret\n", "  clientSecret: !!float \"line "+crafted+"\"\n", 1)
	_, err = LoadServerConfig(writeConfig(t, contents))
	if err == nil || strings.Contains(err.Error(), crafted) {
		t.Fatalf("LoadServerConfig() leaked crafted decoder text: %v", err)
	}
}

func TestLoadServerConfigRejectsDuplicateKeys(t *testing.T) {
	contents := strings.Replace(readFixture(t), "stateID: security-platform\n", "stateID: security-platform\nstateID: duplicate\n", 1)
	path := writeConfig(t, contents)
	_, err := LoadServerConfig(path)
	if err == nil || !strings.Contains(err.Error(), `duplicate key "stateID"`) {
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
	if got := cfg.StartupOverrides(); got.ListenOverride != "127.0.0.1:9000" || got.StateDirOverride != "/override/state" || got.PublicURLOverride != "http://localhost:9000" {
		t.Fatalf("StartupOverrides() = %#v", got)
	}
}

func TestTargetIdentityNormalizesURLAndDefaultSpaceWithoutMutation(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	target := cfg.Targets["production-default"]
	target.URL = "HTTPS://KIBANA.Example.Test:443/"
	target.Space = ""
	cfg.Targets["production-default"] = target

	identity, err := cfg.TargetIdentity("production-default")
	if err != nil {
		t.Fatalf("TargetIdentity() error = %v", err)
	}
	want := TargetIdentity{StateID: "security-platform", Name: "production-default", URL: "https://kibana.example.test", Space: "default"}
	if identity != want {
		t.Fatalf("TargetIdentity() = %#v, want %#v", identity, want)
	}
	if cfg.Targets["production-default"].URL != target.URL || cfg.Targets["production-default"].Space != "" {
		t.Fatal("TargetIdentity mutated mounted target configuration")
	}
}

func TestNormalizeTargetConfigExcludesCredentialsAndCopiesLabels(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	target := cfg.Targets["production-default"]
	target.URL = "HTTPS://KIBANA.Example.Test:443/"
	target.Space = ""
	target.Labels = map[string]string{"environment": "production"}
	target.CredentialSecret = SecretReference{Namespace: "credential-sentinel", Name: "credential-sentinel"}
	cfg.Targets["production-default"] = target

	normalized, err := cfg.NormalizeTargetConfig("production-default")
	if err != nil {
		t.Fatal(err)
	}
	if normalized.URL != "https://kibana.example.test" || normalized.Space != "default" || normalized.ResourceSetID != target.ResourceSet {
		t.Fatalf("NormalizeTargetConfig() = %#v", normalized)
	}
	normalized.Labels["environment"] = "changed"
	if cfg.Targets["production-default"].Labels["environment"] != "production" {
		t.Fatal("NormalizeTargetConfig() returned an aliased labels map")
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "credential-sentinel") || strings.Contains(string(encoded), "credentialSecret") {
		t.Fatalf("normalized target leaked credential reference: %s", encoded)
	}
}

func TestTargetIdentityRejectsUnknownOrInvalidTargets(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.TargetIdentity("unknown"); err == nil || !strings.Contains(err.Error(), "is not configured") {
		t.Fatalf("unknown TargetIdentity() error = %v", err)
	}
	target := cfg.Targets["production-default"]
	target.URL = "http://kibana.example.test"
	cfg.Targets["production-default"] = target
	if _, err := cfg.TargetIdentity("production-default"); err == nil || !strings.Contains(err.Error(), "must use HTTPS") {
		t.Fatalf("unsafe TargetIdentity() error = %v", err)
	}
}

func TestValidateStartupRejectsInvalidNamesAndLabels(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.StateID = strings.Repeat("a", 129)
	cfg.ResourceSets["invalid.name"] = ResourceSetConfig{Path: "/var/lib/elastic-maintainer/sources/invalid"}
	cfg.Targets["invalid.name"] = TargetConfig{
		URL:         "https://kibana.example.test",
		Space:       strings.Repeat("s", 129),
		ResourceSet: "invalid.name",
		Labels: map[string]string{
			"bad key": "value",
			"valid":   "bad value",
		},
		CredentialSecret: SecretReference{Namespace: "elastic-maintainer", Name: "elastic-maintainer-target-invalid"},
	}

	err = cfg.ValidateStartup()
	if err == nil {
		t.Fatal("ValidateStartup() error = nil")
	}
	for _, want := range []string{"stateID must be at most 128 characters", "resourceSets contains invalid name", "targets contains invalid name", "space is invalid", "labels contains invalid key", "contains an invalid value"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateStartup() error %q does not contain %q", err, want)
		}
	}
}

func TestValidateStartupTreatsDefaultPortsAsSameOrigin(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "https://elastic-maintainer.example.test:443"
	if err := cfg.ValidateStartup(); err != nil {
		t.Fatalf("ValidateStartup() error = %v", err)
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

func TestValidateStartupRejectsRootResolvingToFilesystemRootAndUnresolvedStateSymlink(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(string(filepath.Separator), rootLink); err != nil {
		t.Fatal(err)
	}
	cfg.MountRoots = []string{rootLink}
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "mountRoots[0] must not resolve to the filesystem root") {
		t.Fatalf("root link ValidateStartup() error = %v", err)
	}
	cfg.MountRoots = []string{"/var/lib/elastic-maintainer/sources"}
	cfg.StateDir = rootLink
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "stateDir must not resolve to the filesystem root") {
		t.Fatalf("state root link ValidateStartup() error = %v", err)
	}

	parent := t.TempDir()
	dangling := filepath.Join(parent, "dangling")
	if err := os.Symlink(filepath.Join(parent, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	cfg.MountRoots = []string{"/var/lib/elastic-maintainer/sources"}
	cfg.StateDir = dangling
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "stateDir must not traverse an unresolved symlink") {
		t.Fatalf("dangling state ValidateStartup() error = %v", err)
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

func TestValidateStartupRejectsCanonicalEquivalentIssuerAndPublicURLs(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "https://IDENTITY.example.test:443/"
	cfg.OIDC.RedirectURL = "https://identity.example.test/auth/callback"
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "oidc.issuerURL must not equal publicURL") {
		t.Fatalf("ValidateStartup() error = %v", err)
	}
}

func TestValidateStartupRejectsResolvedPathOverlapAndEscape(t *testing.T) {
	parent := t.TempDir()
	mountRoot := filepath.Join(parent, "mount")
	resourceRoot := filepath.Join(mountRoot, "production")
	stateRoot := filepath.Join(mountRoot, "state")
	outsideRoot := filepath.Join(parent, "outside")
	for _, path := range []string{resourceRoot, stateRoot, outsideRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stateLink := filepath.Join(parent, "state-link")
	if err := os.Symlink(stateRoot, stateLink); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	cfg.MountRoots = []string{mountRoot}
	cfg.StateDir = stateLink
	set := cfg.ResourceSets["production"]
	set.Path = resourceRoot
	cfg.ResourceSets["production"] = set
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("resolved overlap ValidateStartup() error = %v", err)
	}

	escapedRoot := filepath.Join(mountRoot, "escaped")
	if err := os.Symlink(outsideRoot, escapedRoot); err != nil {
		t.Fatal(err)
	}
	cfg.StateDir = filepath.Join(parent, "safe-state")
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	set.Path = escapedRoot
	cfg.ResourceSets["production"] = set
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "must be within a configured mount root") {
		t.Fatalf("resolved escape ValidateStartup() error = %v", err)
	}
}

func TestValidateStartupRejectsDotRevisionPath(t *testing.T) {
	cfg, err := LoadServerConfig("testdata/server-valid.yaml")
	if err != nil {
		t.Fatal(err)
	}
	set := cfg.ResourceSets["production"]
	set.RevisionFile = "."
	cfg.ResourceSets["production"] = set
	if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "revisionFile must be a clean relative path") {
		t.Fatalf("ValidateStartup() error = %v", err)
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

func TestValidateStartupRejectsUnsafeTargetURLs(t *testing.T) {
	for name, rawURL := range map[string]string{
		"non-loopback HTTP": "http://kibana.example.test",
		"missing host":      "https://:443",
		"invalid port":      "https://kibana.example.test:0",
		"credentials":       "https://user:password@kibana.example.test",
		"query":             "https://kibana.example.test?token=forbidden",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadServerConfig("testdata/server-valid.yaml")
			if err != nil {
				t.Fatal(err)
			}
			target := cfg.Targets["production-default"]
			target.URL = rawURL
			cfg.Targets["production-default"] = target
			if err := cfg.ValidateStartup(); err == nil || !strings.Contains(err.Error(), "targets.production-default.url") {
				t.Fatalf("ValidateStartup() error = %v", err)
			}
		})
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
