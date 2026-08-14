package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ServerAPIVersion     = "elastic-maintainer/v1alpha1"
	DefaultConfigPath    = "/etc/elastic-maintainer/elastic-maintainer.yaml"
	DefaultListenAddress = ":8080"
	DefaultStateDir      = "/var/lib/elastic-maintainer/state"
)

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	dnsLabelPattern   = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	secretKeyPattern  = regexp.MustCompile(`^[-._A-Za-z0-9]+$`)
	allowedRoles      = map[string]struct{}{
		"viewer": {}, "planner": {}, "applier": {}, "administrator": {},
	}
)

type ServerConfig struct {
	APIVersion         string                       `yaml:"apiVersion"`
	StateID            string                       `yaml:"stateID"`
	PublicURL          string                       `yaml:"publicURL"`
	Listen             string                       `yaml:"listen,omitempty"`
	StateDir           string                       `yaml:"stateDir,omitempty"`
	TrustedProxies     []string                     `yaml:"trustedProxies,omitempty"`
	CORSAllowedOrigins []string                     `yaml:"corsAllowedOrigins,omitempty"`
	MountRoots         []string                     `yaml:"mountRoots"`
	OIDC               OIDCConfig                   `yaml:"oidc"`
	Authorization      AuthorizationConfig          `yaml:"authorization"`
	SecretPolicy       KubernetesSecretPolicy       `yaml:"secretPolicy"`
	ResourceSets       map[string]ResourceSetConfig `yaml:"resourceSets,omitempty"`
	Targets            map[string]TargetConfig      `yaml:"targets,omitempty"`
}

type OIDCConfig struct {
	IssuerURL        string       `yaml:"issuerURL"`
	ClientID         string       `yaml:"clientID"`
	ClientSecret     SecretKeyRef `yaml:"clientSecret"`
	SessionSecret    SecretKeyRef `yaml:"sessionSecret"`
	RedirectURL      string       `yaml:"redirectURL"`
	Scopes           []string     `yaml:"scopes,omitempty"`
	SubjectClaim     string       `yaml:"subjectClaim,omitempty"`
	DisplayNameClaim string       `yaml:"displayNameClaim,omitempty"`
}

type SecretKeyRef struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
	Key       string `yaml:"key"`
}

type AuthorizationConfig struct {
	RoleClaim   string              `yaml:"roleClaim"`
	RoleMapping map[string][]string `yaml:"roleMappings"`
}

type KubernetesSecretPolicy struct {
	Namespace  string `yaml:"namespace"`
	NamePrefix string `yaml:"namePrefix"`
}

type ResourceSetConfig struct {
	Path         string `yaml:"path"`
	RevisionFile string `yaml:"revisionFile,omitempty"`
}

type TargetConfig struct {
	URL              string            `yaml:"url"`
	Space            string            `yaml:"space,omitempty"`
	Labels           map[string]string `yaml:"labels,omitempty"`
	ResourceSet      string            `yaml:"resourceSet"`
	CredentialSecret SecretReference   `yaml:"credentialSecret"`
}

type SecretReference struct {
	Namespace string `yaml:"namespace"`
	Name      string `yaml:"name"`
}

type StartupOptions struct {
	ConfigPath        string
	ListenOverride    string
	StateDirOverride  string
	PublicURLOverride string
	ShowVersion       bool
}

type LookupEnv func(string) (string, bool)

func ParseStartupOptions(args []string, lookup LookupEnv) (StartupOptions, error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}

	options := StartupOptions{
		ConfigPath:        envOrDefault(lookup, "ELASTIC_MAINTAINER_CONFIG", DefaultConfigPath),
		ListenOverride:    envOrDefault(lookup, "ELASTIC_MAINTAINER_LISTEN", ""),
		StateDirOverride:  envOrDefault(lookup, "ELASTIC_MAINTAINER_STATE_DIR", ""),
		PublicURLOverride: envOrDefault(lookup, "ELASTIC_MAINTAINER_PUBLIC_URL", ""),
	}

	set := flag.NewFlagSet("elastic-maintainer", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.StringVar(&options.ConfigPath, "config", options.ConfigPath, "path to mounted server configuration")
	set.StringVar(&options.ListenOverride, "listen", options.ListenOverride, "override server listen address")
	set.StringVar(&options.StateDirOverride, "state-dir", options.StateDirOverride, "override non-secret state directory")
	set.StringVar(&options.PublicURLOverride, "public-url", options.PublicURLOverride, "override externally visible HTTPS URL")
	set.BoolVar(&options.ShowVersion, "version", false, "print build version and exit")

	if err := set.Parse(args); err != nil {
		return StartupOptions{}, err
	}
	if set.NArg() != 0 {
		return StartupOptions{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(set.Args(), " "))
	}
	if strings.TrimSpace(options.ConfigPath) == "" && !options.ShowVersion {
		return StartupOptions{}, errors.New("--config must not be empty")
	}
	return options, nil
}

func LoadServerConfig(path string) (*ServerConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open server config: %w", err)
	}
	defer file.Close()

	cfg := &ServerConfig{Listen: DefaultListenAddress, StateDir: DefaultStateDir}
	decoder := yaml.NewDecoder(file)
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode server config: %w", err)
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode server config: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode server config: %w", err)
	}
	return cfg, nil
}

func (cfg *ServerConfig) ApplyStartupOverrides(options StartupOptions) {
	if options.ListenOverride != "" {
		cfg.Listen = options.ListenOverride
	}
	if options.StateDirOverride != "" {
		cfg.StateDir = options.StateDirOverride
	}
	if options.PublicURLOverride != "" {
		cfg.PublicURL = options.PublicURLOverride
	}
}

func (cfg *ServerConfig) ValidateStartup() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if cfg.APIVersion != ServerAPIVersion {
		add("apiVersion must be %q", ServerAPIVersion)
	}
	if !identifierPattern.MatchString(cfg.StateID) {
		add("stateID must use letters, digits, underscore, dot, or dash and start with a letter, digit, or underscore")
	}
	publicURL, err := validateHTTPSURL("publicURL", cfg.PublicURL, true)
	if err != nil {
		add("%v", err)
	} else if publicURL.Path != "" && publicURL.Path != "/" {
		add("publicURL must not contain a path")
	}
	if err := validateListen(cfg.Listen); err != nil {
		add("%v", err)
	}
	if err := validateAbsoluteDir("stateDir", cfg.StateDir); err != nil {
		add("%v", err)
	}

	seenRoots := map[string]struct{}{}
	if len(cfg.MountRoots) == 0 {
		add("mountRoots must contain at least one absolute path")
	}
	for index, root := range cfg.MountRoots {
		if err := validateAbsoluteDir(fmt.Sprintf("mountRoots[%d]", index), root); err != nil {
			add("%v", err)
			continue
		}
		clean := filepath.Clean(root)
		if _, exists := seenRoots[clean]; exists {
			add("mountRoots contains duplicate path %q", clean)
		}
		seenRoots[clean] = struct{}{}
		if filepath.IsAbs(cfg.StateDir) && pathsOverlap(cfg.StateDir, clean) {
			add("stateDir and mountRoots[%d] must not overlap", index)
		}
	}

	for index, cidr := range cfg.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("trustedProxies[%d] must be a CIDR: %q", index, cidr)
		}
	}
	for index, origin := range cfg.CORSAllowedOrigins {
		if _, err := validateOrigin(origin); err != nil {
			add("corsAllowedOrigins[%d]: %v", index, err)
		}
	}

	issuerURL, issuerErr := validateHTTPSURL("oidc.issuerURL", cfg.OIDC.IssuerURL, true)
	if issuerErr != nil {
		add("%v", issuerErr)
	}
	if strings.TrimSpace(cfg.OIDC.ClientID) == "" {
		add("oidc.clientID is required")
	}
	validateSecretKeyRef("oidc.clientSecret", cfg.OIDC.ClientSecret, &problems)
	validateSecretKeyRef("oidc.sessionSecret", cfg.OIDC.SessionSecret, &problems)
	redirectURL, redirectErr := validateHTTPSURL("oidc.redirectURL", cfg.OIDC.RedirectURL, true)
	if redirectErr != nil {
		add("%v", redirectErr)
	} else {
		if publicURL != nil && !sameOrigin(publicURL, redirectURL) {
			add("oidc.redirectURL must have the same origin as publicURL")
		}
		if redirectURL.Path != "/auth/callback" {
			add("oidc.redirectURL path must be /auth/callback")
		}
	}
	if issuerURL != nil && publicURL != nil && issuerURL.String() == publicURL.String() {
		add("oidc.issuerURL must not equal publicURL")
	}
	hasOpenIDScope := false
	for _, scope := range cfg.OIDC.Scopes {
		if scope == "openid" {
			hasOpenIDScope = true
		}
	}
	if !hasOpenIDScope {
		add("oidc.scopes must include openid")
	}
	if cfg.OIDC.SubjectClaim != "" && !identifierPattern.MatchString(cfg.OIDC.SubjectClaim) {
		add("oidc.subjectClaim is invalid")
	}
	if cfg.OIDC.DisplayNameClaim != "" && !identifierPattern.MatchString(cfg.OIDC.DisplayNameClaim) {
		add("oidc.displayNameClaim is invalid")
	}

	if strings.TrimSpace(cfg.Authorization.RoleClaim) == "" {
		add("authorization.roleClaim is required")
	}
	if len(cfg.Authorization.RoleMapping) == 0 {
		add("authorization.roleMappings must contain at least one role")
	}
	for _, role := range sortedStringKeys(cfg.Authorization.RoleMapping) {
		values := cfg.Authorization.RoleMapping[role]
		if _, ok := allowedRoles[role]; !ok {
			add("authorization.roleMappings contains unsupported role %q", role)
		}
		if len(values) == 0 {
			add("authorization.roleMappings.%s must contain at least one claim value", role)
		}
		for index, value := range values {
			if strings.TrimSpace(value) == "" {
				add("authorization.roleMappings.%s[%d] must not be empty", role, index)
			}
		}
	}

	if !isKubernetesNamespace(cfg.SecretPolicy.Namespace) {
		add("secretPolicy.namespace must be a valid Kubernetes namespace")
	}
	if !isKubernetesNamePrefix(cfg.SecretPolicy.NamePrefix) {
		add("secretPolicy.namePrefix must be a valid Kubernetes Secret name prefix ending in dash")
	}
	secretRefs := []struct {
		field string
		ref   SecretKeyRef
	}{
		{field: "oidc.clientSecret", ref: cfg.OIDC.ClientSecret},
		{field: "oidc.sessionSecret", ref: cfg.OIDC.SessionSecret},
	}
	for _, item := range secretRefs {
		if item.ref.Namespace != cfg.SecretPolicy.Namespace {
			add("%s.namespace must equal secretPolicy.namespace", item.field)
		}
	}

	for _, name := range sortedStringKeys(cfg.ResourceSets) {
		set := cfg.ResourceSets[name]
		if !identifierPattern.MatchString(name) {
			add("resourceSets contains invalid name %q", name)
		}
		if err := validateAbsoluteDir("resourceSets."+name+".path", set.Path); err != nil {
			add("%v", err)
		} else if !pathWithinAny(set.Path, cfg.MountRoots) {
			add("resourceSets.%s.path must be within a configured mount root", name)
		}
		cleanRevision := filepath.Clean(set.RevisionFile)
		if set.RevisionFile != "" && (filepath.IsAbs(set.RevisionFile) || cleanRevision != set.RevisionFile || cleanRevision == ".." || strings.HasPrefix(cleanRevision, ".."+string(filepath.Separator))) {
			add("resourceSets.%s.revisionFile must be a clean relative path", name)
		}
	}
	for _, name := range sortedStringKeys(cfg.Targets) {
		target := cfg.Targets[name]
		if !identifierPattern.MatchString(name) {
			add("targets contains invalid name %q", name)
		}
		if _, err := validateHTTPSURL("targets."+name+".url", target.URL, true); err != nil {
			add("%v", err)
		}
		space := target.Space
		if space == "" {
			space = "default"
		}
		if !identifierPattern.MatchString(space) {
			add("targets.%s.space is invalid", name)
		}
		if !identifierPattern.MatchString(target.ResourceSet) {
			add("targets.%s.resourceSet is invalid", name)
		} else if _, exists := cfg.ResourceSets[target.ResourceSet]; !exists {
			add("targets.%s.resourceSet references an unknown resource set", name)
		}
		if target.CredentialSecret.Namespace != cfg.SecretPolicy.Namespace {
			add("targets.%s.credentialSecret.namespace must equal secretPolicy.namespace", name)
		}
		if !strings.HasPrefix(target.CredentialSecret.Name, cfg.SecretPolicy.NamePrefix) || !isKubernetesSecretName(target.CredentialSecret.Name) {
			add("targets.%s.credentialSecret.name must be a valid Kubernetes Secret name using the configured owned prefix", name)
		}
		for _, key := range sortedStringKeys(target.Labels) {
			if !identifierPattern.MatchString(key) {
				add("targets.%s.labels contains invalid key %q", name, key)
			}
		}
	}

	if len(problems) != 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func sortedStringKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func envOrDefault(lookup LookupEnv, key, fallback string) string {
	if value, ok := lookup(key); ok {
		return value
	}
	return fallback
}

func validateListen(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("listen must be host:port: %w", err)
	}
	_ = host
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("listen port must be between 1 and 65535")
	}
	return nil
}

func validateAbsoluteDir(field, path string) error {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Clean(path) == string(filepath.Separator) {
		return fmt.Errorf("%s must be a clean absolute path other than the filesystem root", field)
	}
	return nil
}

func validateHTTPSURL(field, raw string, allowLoopbackHTTP bool) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials, query, or fragment", field)
	}
	if parsed.Scheme != "https" {
		if !(allowLoopbackHTTP && parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
			return nil, fmt.Errorf("%s must use HTTPS except for loopback development", field)
		}
	}
	return parsed, nil
}

func validateOrigin(raw string) (*url.URL, error) {
	parsed, err := validateHTTPSURL("origin", raw, true)
	if err != nil {
		return nil, err
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("origin must not contain a path")
	}
	return parsed, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func sameOrigin(left, right *url.URL) bool {
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}

func validateSecretKeyRef(field string, ref SecretKeyRef, problems *[]string) {
	if !isKubernetesNamespace(ref.Namespace) {
		*problems = append(*problems, field+".namespace is invalid")
	}
	if !isKubernetesSecretName(ref.Name) {
		*problems = append(*problems, field+".name is invalid")
	}
	if len(ref.Key) == 0 || len(ref.Key) > 253 || !secretKeyPattern.MatchString(ref.Key) {
		*problems = append(*problems, field+".key is invalid")
	}
}

func isKubernetesNamespace(value string) bool {
	return len(value) <= 63 && dnsLabelPattern.MatchString(value)
}

func isKubernetesSecretName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) > 63 || !dnsLabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func isKubernetesNamePrefix(value string) bool {
	if !strings.HasSuffix(value, "-") || len(value) > 252 {
		return false
	}
	return isKubernetesSecretName(strings.TrimSuffix(value, "-"))
}

func pathWithinAny(path string, roots []string) bool {
	cleanPath := filepath.Clean(path)
	for _, root := range roots {
		if pathWithin(cleanPath, filepath.Clean(root)) {
			return true
		}
	}
	return false
}

func pathsOverlap(left, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
