package config

import (
	"bytes"
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
	maxServerConfigBytes = 1 << 20
)

var (
	identifierPattern         = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
	resourceIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)
	labelKeyPattern           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)
	labelValuePattern         = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
	dnsLabelPattern           = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$`)
	secretKeyPattern          = regexp.MustCompile(`^[-._A-Za-z0-9]+$`)
	yamlUnknownFieldPattern   = regexp.MustCompile(`^line [0-9]+: field ([A-Za-z0-9_.-]{1,128}) not found in type .+$`)
	yamlDuplicateKeyPattern   = regexp.MustCompile(`^line [0-9]+: mapping key "([A-Za-z0-9_.-]{1,128})" already defined at line [0-9]+$`)
	allowedRoles              = map[string]struct{}{
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
	configPath         string
	startupOverrides   StartupOptions
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

type TargetIdentity struct {
	StateID string
	Name    string
	URL     string
	Space   string
}

type NormalizedTargetConfig struct {
	StateID       string            `json:"stateID"`
	Name          string            `json:"name"`
	URL           string            `json:"url"`
	Space         string            `json:"space"`
	ResourceSetID string            `json:"resourceSetID"`
	Labels        map[string]string `json:"labels"`
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
	before, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect server config: %w", err)
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("inspect server config: path must resolve to a regular file")
	}
	if before.Size() > maxServerConfigBytes {
		return nil, errors.New("read server config: file exceeds the 1 MiB limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open server config: %w", err)
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect open server config: %w", err)
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("open server config: file changed while opening")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxServerConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read server config: %w", err)
	}
	if len(contents) > maxServerConfigBytes {
		return nil, errors.New("read server config: file exceeds the 1 MiB limit")
	}
	final, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect read server config: %w", err)
	}
	if final.Size() != after.Size() || !final.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("read server config: file changed while reading")
	}

	cfg := &ServerConfig{Listen: DefaultListenAddress, StateDir: DefaultStateDir}
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode server config: %w", sanitizeYAMLDecodeError(err))
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("decode server config: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode server config: %w", sanitizeYAMLDecodeError(err))
	}
	cfg.configPath = path
	return cfg, nil
}

func sanitizeYAMLDecodeError(err error) error {
	var typeError *yaml.TypeError
	if errors.As(err, &typeError) {
		for _, issue := range typeError.Errors {
			if match := yamlUnknownFieldPattern.FindStringSubmatch(issue); len(match) == 2 {
				return fmt.Errorf("unknown field %q", match[1])
			}
			if match := yamlDuplicateKeyPattern.FindStringSubmatch(issue); len(match) == 2 {
				return fmt.Errorf("duplicate key %q", match[1])
			}
		}
	}
	return errors.New("invalid YAML")
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
	cfg.startupOverrides = options
}

func (cfg *ServerConfig) RuntimeConfigPath() string {
	if cfg == nil {
		return ""
	}
	return cfg.configPath
}

func (cfg *ServerConfig) StartupOverrides() StartupOptions {
	if cfg == nil {
		return StartupOptions{}
	}
	return cfg.startupOverrides
}

func (cfg *ServerConfig) TargetIdentity(name string) (TargetIdentity, error) {
	if cfg == nil {
		return TargetIdentity{}, errors.New("server config is nil")
	}
	if !resourceIdentifierPattern.MatchString(name) {
		return TargetIdentity{}, errors.New("target name is invalid")
	}
	target, ok := cfg.Targets[name]
	if !ok {
		return TargetIdentity{}, fmt.Errorf("target %q is not configured", name)
	}
	normalizedURL, err := normalizeTargetURL(target.URL)
	if err != nil {
		return TargetIdentity{}, fmt.Errorf("target %q URL: %w", name, err)
	}
	space := target.Space
	if space == "" {
		space = "default"
	}
	if len(cfg.StateID) > 128 || !identifierPattern.MatchString(cfg.StateID) || len(space) > 128 || !identifierPattern.MatchString(space) {
		return TargetIdentity{}, fmt.Errorf("target %q identity is invalid", name)
	}
	return TargetIdentity{StateID: cfg.StateID, Name: name, URL: normalizedURL, Space: space}, nil
}

func (cfg *ServerConfig) NormalizeTargetConfig(name string) (NormalizedTargetConfig, error) {
	identity, err := cfg.TargetIdentity(name)
	if err != nil {
		return NormalizedTargetConfig{}, err
	}
	target := cfg.Targets[name]
	labels := make(map[string]string, len(target.Labels))
	for key, value := range target.Labels {
		labels[key] = value
	}
	return NormalizedTargetConfig{
		StateID: identity.StateID, Name: identity.Name, URL: identity.URL, Space: identity.Space,
		ResourceSetID: target.ResourceSet, Labels: labels,
	}, nil
}

func (cfg *ServerConfig) ValidateStartup() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if cfg.APIVersion != ServerAPIVersion {
		add("apiVersion must be %q", ServerAPIVersion)
	}
	if len(cfg.StateID) > 128 || !identifierPattern.MatchString(cfg.StateID) {
		add("stateID must be at most 128 characters, use letters, digits, underscore, dot, or dash, and start with a letter, digit, or underscore")
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
	} else if resolved, err := filepath.EvalSymlinks(cfg.StateDir); err == nil && resolved == string(filepath.Separator) {
		add("stateDir must not resolve to the filesystem root")
	} else if err != nil && hasUnresolvedSymlink(cfg.StateDir) {
		add("stateDir must not traverse an unresolved symlink")
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
		if resolved, err := filepath.EvalSymlinks(clean); err == nil && resolved == string(filepath.Separator) {
			add("mountRoots[%d] must not resolve to the filesystem root", index)
		} else if err != nil && hasUnresolvedSymlink(clean) {
			add("mountRoots[%d] must not traverse an unresolved symlink", index)
		}
		if _, exists := seenRoots[clean]; exists {
			add("mountRoots contains duplicate path %q", clean)
		}
		seenRoots[clean] = struct{}{}
		if filepath.IsAbs(cfg.StateDir) && (pathsOverlap(cfg.StateDir, clean) || resolvedPathsOverlap(cfg.StateDir, clean)) {
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
	if issuerURL != nil && publicURL != nil && canonicalURL(issuerURL) == canonicalURL(publicURL) {
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
		if !resourceIdentifierPattern.MatchString(name) {
			add("resourceSets contains invalid name %q", name)
		}
		if err := validateAbsoluteDir("resourceSets."+name+".path", set.Path); err != nil {
			add("%v", err)
		} else if hasUnresolvedSymlink(set.Path) {
			add("resourceSets.%s.path must not traverse an unresolved symlink", name)
		} else if !pathWithinAny(set.Path, cfg.MountRoots) || resolvedPathEscapesRoots(set.Path, cfg.MountRoots) {
			add("resourceSets.%s.path must be within a configured mount root", name)
		}
		cleanRevision := filepath.Clean(set.RevisionFile)
		if set.RevisionFile != "" && (filepath.IsAbs(set.RevisionFile) || cleanRevision != set.RevisionFile || cleanRevision == "." || cleanRevision == ".." || strings.HasPrefix(cleanRevision, ".."+string(filepath.Separator))) {
			add("resourceSets.%s.revisionFile must be a clean relative path", name)
		}
	}
	for _, name := range sortedStringKeys(cfg.Targets) {
		target := cfg.Targets[name]
		if !resourceIdentifierPattern.MatchString(name) {
			add("targets contains invalid name %q", name)
		}
		if _, err := validateHTTPSURL("targets."+name+".url", target.URL, true); err != nil {
			add("%v", err)
		}
		space := target.Space
		if space == "" {
			space = "default"
		}
		if len(space) > 128 || !identifierPattern.MatchString(space) {
			add("targets.%s.space is invalid", name)
		}
		if !resourceIdentifierPattern.MatchString(target.ResourceSet) {
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
		if len(target.Labels) > 64 {
			add("targets.%s.labels must contain at most 64 entries", name)
		}
		for _, key := range sortedStringKeys(target.Labels) {
			if !labelKeyPattern.MatchString(key) {
				add("targets.%s.labels contains invalid key %q", name, key)
			}
			if !labelValuePattern.MatchString(target.Labels[key]) {
				add("targets.%s.labels.%s contains an invalid value", name, key)
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
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || strings.HasSuffix(parsed.Host, ":") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("%s must be an absolute URL without credentials, query, or fragment", field)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		if !(allowLoopbackHTTP && strings.EqualFold(parsed.Scheme, "http") && isLoopbackHost(parsed.Hostname())) {
			return nil, fmt.Errorf("%s must use HTTPS except for loopback development", field)
		}
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return nil, fmt.Errorf("%s contains an invalid port", field)
		}
	}
	return parsed, nil
}

func normalizeTargetURL(raw string) (string, error) {
	parsed, err := validateHTTPSURL("target URL", raw, true)
	if err != nil {
		return "", err
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	parsed.Host = hostname
	if port != "" {
		parsed.Host += ":" + port
	}
	if parsed.Path == "/" {
		parsed.Path = ""
		parsed.RawPath = ""
	}
	return parsed.String(), nil
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
	return canonicalOrigin(left) == canonicalOrigin(right)
}

func canonicalOrigin(value *url.URL) string {
	scheme := strings.ToLower(value.Scheme)
	hostname := strings.ToLower(value.Hostname())
	port := value.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	if port != "" {
		hostname += ":" + port
	}
	return scheme + "://" + hostname
}

func canonicalURL(value *url.URL) string {
	copy := *value
	copy.Scheme = strings.ToLower(copy.Scheme)
	copy.Host = strings.TrimPrefix(canonicalOrigin(value), copy.Scheme+"://")
	if copy.Path == "/" {
		copy.Path = ""
		copy.RawPath = ""
	}
	return copy.String()
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

func hasUnresolvedSymlink(path string) bool {
	if _, err := filepath.EvalSymlinks(path); err == nil {
		return false
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return false
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func resolvedPathsOverlap(left, right string) bool {
	resolvedLeft, leftErr := filepath.EvalSymlinks(left)
	resolvedRight, rightErr := filepath.EvalSymlinks(right)
	return leftErr == nil && rightErr == nil && pathsOverlap(resolvedLeft, resolvedRight)
}

func resolvedPathEscapesRoots(path string, roots []string) bool {
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false
	}
	resolvedAnyRoot := false
	for _, root := range roots {
		resolvedRoot, err := filepath.EvalSymlinks(root)
		if err != nil {
			continue
		}
		resolvedAnyRoot = true
		if pathWithin(resolvedPath, resolvedRoot) {
			return false
		}
	}
	return resolvedAnyRoot
}

func pathWithin(path, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
