package kibana

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const liveFingerprintVersion = "v1"

var liveIntervalPattern = regexp.MustCompile(`^[1-9][0-9]*[smhd]$`)
var ErrResourceNotManageable = errors.New("Kibana resource is not manageable")

type LiveFingerprint struct {
	Algorithm string `json:"algorithm"`
	Version   string `json:"version"`
	Value     string `json:"value"`
}

type InstalledPackage struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	Title          string `json:"title"`
	Status         string `json:"status"`
	updateBaseline json.RawMessage
}
type AgentPolicy struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	Description    string `json:"description"`
	Status         string `json:"status"`
	IsManaged      bool   `json:"is_managed"`
	IsProtected    bool   `json:"is_protected"`
	Revision       int    `json:"revision"`
	updateBaseline json.RawMessage
}
type PackagePolicyPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Title   string `json:"title"`
}
type PackagePolicy struct {
	ID             string               `json:"id"`
	Name           string               `json:"name"`
	Namespace      string               `json:"namespace"`
	Description    string               `json:"description"`
	Enabled        bool                 `json:"enabled"`
	Revision       int                  `json:"revision"`
	PolicyIDs      []string             `json:"policy_ids"`
	Package        PackagePolicyPackage `json:"package"`
	updateBaseline json.RawMessage      `json:"-"`
}
type Rule struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"rule_id"`
	Name           string   `json:"name"`
	Type           string   `json:"type"`
	Enabled        bool     `json:"enabled"`
	Query          string   `json:"query"`
	Severity       string   `json:"severity"`
	Interval       string   `json:"interval"`
	Language       string   `json:"language"`
	Index          []string `json:"index"`
	Revision       int      `json:"revision"`
	Version        int      `json:"version"`
	Immutable      bool     `json:"immutable"`
	Tags           []string `json:"tags"`
	Manageable     bool     `json:"-"`
	updateBaseline json.RawMessage
}
type PrebuiltStatus struct {
	RulesCustomInstalled  int             `json:"rules_custom_installed"`
	RulesInstalled        int             `json:"rules_installed"`
	RulesNotInstalled     int             `json:"rules_not_installed"`
	RulesNotUpdated       int             `json:"rules_not_updated"`
	TimelinesInstalled    int             `json:"timelines_installed"`
	TimelinesNotInstalled int             `json:"timelines_not_installed"`
	TimelinesNotUpdated   int             `json:"timelines_not_updated"`
	updateBaseline        json.RawMessage `json:"-"`
}

type IntegrationPackageProjection struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type AgentPolicyProjection struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}
type PackagePolicyProjection struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace"`
	PackageName    string   `json:"packageName"`
	PackageVersion string   `json:"packageVersion"`
	AgentPolicyIDs []string `json:"agentPolicyIDs"`
}
type DetectionRuleProjection struct {
	RuleID   string   `json:"ruleID"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Enabled  bool     `json:"enabled"`
	Query    string   `json:"query"`
	Severity string   `json:"severity"`
	Interval string   `json:"interval"`
	Language string   `json:"language"`
	Index    []string `json:"index"`
}
type PrebuiltStatusProjection struct {
	RulesCustomInstalled  int `json:"rulesCustomInstalled"`
	RulesInstalled        int `json:"rulesInstalled"`
	RulesNotInstalled     int `json:"rulesNotInstalled"`
	RulesNotUpdated       int `json:"rulesNotUpdated"`
	TimelinesInstalled    int `json:"timelinesInstalled"`
	TimelinesNotInstalled int `json:"timelinesNotInstalled"`
	TimelinesNotUpdated   int `json:"timelinesNotUpdated"`
}

func cloneBaseline(value json.RawMessage) json.RawMessage { return append(json.RawMessage{}, value...) }
func (value InstalledPackage) Baseline() json.RawMessage  { return cloneBaseline(value.updateBaseline) }
func (value AgentPolicy) Baseline() json.RawMessage       { return cloneBaseline(value.updateBaseline) }
func (value PackagePolicy) Baseline() json.RawMessage     { return cloneBaseline(value.updateBaseline) }
func (value Rule) Baseline() json.RawMessage              { return cloneBaseline(value.updateBaseline) }
func (value PrebuiltStatus) Baseline() json.RawMessage    { return cloneBaseline(value.updateBaseline) }

func (value *InstalledPackage) UnmarshalJSON(data []byte) error {
	if !validStrictJSONStrings(data) {
		return adapterProtocolError()
	}
	type wire InstalledPackage
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*value = InstalledPackage(decoded)
	value.updateBaseline = append([]byte{}, data...)
	return nil
}
func (value *AgentPolicy) UnmarshalJSON(data []byte) error {
	if !validStrictJSONStrings(data) {
		return adapterProtocolError()
	}
	type wire AgentPolicy
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*value = AgentPolicy(decoded)
	value.updateBaseline = append([]byte{}, data...)
	return nil
}
func (value *PackagePolicy) UnmarshalJSON(data []byte) error {
	if !validStrictJSONStrings(data) {
		return adapterProtocolError()
	}
	type wire PackagePolicy
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*value = PackagePolicy(decoded)
	value.updateBaseline = append([]byte{}, data...)
	return nil
}
func (value *Rule) UnmarshalJSON(data []byte) error {
	if !validStrictJSONStrings(data) {
		return adapterProtocolError()
	}
	type wire Rule
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*value = Rule(decoded)
	value.updateBaseline = append([]byte{}, data...)
	return nil
}
func (value *PrebuiltStatus) UnmarshalJSON(data []byte) error {
	if !validStrictJSONStrings(data) {
		return adapterProtocolError()
	}
	type wire PrebuiltStatus
	var decoded wire
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*value = PrebuiltStatus(decoded)
	value.updateBaseline = append([]byte{}, data...)
	return nil
}

func (value InstalledPackage) Canonical() (IntegrationPackageProjection, LiveFingerprint, error) {
	projection := IntegrationPackageProjection{Name: value.Name, Version: value.Version}
	if !validInstalled(value) {
		return projection, LiveFingerprint{}, adapterProtocolError()
	}
	fingerprint, err := liveFingerprint("integration-package", projection)
	return projection, fingerprint, err
}
func (value AgentPolicy) Canonical() (AgentPolicyProjection, LiveFingerprint, error) {
	projection := AgentPolicyProjection{ID: value.ID, Name: value.Name, Namespace: value.Namespace}
	if !validAgent(value) {
		return projection, LiveFingerprint{}, adapterProtocolError()
	}
	fingerprint, err := liveFingerprint("agent-policy", projection)
	return projection, fingerprint, err
}
func (value PackagePolicy) Canonical() (PackagePolicyProjection, LiveFingerprint, error) {
	ids, err := canonicalStrings(value.PolicyIDs)
	projection := PackagePolicyProjection{ID: value.ID, Name: value.Name, Namespace: value.Namespace, PackageName: value.Package.Name, PackageVersion: value.Package.Version, AgentPolicyIDs: ids}
	if err != nil || !validPackagePolicy(value) {
		return projection, LiveFingerprint{}, adapterProtocolError()
	}
	fingerprint, err := liveFingerprint("package-policy", projection)
	return projection, fingerprint, err
}
func (value Rule) Canonical() (DetectionRuleProjection, LiveFingerprint, error) {
	indexes, err := canonicalStrings(value.Index)
	projection := DetectionRuleProjection{RuleID: value.RuleID, Name: value.Name, Type: value.Type, Enabled: value.Enabled, Query: value.Query, Severity: value.Severity, Interval: value.Interval, Language: value.Language, Index: indexes}
	if err != nil || value.Immutable || !validRule(value) {
		return projection, LiveFingerprint{}, adapterProtocolError()
	}
	fingerprint, err := liveFingerprint("detection-rule", projection)
	return projection, fingerprint, err
}
func (value PrebuiltStatus) Canonical() (PrebuiltStatusProjection, LiveFingerprint, error) {
	projection := PrebuiltStatusProjection{value.RulesCustomInstalled, value.RulesInstalled, value.RulesNotInstalled, value.RulesNotUpdated, value.TimelinesInstalled, value.TimelinesNotInstalled, value.TimelinesNotUpdated}
	if !validPrebuilt(value) {
		return projection, LiveFingerprint{}, adapterProtocolError()
	}
	fingerprint, err := liveFingerprint("prebuilt-rules", projection)
	return projection, fingerprint, err
}

func (c *Client) InstalledPackages(ctx context.Context) ([]InstalledPackage, error) {
	items, err := c.installedPackages(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range items {
		if _, _, canonicalErr := item.Canonical(); canonicalErr != nil {
			return nil, canonicalErr
		}
		key := strings.ToLower(item.Name)
		if seen[key] {
			return nil, adapterProtocolError()
		}
		seen[key] = true
	}
	return items, nil
}
func (c *Client) AgentPolicies(ctx context.Context) ([]AgentPolicy, error) {
	items, err := c.agentPolicies(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range items {
		if _, _, canonicalErr := item.Canonical(); canonicalErr != nil {
			return nil, canonicalErr
		}
		if seen[item.ID] {
			return nil, adapterProtocolError()
		}
		seen[item.ID] = true
	}
	return items, nil
}
func (c *Client) PackagePolicies(ctx context.Context) ([]PackagePolicy, error) {
	items, err := c.packagePolicies(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, item := range items {
		if _, _, canonicalErr := item.Canonical(); canonicalErr != nil {
			return nil, canonicalErr
		}
		if seen[item.ID] {
			return nil, adapterProtocolError()
		}
		seen[item.ID] = true
	}
	return items, nil
}
func (c *Client) Rules(ctx context.Context) ([]Rule, error) {
	items, err := c.rules(ctx)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for index := range items {
		item := &items[index]
		if !validRuleIdentity(*item) || seen[item.RuleID] {
			return nil, adapterProtocolError()
		}
		seen[item.RuleID] = true
		if item.Immutable || item.Type != "query" {
			item.Manageable = false
			continue
		}
		if _, _, canonicalErr := item.Canonical(); canonicalErr != nil {
			return nil, canonicalErr
		}
		item.Manageable = containsString(item.Tags, managedRuleTag)
	}
	return items, nil
}

func (c *Client) IntegrationPackage(ctx context.Context, name, version string) (InstalledPackage, error) {
	safeName, nameErr := safePathSegment(name)
	safeVersion, versionErr := safePathSegment(version)
	if nameErr != nil || versionErr != nil || !exactPackageVersionPattern.MatchString(version) {
		return InstalledPackage{}, errors.New("exact Kibana package name and version are required")
	}
	var response struct {
		Item InstalledPackage `json:"item"`
	}
	if err := c.getJSON(ctx, "/api/fleet/epm/packages/"+safeName+"/"+safeVersion, &response); err != nil {
		return InstalledPackage{}, err
	}
	_, _, canonicalErr := response.Item.Canonical()
	if canonicalErr != nil || response.Item.Name != name || response.Item.Version != version {
		return InstalledPackage{}, adapterProtocolError()
	}
	return response.Item, nil
}
func (c *Client) AgentPolicy(ctx context.Context, id string) (AgentPolicy, error) {
	segment, err := safePathSegment(id)
	if err != nil {
		return AgentPolicy{}, err
	}
	var response struct {
		Item AgentPolicy `json:"item"`
	}
	if err := c.getJSON(ctx, "/api/fleet/agent_policies/"+segment, &response); err != nil {
		return AgentPolicy{}, err
	}
	_, _, canonicalErr := response.Item.Canonical()
	if canonicalErr != nil || response.Item.ID != id {
		return AgentPolicy{}, adapterProtocolError()
	}
	return response.Item, nil
}
func (c *Client) PackagePolicy(ctx context.Context, id string) (PackagePolicy, error) {
	segment, err := safePathSegment(id)
	if err != nil {
		return PackagePolicy{}, err
	}
	var response struct {
		Item PackagePolicy `json:"item"`
	}
	if err := c.getJSON(ctx, "/api/fleet/package_policies/"+segment, &response); err != nil {
		return PackagePolicy{}, err
	}
	_, _, canonicalErr := response.Item.Canonical()
	if canonicalErr != nil || response.Item.ID != id {
		return PackagePolicy{}, adapterProtocolError()
	}
	return response.Item, nil
}
func (c *Client) Rule(ctx context.Context, ruleID string) (Rule, error) {
	if !safeSegmentPattern.MatchString(ruleID) {
		return Rule{}, errors.New("Kibana rule identifier is invalid")
	}
	query := url.Values{"rule_id": {ruleID}}
	var result Rule
	if err := c.getJSON(ctx, "/api/detection_engine/rules?"+query.Encode(), &result); err != nil {
		return Rule{}, err
	}
	if result.Immutable || result.Type != "query" {
		return Rule{}, ErrResourceNotManageable
	}
	_, _, canonicalErr := result.Canonical()
	if canonicalErr != nil || result.RuleID != ruleID {
		return Rule{}, adapterProtocolError()
	}
	return result, nil
}
func (c *Client) PrebuiltStatus(ctx context.Context) (PrebuiltStatus, error) {
	var result PrebuiltStatus
	if err := c.getJSON(ctx, "/api/detection_engine/rules/prepackaged/_status", &result); err != nil {
		return PrebuiltStatus{}, err
	}
	if _, _, canonicalErr := result.Canonical(); canonicalErr != nil {
		return PrebuiltStatus{}, adapterProtocolError()
	}
	return result, nil
}

func validInstalled(value InstalledPackage) bool {
	return safeSegmentPattern.MatchString(value.Name) && exactPackageVersionPattern.MatchString(value.Version) && value.Status == "installed" && requiredFields(value.updateBaseline, "name", "version", "status")
}
func validAgent(value AgentPolicy) bool {
	return safeSegmentPattern.MatchString(value.ID) && validLiveText(value.Name, 1024) && safeSegmentPattern.MatchString(value.Namespace) && value.Revision >= 0 && requiredFields(value.updateBaseline, "id", "name", "namespace", "is_managed", "is_protected", "revision")
}
func validPackagePolicy(value PackagePolicy) bool {
	if !safeSegmentPattern.MatchString(value.ID) || !validLiveText(value.Name, 1024) || !safeSegmentPattern.MatchString(value.Namespace) || !safeSegmentPattern.MatchString(value.Package.Name) || !exactPackageVersionPattern.MatchString(value.Package.Version) || value.Revision < 0 || len(value.PolicyIDs) == 0 || !requiredFields(value.updateBaseline, "id", "name", "namespace", "enabled", "revision", "policy_ids", "package", "inputs") {
		return false
	}
	for _, id := range value.PolicyIDs {
		if !safeSegmentPattern.MatchString(id) {
			return false
		}
	}
	return true
}
func validRuleIdentity(value Rule) bool {
	return safeSegmentPattern.MatchString(value.RuleID) && validLiveText(value.Name, 256) && safeSegmentPattern.MatchString(value.Type) && requiredFields(value.updateBaseline, "rule_id", "name", "type", "immutable")
}
func validRule(value Rule) bool {
	return safeSegmentPattern.MatchString(value.RuleID) && validLiveText(value.Name, 256) && value.Type == "query" && validLiveText(value.Query, 64<<10) && (value.Severity == "low" || value.Severity == "medium" || value.Severity == "high" || value.Severity == "critical") && validLiveText(value.Interval, 128) && liveIntervalPattern.MatchString(value.Interval) && (value.Language == "kuery" || value.Language == "lucene") && len(value.Index) > 0 && len(value.Index) <= 1024 && value.Revision >= 0 && value.Version >= 0 && requiredFields(value.updateBaseline, "rule_id", "name", "type", "enabled", "query", "severity", "interval", "language", "index", "revision", "version", "immutable", "tags")
}
func validPrebuilt(value PrebuiltStatus) bool {
	return value.RulesCustomInstalled >= 0 && value.RulesInstalled >= 0 && value.RulesNotInstalled >= 0 && value.RulesNotUpdated >= 0 && value.TimelinesInstalled >= 0 && value.TimelinesNotInstalled >= 0 && value.TimelinesNotUpdated >= 0 && requiredFields(value.updateBaseline, "rules_custom_installed", "rules_installed", "rules_not_installed", "rules_not_updated", "timelines_installed", "timelines_not_installed", "timelines_not_updated")
}
func validStrictJSONStrings(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inside := false
	for index := 0; index < len(data); index++ {
		char := data[index]
		if !inside {
			if char == '"' {
				inside = true
			}
			continue
		}
		if char == '"' {
			inside = false
			continue
		}
		if char < 0x20 {
			return false
		}
		if char != '\\' {
			continue
		}
		index++
		if index >= len(data) {
			return false
		}
		if data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[index+1:index+5]), 16, 16)
		if err != nil {
			return false
		}
		index += 4
		if value >= 0xD800 && value <= 0xDBFF {
			if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[index+3:index+7]), 16, 16)
			if err != nil || low < 0xDC00 || low > 0xDFFF {
				return false
			}
			index += 6
		} else if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
	}
	return !inside
}
func requiredFields(raw json.RawMessage, names ...string) bool {
	if len(raw) == 0 {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	for _, name := range names {
		value, exists := fields[name]
		if !exists || string(value) == "null" {
			return false
		}
	}
	return true
}
func validLiveText(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.Is(unicode.Categories["C"], char) {
			return false
		}
	}
	return true
}
func canonicalStrings(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 1024 {
		return nil, adapterProtocolError()
	}
	result := append([]string{}, values...)
	sort.Strings(result)
	for index, value := range result {
		if !validLiveText(value, 256) || index > 0 && result[index-1] == value {
			return nil, adapterProtocolError()
		}
	}
	return result, nil
}
func liveFingerprint(kind string, value any) (LiveFingerprint, error) {
	encoded, err := marshalLiveCanonicalJSON(value)
	if err != nil {
		return LiveFingerprint{}, adapterProtocolError()
	}
	hash := sha256.New()
	for _, part := range []string{"elastic-maintainer/kibana-live", liveFingerprintVersion, kind} {
		hash.Write([]byte(part))
		hash.Write([]byte{0})
	}
	hash.Write(encoded)
	return LiveFingerprint{Algorithm: "sha256", Version: liveFingerprintVersion, Value: hex.EncodeToString(hash.Sum(nil))}, nil
}
func adapterProtocolError() error {
	return &ResponseError{StatusCode: 0, Message: "Kibana adapter response is invalid", kind: ErrorProtocol}
}
