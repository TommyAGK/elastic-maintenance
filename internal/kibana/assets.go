package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

const managedDescriptionMarker = "[managed-by:elastic-maintainer]"
const managedRuleTag = "elastic-maintainer:managed"

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func ruleKey(r config.Rule) string {
	if k := normalize(r.RuleID); k != "" {
		return k
	}
	return normalize(r.Name) + "|" + normalize(r.Type)
}

func policyKey(name, namespace string) string {
	ns := namespace
	if ns == "" {
		ns = "default"
	}
	return normalize(name) + "|" + normalize(ns)
}

func (c *Client) ReviewIntegrations(items []config.Integration) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.InstalledPackages(ctx)
	if err != nil {
		return nil, err
	}
	existingMap := map[string]InstalledPackage{}
	for _, item := range existing {
		existingMap[normalize(item.Name)] = item
	}
	var out []ReviewChange
	for _, item := range items {
		cur, ok := existingMap[normalize(item.Name)]
		if !ok {
			out = append(out, ReviewChange{Kind: "integration", Name: item.Name, Action: "install", Details: fmt.Sprintf("version=%s", item.Version)})
			continue
		}
		if item.Version != "" && cur.Version != "" && item.Version != cur.Version {
			out = append(out, ReviewChange{Kind: "integration", Name: item.Name, Action: "update", Details: fmt.Sprintf("%s -> %s", cur.Version, item.Version)})
		}
	}
	return out, nil
}

func (c *Client) ReviewFleetPolicies(items []config.FleetPolicy) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.PackagePolicies(ctx)
	if err != nil {
		return nil, err
	}
	existingMap := map[string]PackagePolicy{}
	for _, item := range existing {
		key := policyKey(item.Name, item.Namespace)
		if _, duplicate := existingMap[key]; duplicate {
			return nil, errors.New("ambiguous Kibana package policy identity")
		}
		existingMap[key] = item
	}
	var out []ReviewChange
	for _, item := range items {
		if current, ok := existingMap[policyKey(item.Name, "default")]; ok {
			if !managedDescription(current.Description) {
				return nil, ErrResourceNotManageable
			}
		} else {
			out = append(out, ReviewChange{Kind: "fleet_policy", Name: item.Name, Action: "create"})
		}
	}
	return out, nil
}

func (c *Client) ReviewRules(items []config.Rule) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.Rules(ctx)
	if err != nil {
		return nil, err
	}
	existingMap := map[string]Rule{}
	for _, item := range existing {
		key := normalize(item.RuleID)
		if _, duplicate := existingMap[key]; duplicate {
			return nil, errors.New("ambiguous Kibana rule identity")
		}
		existingMap[key] = item
	}
	var out []ReviewChange
	for _, item := range items {
		cur, ok := existingMap[normalize(item.RuleID)]
		if !ok && normalize(item.RuleID) == "" {
			cur, ok = existingMap[normalize(item.Name)+"|"+normalize(item.Type)]
		}
		if !ok {
			out = append(out, ReviewChange{Kind: "rule", Name: item.Name, Action: "create"})
			continue
		}
		if !cur.Manageable {
			return nil, ErrResourceNotManageable
		}
		if cur.Name != item.Name || cur.Enabled != item.Enabled || cur.Type != item.Type || cur.Query != item.Query || cur.Severity != item.Severity || cur.Interval != item.Interval || cur.Language != item.Language || strings.Join(cur.Index, ",") != item.Index {
			out = append(out, ReviewChange{Kind: "rule", Name: item.Name, Action: "update"})
		}
	}
	return out, nil
}

func (c *Client) EnsureIntegrations(items []config.Integration) (int, error) {
	ctx := context.Background()
	planned := 0
	for _, item := range items {
		if err := c.installPackage(ctx, item.Name, item.Version); err != nil {
			return planned, err
		}
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureFleetPolicies(items []config.FleetPolicy) (int, error) {
	ctx := context.Background()
	existing, err := c.PackagePolicies(ctx)
	if err != nil {
		return 0, err
	}
	byName := map[string]PackagePolicy{}
	for _, item := range existing {
		key := policyKey(item.Name, item.Namespace)
		if _, duplicate := byName[key]; duplicate {
			return 0, errors.New("ambiguous Kibana package policy identity")
		}
		byName[key] = item
	}
	type preparedPolicy struct {
		id   string
		body map[string]any
	}
	prepared := map[string]preparedPolicy{}
	desiredSeen := map[string]bool{}
	for _, item := range items {
		key := policyKey(item.Name, "default")
		if desiredSeen[key] {
			return 0, ErrResourceNotManageable
		}
		desiredSeen[key] = true
		cur, ok := byName[key]
		if !ok || !managedDescription(cur.Description) {
			return 0, ErrResourceNotManageable
		}
		id, segmentErr := safePathSegment(cur.ID)
		if segmentErr != nil {
			return 0, segmentErr
		}
		body, baselineErr := baselineObject(cur.Baseline())
		if baselineErr != nil {
			return 0, baselineErr
		}
		prepared[key] = preparedPolicy{id: id, body: body}
	}
	planned := 0
	for _, item := range items {
		key := policyKey(item.Name, "default")
		operation := prepared[key]
		id, body := operation.id, operation.body
		for _, field := range []string{"id", "created_at", "created_by", "updated_at", "updated_by", "revision"} {
			delete(body, field)
		}
		body["name"] = item.Name
		body["namespace"] = "default"
		description := managedDescriptionMarker
		if item.Description != "" {
			description += " " + item.Description
		}
		body["description"] = description
		if err := c.putJSON(ctx, fmt.Sprintf("/api/fleet/package_policies/%s", id), body, nil); err != nil {
			return planned, err
		}
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureRules(items []config.Rule) (int, error) {
	ctx := context.Background()
	existing, err := c.Rules(ctx)
	if err != nil {
		return 0, err
	}
	byKey := map[string]Rule{}
	for _, item := range existing {
		key := normalize(item.RuleID)
		if key == "" {
			key = normalize(item.Name) + "|" + normalize(item.Type)
		}
		if _, duplicate := byKey[key]; duplicate {
			return 0, errors.New("ambiguous Kibana rule identity")
		}
		byKey[key] = item
	}
	desiredSeen := map[string]bool{}
	prepared := map[string]map[string]any{}
	for _, item := range items {
		if !validDesiredRule(item) {
			return 0, ErrResourceNotManageable
		}
		key := ruleKey(item)
		if desiredSeen[key] {
			return 0, ErrResourceNotManageable
		}
		desiredSeen[key] = true
		if current, ok := byKey[key]; ok {
			if !current.Manageable || current.Immutable || !containsString(current.Tags, managedRuleTag) {
				return 0, ErrResourceNotManageable
			}
			body, baselineErr := baselineObject(current.Baseline())
			if baselineErr != nil {
				return 0, baselineErr
			}
			prepared[key] = body
		}
	}
	planned := 0
	for _, item := range items {
		key := ruleKey(item)
		req := CreateRuleRequest{RuleID: item.RuleID, Name: item.Name, Type: item.Type, Enabled: item.Enabled, Query: item.Query, Severity: item.Severity, Interval: item.Interval, Language: item.Language, Index: ruleIndexes(item.Index), Tags: []string{managedRuleTag}}
		if current, ok := byKey[key]; ok {
			body := prepared[key]
			for _, field := range []string{"id", "created_at", "created_by", "updated_at", "updated_by", "revision", "version", "immutable", "rule_source"} {
				delete(body, field)
			}
			body["rule_id"] = item.RuleID
			body["name"] = item.Name
			body["type"] = item.Type
			body["enabled"] = item.Enabled
			body["query"] = item.Query
			body["severity"] = item.Severity
			body["interval"] = item.Interval
			body["language"] = item.Language
			body["index"] = ruleIndexes(item.Index)
			body["tags"] = appendManagedTag(current.Tags)
			query := url.Values{"rule_id": {item.RuleID}}
			if err := c.putJSON(ctx, "/api/detection_engine/rules?"+query.Encode(), body, nil); err != nil {
				return planned, err
			}
		} else {
			path := "/api/detection_engine/rules"
			if item.Prebuilt && item.RuleID != "" {
				path = "/api/detection_engine/rules?" + url.Values{"rule_id": {item.RuleID}}.Encode()
			}
			if err := c.postJSON(ctx, path, req, nil); err != nil {
				return planned, err
			}
		}
		planned++
	}
	return planned, nil
}

func managedDescription(value string) bool {
	return value == managedDescriptionMarker || strings.HasPrefix(value, managedDescriptionMarker+" ")
}
func validDesiredRule(item config.Rule) bool {
	if !safeSegmentPattern.MatchString(item.RuleID) || !validLiveText(item.Name, 256) || item.Type != "query" || !validLiveText(item.Query, 64<<10) || (item.Severity != "low" && item.Severity != "medium" && item.Severity != "high" && item.Severity != "critical") || !validLiveText(item.Interval, 128) || !liveIntervalPattern.MatchString(item.Interval) || (item.Language != "kuery" && item.Language != "lucene") {
		return false
	}
	indexes := ruleIndexes(item.Index)
	_, err := canonicalStrings(indexes)
	return err == nil
}
func baselineObject(raw json.RawMessage) (map[string]any, error) {
	var value map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &value) != nil {
		return nil, ErrResourceNotManageable
	}
	return value, nil
}
func appendManagedTag(values []string) []string {
	result := append([]string{}, values...)
	if !containsString(result, managedRuleTag) {
		result = append(result, managedRuleTag)
	}
	return result
}
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
func ruleIndexes(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func (c *Client) installPackage(ctx context.Context, name, version string) error {
	safeName, nameErr := safePathSegment(name)
	safeVersion, versionErr := safePathSegment(version)
	if nameErr != nil || versionErr != nil || !exactPackageVersionPattern.MatchString(version) {
		return errors.New("exact Kibana package name and version are required")
	}
	return c.postJSON(ctx, fmt.Sprintf("/api/fleet/epm/packages/%s/%s", safeName, safeVersion), map[string]any{"ignore_constraints": false}, nil)
}
