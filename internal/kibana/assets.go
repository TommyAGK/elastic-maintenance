package kibana

import (
	"context"
	"fmt"
	"strings"

	"elastic-maintenance/internal/config"
)

func normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func ruleKey(r config.Rule) string {
	if k := normalize(r.RuleID); k != "" { return k }
	return normalize(r.Name) + "|" + normalize(r.Type)
}

func policyKey(name, namespace string) string {
	ns := namespace
	if ns == "" { ns = "default" }
	return normalize(name) + "|" + normalize(ns)
}

func (c *Client) ReviewIntegrations(items []config.Integration) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.InstalledPackages(ctx)
	if err != nil { return nil, err }
	existingMap := map[string]InstalledPackage{}
	for _, item := range existing { existingMap[normalize(item.Name)] = item }
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
	if err != nil { return nil, err }
	existingMap := map[string]PackagePolicy{}
	for _, item := range existing { existingMap[policyKey(item.Name, item.Namespace)] = item }
	var out []ReviewChange
	for _, item := range items {
		if _, ok := existingMap[policyKey(item.Name, "default")]; !ok {
			out = append(out, ReviewChange{Kind: "fleet_policy", Name: item.Name, Action: "create"})
		}
	}
	return out, nil
}

func (c *Client) ReviewRules(items []config.Rule) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.Rules(ctx)
	if err != nil { return nil, err }
	existingMap := map[string]Rule{}
	for _, item := range existing { existingMap[normalize(item.RuleID)] = item }
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
		if cur.Enabled != item.Enabled || cur.Type != item.Type || cur.Query != item.Query || cur.Index != item.Index {
			out = append(out, ReviewChange{Kind: "rule", Name: item.Name, Action: "update"})
		}
	}
	return out, nil
}

func (c *Client) EnsureIntegrations(items []config.Integration) (int, error) {
	ctx := context.Background()
	planned := 0
	for _, item := range items {
		if err := c.installPackage(ctx, item.Name, item.Version); err != nil { return planned, err }
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureFleetPolicies(items []config.FleetPolicy) (int, error) {
	ctx := context.Background()
	existing, err := c.PackagePolicies(ctx)
	if err != nil { return 0, err }
	byName := map[string]PackagePolicy{}
	for _, item := range existing { byName[policyKey(item.Name, item.Namespace)] = item }
	planned := 0
	for _, item := range items {
		key := policyKey(item.Name, "default")
		if cur, ok := byName[key]; ok {
		req := UpdatePackagePolicyRequest{Name: item.Name, Namespace: "default"}
			if err := c.putJSON(ctx, fmt.Sprintf("/api/fleet/package_policies/%s", cur.ID), req, nil); err != nil { return planned, err }
		} else {
			req := CreatePackagePolicyRequest{Name: item.Name, Namespace: "default"}
			if err := c.postJSON(ctx, "/api/fleet/package_policies", req, nil); err != nil { return planned, err }
		}
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureRules(items []config.Rule) (int, error) {
	ctx := context.Background()
	existing, err := c.Rules(ctx)
	if err != nil { return 0, err }
	byKey := map[string]Rule{}
	for _, item := range existing {
		key := normalize(item.RuleID)
		if key == "" { key = normalize(item.Name) + "|" + normalize(item.Type) }
		byKey[key] = item
	}
	planned := 0
	for _, item := range items {
		key := ruleKey(item)
		req := CreateRuleRequest{RuleID: item.RuleID, Name: item.Name, Type: item.Type, Enabled: item.Enabled, Query: item.Query, Severity: item.Severity, Interval: item.Interval, Language: item.Language, Index: item.Index}
		if cur, ok := byKey[key]; ok {
			if err := c.putJSON(ctx, fmt.Sprintf("/api/detection_engine/rules/%s", cur.ID), req, nil); err != nil { return planned, err }
		} else {
			path := "/api/detection_engine/rules"
			if item.Prebuilt && item.RuleID != "" { path = fmt.Sprintf("/api/detection_engine/rules?rule_id=%s", item.RuleID) }
			if err := c.postJSON(ctx, path, req, nil); err != nil { return planned, err }
		}
		planned++
	}
	return planned, nil
}

func (c *Client) installPackage(ctx context.Context, name, version string) error {
	if version == "" { version = "latest" }
	return c.postJSON(ctx, fmt.Sprintf("/api/fleet/epm/packages/%s/%s", name, version), map[string]any{"ignore_constraints": false}, nil)
}
