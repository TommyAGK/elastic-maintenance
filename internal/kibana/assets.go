package kibana

import (
	"context"
	"fmt"

	"elastic-maintenance/internal/config"
)

func (c *Client) ReviewIntegrations(items []config.Integration) ([]ReviewChange, error) {
	ctx := context.Background()
	existing, err := c.InstalledPackages(ctx)
	if err != nil { return nil, err }
	existingMap := map[string]InstalledPackage{}
	for _, item := range existing {
		existingMap[item.Name] = item
	}
	var out []ReviewChange
	for _, item := range items {
		cur, ok := existingMap[item.Name]
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
	for _, item := range existing {
		existingMap[item.Name] = item
	}
	var out []ReviewChange
	for _, item := range items {
		if _, ok := existingMap[item.Name]; !ok {
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
	for _, item := range existing {
		key := item.RuleID
		if key == "" { key = item.Name }
		existingMap[key] = item
	}
	var out []ReviewChange
	for _, item := range items {
		key := item.RuleID
		if key == "" { key = item.Name }
		cur, ok := existingMap[key]
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
	planned := 0
	for _, item := range items {
		req := CreatePackagePolicyRequest{Name: item.Name, Namespace: "default"}
		if err := c.postJSON(ctx, "/api/fleet/package_policies", req, nil); err != nil { return planned, err }
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureRules(items []config.Rule) (int, error) {
	ctx := context.Background()
	planned := 0
	for _, item := range items {
		req := CreateRuleRequest{RuleID: item.RuleID, Name: item.Name, Type: item.Type, Enabled: item.Enabled, Query: item.Query, Severity: item.Severity, Interval: item.Interval, Language: item.Language, Index: item.Index}
		path := "/api/detection_engine/rules"
		if item.Prebuilt && item.RuleID != "" { path = fmt.Sprintf("/api/detection_engine/rules?rule_id=%s", item.RuleID) }
		if err := c.postJSON(ctx, path, req, nil); err != nil { return planned, err }
		planned++
	}
	return planned, nil
}

func (c *Client) installPackage(ctx context.Context, name, version string) error {
	if version == "" { version = "latest" }
	return c.postJSON(ctx, fmt.Sprintf("/api/fleet/epm/packages/%s/%s", name, version), map[string]any{"ignore_constraints": false}, nil)
}
