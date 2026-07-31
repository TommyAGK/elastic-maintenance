package kibana

import (
	"context"
	"fmt"

	"elastic-maintenance/internal/config"
)

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
	planned := 0
	for _, item := range items {
		req := CreatePackagePolicyRequest{Name: item.Name, Namespace: "default"}
		if err := c.postJSON(ctx, "/api/fleet/package_policies", req, nil); err != nil {
			return planned, err
		}
		planned++
	}
	return planned, nil
}

func (c *Client) EnsureRules(items []config.Rule) (int, error) {
	ctx := context.Background()
	planned := 0
	for _, item := range items {
		req := CreateRuleRequest{
			RuleID:   item.RuleID,
			Name:     item.Name,
			Type:     item.Type,
			Enabled:  item.Enabled,
			Query:    item.Query,
			Severity: item.Severity,
			Interval: item.Interval,
			Language: item.Language,
			Index:    item.Index,
		}
		path := "/api/detection_engine/rules"
		if item.Prebuilt && item.RuleID != "" {
			path = fmt.Sprintf("/api/detection_engine/rules?rule_id=%s", item.RuleID)
		}
		if err := c.postJSON(ctx, path, req, nil); err != nil {
			return planned, err
		}
		planned++
	}
	return planned, nil
}

func (c *Client) installPackage(ctx context.Context, name, version string) error {
	if version == "" {
		version = "latest"
	}
	return c.postJSON(ctx, fmt.Sprintf("/api/fleet/epm/packages/%s/%s", name, version), map[string]any{"ignore_constraints": false}, nil)
}
