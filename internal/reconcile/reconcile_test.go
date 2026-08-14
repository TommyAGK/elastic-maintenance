package reconcile

import (
	"errors"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/kibana"
)

type fakeClient struct{}

func (fakeClient) ReviewIntegrations(items []config.Integration) ([]kibana.ReviewChange, error) {
	var out []kibana.ReviewChange
	for _, item := range items {
		out = append(out, kibana.ReviewChange{Kind: "integration", Name: item.Name, Action: "install", Details: "version=latest"})
	}
	return out, nil
}
func (fakeClient) ReviewFleetPolicies(items []config.FleetPolicy) ([]kibana.ReviewChange, error) { return []kibana.ReviewChange{{Kind: "fleet_policy", Name: "policy-a", Action: "create"}}, nil }
func (fakeClient) ReviewRules(items []config.Rule) ([]kibana.ReviewChange, error) { return []kibana.ReviewChange{{Kind: "rule", Name: "rule-b", Action: "update"}, {Kind: "rule", Name: "rule-a", Action: "create"}}, nil }
func (fakeClient) EnsureIntegrations(items []config.Integration) (int, error) { return len(items), nil }
func (fakeClient) EnsureFleetPolicies(items []config.FleetPolicy) (int, error) { return len(items), nil }
func (fakeClient) EnsureRules(items []config.Rule) (int, error) { return len(items), nil }

func TestRunReview(t *testing.T) {
	rep, err := Run(fakeClient{}, &config.DesiredState{
		Integrations:  []config.Integration{{Name: "endpoint"}},
		FleetPolicies: []config.FleetPolicy{{Name: "policy"}},
		Rules:         []config.Rule{{Name: "rule"}},
	}, ModeReview)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if rep.ChangesPlanned != 4 {
		t.Fatalf("expected 4 planned changes, got %d", rep.ChangesPlanned)
	}
	if len(rep.Changes) != 4 {
		t.Fatalf("expected 4 review changes, got %d", len(rep.Changes))
	}
	if rep.Changes[0].Kind != "fleet_policy" || rep.Changes[1].Name != "endpoint" || rep.Changes[2].Name != "rule-a" {
		t.Fatalf("unexpected sort order: %+v", rep.Changes)
	}
	msg := rep.String()
	if !strings.Contains(msg, "changes:") || !strings.Contains(msg, "fleet_policy create: policy-a") {
		t.Fatalf("report string not formatted as expected: %s", msg)
	}
}

type failingClient struct{}

func (failingClient) ReviewIntegrations(items []config.Integration) ([]kibana.ReviewChange, error) { return nil, errors.New("boom") }
func (failingClient) ReviewFleetPolicies(items []config.FleetPolicy) ([]kibana.ReviewChange, error) { return nil, nil }
func (failingClient) ReviewRules(items []config.Rule) ([]kibana.ReviewChange, error) { return nil, nil }
func (failingClient) EnsureIntegrations(items []config.Integration) (int, error) { return 0, nil }
func (failingClient) EnsureFleetPolicies(items []config.FleetPolicy) (int, error) { return 0, nil }
func (failingClient) EnsureRules(items []config.Rule) (int, error) { return 0, nil }

func TestRunStopsOnError(t *testing.T) {
	_, err := Run(failingClient{}, &config.DesiredState{}, ModeReview)
	if err == nil {
		t.Fatal("expected error")
	}
}
