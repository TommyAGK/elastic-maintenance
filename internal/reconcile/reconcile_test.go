package reconcile

import (
	"errors"
	"testing"

	"elastic-maintenance/internal/config"
)

type fakeClient struct{}

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
	if rep.ChangesPlanned != 3 {
		t.Fatalf("expected 3 planned changes, got %d", rep.ChangesPlanned)
	}
	if rep.ChangesApplied != 0 {
		t.Fatalf("expected 0 applied changes in review mode, got %d", rep.ChangesApplied)
	}
}

type failingClient struct{}

func (failingClient) EnsureIntegrations(items []config.Integration) (int, error) { return 0, errors.New("boom") }
func (failingClient) EnsureFleetPolicies(items []config.FleetPolicy) (int, error) { return 0, nil }
func (failingClient) EnsureRules(items []config.Rule) (int, error) { return 0, nil }

func TestRunStopsOnError(t *testing.T) {
	_, err := Run(failingClient{}, &config.DesiredState{}, ModeReview)
	if err == nil {
		t.Fatal("expected error")
	}
}
