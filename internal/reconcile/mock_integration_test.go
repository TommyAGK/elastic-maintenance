package reconcile

import (
	"testing"

	"elastic-maintenance/internal/config"
	"elastic-maintenance/internal/kibana"
	"elastic-maintenance/internal/mockkibana"
)

func TestReviewAgainstMockKibana(t *testing.T) {
	srv := mockkibana.New()
	defer srv.Close()

	cli := kibana.NewClient(srv.URL(), "test-key")
	rep, err := Run(cli, &config.DesiredState{
		Integrations: []config.Integration{{Name: "endpoint", Version: "8.18.0"}},
		FleetPolicies: []config.FleetPolicy{{Name: "policy-a"}},
		Rules: []config.Rule{{Name: "rule-a", Type: "query", Enabled: true}},
	}, ModeReview)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if rep.ChangesPlanned != 3 {
		t.Fatalf("expected 3 planned changes, got %d", rep.ChangesPlanned)
	}
	if len(srv.Requests) != 3 {
		t.Fatalf("expected 3 GET requests, got %d: %#v", len(srv.Requests), srv.Requests)
	}
}

func TestApplyAgainstMockKibana(t *testing.T) {
	srv := mockkibana.New()
	srv.InstalledPackages = []mockkibana.InstalledPackage{{Name: "endpoint", Version: "8.17.0"}}
	srv.PackagePolicies = []mockkibana.PackagePolicy{{ID: "policy-a", Name: "policy-a", Namespace: "default"}}
	srv.Rules = []mockkibana.Rule{{ID: "rule-a", RuleID: "rule-a", Name: "rule-a", Type: "query", Enabled: false, Query: "foo", Index: "logs-*"}}
	defer srv.Close()

	cli := kibana.NewClient(srv.URL(), "test-key")
	_, err := Run(cli, &config.DesiredState{
		Integrations: []config.Integration{{Name: "endpoint", Version: "8.18.0"}},
		FleetPolicies: []config.FleetPolicy{{Name: "policy-a"}},
		Rules: []config.Rule{{Name: "rule-a", RuleID: "rule-a", Type: "query", Enabled: true, Query: "bar", Index: "logs-*"}},
	}, ModeApply)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(srv.Requests) < 4 {
		t.Fatalf("expected update requests, got %#v", srv.Requests)
	}
}
