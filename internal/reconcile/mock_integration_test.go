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
