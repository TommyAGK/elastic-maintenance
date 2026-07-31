package reconcile

import (
	"fmt"

	"elastic-maintenance/internal/config"
)

type Mode string

const (
	ModeReview Mode = "review"
	ModeApply  Mode = "apply"
)

type Report struct {
	Checks        []string
	ChangesPlanned int
	ChangesApplied int
}

func (r Report) String() string {
	return fmt.Sprintf("checks=%d planned=%d applied=%d", len(r.Checks), r.ChangesPlanned, r.ChangesApplied)
}

type assetClient interface {
	EnsureIntegrations([]config.Integration) (int, error)
	EnsureFleetPolicies([]config.FleetPolicy) (int, error)
	EnsureRules([]config.Rule) (int, error)
}

func Run(client assetClient, desired *config.DesiredState, mode Mode) (Report, error) {
	rep := Report{}
	planned, err := client.EnsureIntegrations(desired.Integrations)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	planned, err = client.EnsureFleetPolicies(desired.FleetPolicies)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	planned, err = client.EnsureRules(desired.Rules)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	if mode == ModeApply {
		rep.ChangesApplied = rep.ChangesPlanned
	}
	rep.Checks = []string{"integrations", "fleet_policies", "rules"}
	return rep, nil
}

