package reconcile

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/kibana"
)

type Mode string

const (
	ModeReview Mode = "review"
	ModeApply  Mode = "apply"
)

type Report struct {
	Checks         []string
	ChangesPlanned int
	ChangesApplied int
	Changes        []kibana.ReviewChange
}

func (r Report) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "checks=%d planned=%d applied=%d", len(r.Checks), r.ChangesPlanned, r.ChangesApplied)
	if len(r.Changes) == 0 {
		return b.String()
	}
	b.WriteString("\nchanges:")
	for _, change := range r.Changes {
		fmt.Fprintf(&b, "\n- %s %s: %s", change.Kind, change.Action, change.Name)
		if change.Details != "" {
			fmt.Fprintf(&b, " (%s)", change.Details)
		}
	}
	return b.String()
}

type assetClient interface {
	ReviewIntegrations([]config.Integration) ([]kibana.ReviewChange, error)
	ReviewFleetPolicies([]config.FleetPolicy) ([]kibana.ReviewChange, error)
	ReviewRules([]config.Rule) ([]kibana.ReviewChange, error)
	EnsureIntegrations([]config.Integration) (int, error)
	EnsureFleetPolicies([]config.FleetPolicy) (int, error)
	EnsureRules([]config.Rule) (int, error)
}

func Run(client assetClient, desired *config.DesiredState, mode Mode) (Report, error) {
	rep := Report{Checks: []string{"integrations", "fleet_policies", "rules"}}
	if mode == ModeReview {
		changes, err := client.ReviewIntegrations(desired.Integrations)
		if err != nil { return rep, err }
		rep.Changes = append(rep.Changes, changes...)
		changes, err = client.ReviewFleetPolicies(desired.FleetPolicies)
		if err != nil { return rep, err }
		rep.Changes = append(rep.Changes, changes...)
		changes, err = client.ReviewRules(desired.Rules)
		if err != nil { return rep, err }
		rep.Changes = append(rep.Changes, changes...)
		sort.Slice(rep.Changes, func(i, j int) bool {
			if rep.Changes[i].Kind != rep.Changes[j].Kind {
				return rep.Changes[i].Kind < rep.Changes[j].Kind
			}
			if rep.Changes[i].Name != rep.Changes[j].Name {
				return rep.Changes[i].Name < rep.Changes[j].Name
			}
			return rep.Changes[i].Action < rep.Changes[j].Action
		})
		rep.ChangesPlanned = len(rep.Changes)
		return rep, nil
	}
	planned, err := client.EnsureIntegrations(desired.Integrations)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	planned, err = client.EnsureFleetPolicies(desired.FleetPolicies)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	planned, err = client.EnsureRules(desired.Rules)
	if err != nil { return rep, err }
	rep.ChangesPlanned += planned
	rep.ChangesApplied = rep.ChangesPlanned
	return rep, nil
}
