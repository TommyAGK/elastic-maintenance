package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type DesiredState struct {
	Integrations  []Integration `json:"integrations"`
	FleetPolicies []FleetPolicy `json:"fleet_policies"`
	Rules         []Rule        `json:"rules"`
}

type Integration struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Namespace string `json:"namespace,omitempty"`
}

type FleetPolicy struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Rule struct {
	RuleID   string `json:"rule_id,omitempty"`
	ID       string `json:"id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	Prebuilt bool   `json:"prebuilt"`
	Query    string `json:"query,omitempty"`
	Severity string `json:"severity,omitempty"`
	Interval string `json:"interval,omitempty"`
	Language string `json:"language,omitempty"`
	Index    string `json:"index,omitempty"`
}

func Load(path string) (*DesiredState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read desired state: %w", err)
	}
	var s DesiredState
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse desired state: %w", err)
	}
	return &s, nil
}
