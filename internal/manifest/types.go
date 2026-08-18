package manifest

import "github.com/TommyAGK/elastic-maintenance/internal/source"

const APIVersion = "elastic-maintainer/v1alpha1"

type Kind string

const (
	KindIntegrationPackage Kind = "IntegrationPackage"
	KindAgentPolicy        Kind = "AgentPolicy"
	KindPackagePolicy      Kind = "PackagePolicy"
	KindDetectionRule      Kind = "DetectionRule"
	KindPrebuiltRules      Kind = "PrebuiltRules"
)

type Reference struct {
	Kind Kind   `json:"kind"`
	ID   string `json:"id"`
}

type TargetSelector struct {
	MatchLabels map[string]string `json:"matchLabels"`
}

type Metadata struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	TargetSelector *TargetSelector `json:"targetSelector,omitempty"`
	DependsOn      []Reference     `json:"dependsOn,omitempty"`
}

type IntegrationPackageSpec struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type AgentPolicySpec struct {
	Namespace string `json:"namespace"`
}

type PackagePolicySpec struct {
	Namespace      string    `json:"namespace"`
	IntegrationRef Reference `json:"integrationRef"`
	AgentPolicyRef Reference `json:"agentPolicyRef"`
}

type DetectionRuleSpec struct {
	Type     string   `json:"type"`
	Enabled  bool     `json:"enabled"`
	Query    string   `json:"query"`
	Severity string   `json:"severity"`
	Interval string   `json:"interval"`
	Language string   `json:"language"`
	Index    []string `json:"index"`
}

type PrebuiltRulesSpec struct{}

type Resource struct {
	APIVersion string          `json:"apiVersion"`
	Kind       Kind            `json:"kind"`
	Metadata   Metadata        `json:"metadata"`
	Spec       any             `json:"spec"`
	Source     source.Location `json:"source"`
}

type ResourceSet struct {
	ID        string     `json:"id"`
	Revision  string     `json:"revision,omitempty"`
	Resources []Resource `json:"resources"`
}
