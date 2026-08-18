package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

const (
	DesiredDigestDomain  = "elastic-maintainer/desired"
	DesiredDigestVersion = "v1"
)

type DesiredDigest struct {
	Algorithm string `json:"algorithm"`
	Version   string `json:"version"`
	Value     string `json:"value"`
}

type canonicalLabel struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type canonicalSelector struct {
	MatchLabels []canonicalLabel `json:"matchLabels"`
}

type canonicalMetadata struct {
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	TargetSelector *canonicalSelector `json:"targetSelector,omitempty"`
	DependsOn      []Reference        `json:"dependsOn"`
}

type canonicalResource struct {
	APIVersion string            `json:"apiVersion"`
	Kind       Kind              `json:"kind"`
	Metadata   canonicalMetadata `json:"metadata"`
	Spec       any               `json:"spec"`
}

type canonicalResourceSet struct {
	ID        string              `json:"id"`
	Resources []canonicalResource `json:"resources"`
}

type canonicalTargetConfig struct {
	StateID       string           `json:"stateID"`
	Name          string           `json:"name"`
	URL           string           `json:"url"`
	Space         string           `json:"space"`
	ResourceSetID string           `json:"resourceSetID"`
	Labels        []canonicalLabel `json:"labels"`
}

type canonicalTargetDesired struct {
	Target    canonicalTargetConfig `json:"target"`
	Resources []canonicalResource   `json:"resources"`
}

func canonicalizeResource(resource Resource) (canonicalResource, error) {
	metadata := canonicalMetadata{ID: resource.Metadata.ID, Name: resource.Metadata.Name, DependsOn: append([]Reference{}, resource.Metadata.DependsOn...)}
	sort.SliceStable(metadata.DependsOn, func(i, j int) bool {
		if metadata.DependsOn[i].Kind != metadata.DependsOn[j].Kind {
			return metadata.DependsOn[i].Kind < metadata.DependsOn[j].Kind
		}
		return metadata.DependsOn[i].ID < metadata.DependsOn[j].ID
	})
	if resource.Metadata.TargetSelector != nil {
		metadata.TargetSelector = &canonicalSelector{MatchLabels: canonicalLabels(resource.Metadata.TargetSelector.MatchLabels)}
	}
	var spec any
	switch resource.Kind {
	case KindIntegrationPackage:
		value, ok := resource.Spec.(IntegrationPackageSpec)
		if !ok {
			return canonicalResource{}, errors.New("canonicalize resource: invalid IntegrationPackage spec")
		}
		spec = value
	case KindAgentPolicy:
		value, ok := resource.Spec.(AgentPolicySpec)
		if !ok {
			return canonicalResource{}, errors.New("canonicalize resource: invalid AgentPolicy spec")
		}
		spec = value
	case KindPackagePolicy:
		value, ok := resource.Spec.(PackagePolicySpec)
		if !ok {
			return canonicalResource{}, errors.New("canonicalize resource: invalid PackagePolicy spec")
		}
		spec = value
	case KindDetectionRule:
		value, ok := resource.Spec.(DetectionRuleSpec)
		if !ok {
			return canonicalResource{}, errors.New("canonicalize resource: invalid DetectionRule spec")
		}
		value.Index = append([]string{}, value.Index...)
		sort.Strings(value.Index)
		spec = value
	case KindPrebuiltRules:
		if _, ok := resource.Spec.(PrebuiltRulesSpec); !ok {
			return canonicalResource{}, errors.New("canonicalize resource: invalid PrebuiltRules spec")
		}
		spec = PrebuiltRulesSpec{}
	default:
		return canonicalResource{}, errors.New("canonicalize resource: unsupported kind")
	}
	return canonicalResource{APIVersion: resource.APIVersion, Kind: resource.Kind, Metadata: metadata, Spec: spec}, nil
}

func canonicalizeResourceSet(set *ResourceSet) (canonicalResourceSet, error) {
	if set == nil {
		return canonicalResourceSet{}, errors.New("canonicalize resource set: set is nil")
	}
	resources := append([]Resource(nil), set.Resources...)
	sort.SliceStable(resources, func(i, j int) bool {
		return lessIdentity(resourceIdentity(resources[i]), resourceIdentity(resources[j]))
	})
	result := canonicalResourceSet{ID: set.ID, Resources: make([]canonicalResource, 0, len(resources))}
	for _, resource := range resources {
		canonical, err := canonicalizeResource(resource)
		if err != nil {
			return canonicalResourceSet{}, err
		}
		result.Resources = append(result.Resources, canonical)
	}
	return result, nil
}

func canonicalizeTarget(cfg *config.ServerConfig, target TargetInventory, set *ResourceSet) (canonicalTargetDesired, error) {
	normalized, err := cfg.NormalizeTargetConfig(target.Identity.Name)
	if err != nil {
		return canonicalTargetDesired{}, errors.New("canonicalize target: target identity is invalid")
	}
	resourcesByKey := make(map[string]Resource, len(set.Resources))
	for _, resource := range set.Resources {
		resourcesByKey[identityKey(resourceIdentity(resource))] = resource
	}
	identities := append([]ResourceIdentity(nil), target.Resources...)
	sort.SliceStable(identities, func(i, j int) bool { return lessIdentity(identities[i], identities[j]) })
	result := canonicalTargetDesired{
		Target: canonicalTargetConfig{
			StateID: normalized.StateID, Name: normalized.Name, URL: normalized.URL, Space: normalized.Space,
			ResourceSetID: normalized.ResourceSetID, Labels: canonicalLabels(normalized.Labels),
		},
		Resources: make([]canonicalResource, 0, len(identities)),
	}
	for _, identity := range identities {
		resource, exists := resourcesByKey[identityKey(identity)]
		if !exists {
			return canonicalTargetDesired{}, errors.New("canonicalize target: applicable resource is missing")
		}
		canonical, err := canonicalizeResource(resource)
		if err != nil {
			return canonicalTargetDesired{}, err
		}
		result.Resources = append(result.Resources, canonical)
	}
	return result, nil
}

func canonicalLabels(labels map[string]string) []canonicalLabel {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]canonicalLabel, 0, len(keys))
	for _, key := range keys {
		result = append(result, canonicalLabel{Key: key, Value: labels[key]})
	}
	return result
}

func desiredDigest(scope string, value any) (DesiredDigest, error) {
	canonical, err := marshalCanonicalJSON(value)
	if err != nil {
		return DesiredDigest{}, fmt.Errorf("marshal canonical desired %s: %w", scope, err)
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(DesiredDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(DesiredDigestVersion))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(scope))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return DesiredDigest{Algorithm: "sha256", Version: DesiredDigestVersion, Value: hex.EncodeToString(hash.Sum(nil))}, nil
}
