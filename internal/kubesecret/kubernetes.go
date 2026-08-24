package kubesecret

import (
	"fmt"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
	coreclient "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
)

// NewInCluster creates the production boundary using the pod service account.
// Kubernetes RBAC must grant only Secret get/create/update/delete in the
// configured namespace; this package performs an additional ownership check.
func NewInCluster(policy config.KubernetesSecretPolicy, stateID string) (*Client, error) {
	if err := validateIdentity(policy.Namespace, policy.NamePrefix, stateID); err != nil {
		return nil, err
	}
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("initialize in-cluster Kubernetes client: %w", ErrUnavailable)
	}
	core, err := coreclient.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("initialize in-cluster Kubernetes client: %w", ErrUnavailable)
	}
	return New(Options{Namespace: policy.Namespace, NamePrefix: policy.NamePrefix, StateID: stateID, API: core.Secrets(policy.Namespace)})
}
