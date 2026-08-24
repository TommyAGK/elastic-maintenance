package kubesecret

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubevalidation "k8s.io/apimachinery/pkg/util/validation"
)

const (
	ManagedByLabel      = "app.kubernetes.io/managed-by"
	ManagedByValue      = "elastic-maintainer"
	StateIDAnnotation   = "elastic-maintainer.tommyagk.github.io/state-id"
	TargetIDAnnotation  = "elastic-maintainer.tommyagk.github.io/target-id"
	UpdatedAtAnnotation = "elastic-maintainer.tommyagk.github.io/updated-at"
)

var (
	ErrInvalidReference = errors.New("Kubernetes Secret reference is invalid")
	ErrNotFound         = errors.New("Kubernetes Secret was not found")
	ErrConflict         = errors.New("Kubernetes Secret update conflicted")
	ErrForbidden        = errors.New("Kubernetes Secret operation is forbidden")
	ErrUnavailable      = errors.New("Kubernetes Secret service is unavailable")
	ErrUnowned          = errors.New("Kubernetes Secret is not owned by Elastic Maintainer")
	idPattern           = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$`)
	stateIDPattern      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
)

type API interface {
	Get(context.Context, string, metav1.GetOptions) (*corev1.Secret, error)
	Create(context.Context, *corev1.Secret, metav1.CreateOptions) (*corev1.Secret, error)
	Update(context.Context, *corev1.Secret, metav1.UpdateOptions) (*corev1.Secret, error)
	Delete(context.Context, string, metav1.DeleteOptions) error
}

type Options struct {
	Namespace, NamePrefix, StateID string
	API                            API
	Now                            func() time.Time
}
type Client struct {
	namespace, prefix, stateID string
	api                        API
	now                        func() time.Time
}
type Status struct {
	Namespace, Name, ResourceVersion string
	UpdatedAt                        time.Time
	TargetID                         string
}
type Material struct {
	Status Status
	Data   map[string][]byte
}

func New(options Options) (*Client, error) {
	if options.API == nil {
		return nil, errors.New("Kubernetes Secret API is required")
	}
	if err := validateIdentity(options.Namespace, options.NamePrefix, options.StateID); err != nil {
		return nil, ErrInvalidReference
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Client{namespace: options.Namespace, prefix: options.NamePrefix, stateID: options.StateID, api: options.API, now: now}, nil
}

func (client *Client) Status(ctx context.Context, name, targetID string) (Status, error) {
	secret, err := client.getOwnedTarget(ctx, name, targetID)
	if err != nil {
		return Status{}, err
	}
	return statusOf(secret), nil
}
func (client *Client) Read(ctx context.Context, name, targetID string) (Material, error) {
	secret, err := client.getOwnedTarget(ctx, name, targetID)
	if err != nil {
		return Material{}, err
	}
	return Material{Status: statusOf(secret), Data: cloneData(secret.Data)}, nil
}

func (client *Client) Upsert(ctx context.Context, name, targetID string, data map[string][]byte) (Status, error) {
	if err := client.validateName(name); err != nil || !idPattern.MatchString(targetID) {
		return Status{}, ErrInvalidReference
	}
	if data == nil {
		return Status{}, ErrInvalidReference
	}
	existing, err := client.api.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: client.namespace, Name: name, Labels: map[string]string{ManagedByLabel: ManagedByValue}, Annotations: map[string]string{StateIDAnnotation: client.stateID, TargetIDAnnotation: targetID, UpdatedAtAnnotation: client.now().UTC().Format(time.RFC3339Nano)}}, Type: corev1.SecretTypeOpaque, Data: cloneData(data)}
		created, createErr := client.api.Create(ctx, secret, metav1.CreateOptions{})
		if createErr != nil {
			return Status{}, classify(createErr)
		}
		if !client.owned(created, name) || created.Annotations[TargetIDAnnotation] != targetID {
			return Status{}, ErrUnavailable
		}
		return statusOf(created), nil
	}
	if err != nil {
		return Status{}, classify(err)
	}
	if !client.owned(existing, name) || existing.Annotations[TargetIDAnnotation] != targetID {
		return Status{}, ErrUnowned
	}
	updated := existing.DeepCopy()
	updated.Type = corev1.SecretTypeOpaque
	updated.Data = cloneData(data)
	ensureMetadata(updated, client.stateID, targetID)
	updated.Annotations[UpdatedAtAnnotation] = client.now().UTC().Format(time.RFC3339Nano)
	result, updateErr := client.api.Update(ctx, updated, metav1.UpdateOptions{})
	if updateErr != nil {
		return Status{}, classify(updateErr)
	}
	if !client.owned(result, name) || result.Annotations[TargetIDAnnotation] != targetID {
		return Status{}, ErrUnavailable
	}
	return statusOf(result), nil
}

func (client *Client) Delete(ctx context.Context, name, targetID string) error {
	secret, err := client.getOwnedTarget(ctx, name, targetID)
	if err != nil {
		return err
	}
	uid := secret.UID
	resourceVersion := secret.ResourceVersion
	policy := metav1.DeletePropagationBackground
	err = client.api.Delete(ctx, name, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &resourceVersion}, PropagationPolicy: &policy})
	return classify(err)
}

func (client *Client) getOwnedTarget(ctx context.Context, name, targetID string) (*corev1.Secret, error) {
	if !idPattern.MatchString(targetID) {
		return nil, ErrInvalidReference
	}
	secret, err := client.getOwned(ctx, name)
	if err != nil {
		return nil, err
	}
	if secret.Annotations[TargetIDAnnotation] != targetID {
		return nil, ErrUnowned
	}
	return secret, nil
}
func (client *Client) getOwned(ctx context.Context, name string) (*corev1.Secret, error) {
	if err := client.validateName(name); err != nil {
		return nil, err
	}
	secret, err := client.api.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, classify(err)
	}
	if !client.owned(secret, name) {
		return nil, ErrUnowned
	}
	return secret, nil
}
func (client *Client) owned(secret *corev1.Secret, name string) bool {
	return secret != nil && secret.Namespace == client.namespace && secret.Name == name && secret.Labels[ManagedByLabel] == ManagedByValue && secret.Annotations[StateIDAnnotation] == client.stateID
}
func (client *Client) validateName(name string) error {
	if len(name) > 253 || !strings.HasPrefix(name, client.prefix) || len(kubevalidation.IsDNS1123Subdomain(name)) != 0 {
		return ErrInvalidReference
	}
	return nil
}
func ensureMetadata(secret *corev1.Secret, stateID, targetID string) {
	if secret.Labels == nil {
		secret.Labels = map[string]string{}
	}
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Labels[ManagedByLabel] = ManagedByValue
	secret.Annotations[StateIDAnnotation] = stateID
	secret.Annotations[TargetIDAnnotation] = targetID
}
func statusOf(secret *corev1.Secret) Status {
	updated, _ := time.Parse(time.RFC3339Nano, secret.Annotations[UpdatedAtAnnotation])
	return Status{Namespace: secret.Namespace, Name: secret.Name, ResourceVersion: secret.ResourceVersion, UpdatedAt: updated, TargetID: secret.Annotations[TargetIDAnnotation]}
}
func cloneData(input map[string][]byte) map[string][]byte {
	result := make(map[string][]byte, len(input))
	for key, value := range input {
		result[key] = append([]byte{}, value...)
	}
	return result
}
func classify(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case apierrors.IsNotFound(err):
		return ErrNotFound
	case apierrors.IsConflict(err) || apierrors.IsAlreadyExists(err):
		return ErrConflict
	case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
		return ErrForbidden
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrUnavailable
	}
}
func validateIdentity(namespace, prefix, stateID string) error {
	if !validNamespace(namespace) || !validPrefix(prefix) || !stateIDPattern.MatchString(stateID) {
		return ErrInvalidReference
	}
	return nil
}
func validNamespace(value string) bool { return len(kubevalidation.IsDNS1123Label(value)) == 0 }
func validPrefix(value string) bool {
	if len(value) < 2 || len(value) > 252 || !strings.HasSuffix(value, "-") {
		return false
	}
	base := strings.TrimSuffix(value, "-")
	if len(kubevalidation.IsDNS1123Subdomain(base)) != 0 {
		return false
	}
	for _, label := range strings.Split(base, ".") {
		if len(label) > 63 {
			return false
		}
	}
	return true
}
