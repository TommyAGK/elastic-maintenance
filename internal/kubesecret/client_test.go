package kubesecret

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type fakeAPI struct {
	gets, creates, updates, deletes              int
	secret                                       *corev1.Secret
	getErr, createErr, updateErr, deleteErr      error
	created, updated, createResult, updateResult *corev1.Secret
	deleted                                      string
	deleteOptions                                metav1.DeleteOptions
}

func (api *fakeAPI) Get(context.Context, string, metav1.GetOptions) (*corev1.Secret, error) {
	api.gets++
	if api.getErr != nil {
		return nil, api.getErr
	}
	if api.secret == nil {
		return nil, apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "missing")
	}
	return api.secret.DeepCopy(), nil
}
func (api *fakeAPI) Create(_ context.Context, secret *corev1.Secret, _ metav1.CreateOptions) (*corev1.Secret, error) {
	api.creates++
	api.created = secret
	if api.createErr != nil {
		return nil, api.createErr
	}
	result := secret.DeepCopy()
	if api.createResult != nil {
		result = api.createResult.DeepCopy()
	}
	result.ResourceVersion = "1"
	return result, nil
}
func (api *fakeAPI) Update(_ context.Context, secret *corev1.Secret, _ metav1.UpdateOptions) (*corev1.Secret, error) {
	api.updates++
	api.updated = secret
	if api.updateErr != nil {
		return nil, api.updateErr
	}
	result := secret.DeepCopy()
	if api.updateResult != nil {
		result = api.updateResult.DeepCopy()
	}
	result.ResourceVersion = "2"
	return result, nil
}
func (api *fakeAPI) Delete(_ context.Context, name string, options metav1.DeleteOptions) error {
	api.deletes++
	api.deleted = name
	api.deleteOptions = options
	return api.deleteErr
}

func TestCreateUpdateReadAndDeleteOwnedSecret(t *testing.T) {
	clock := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	backend := &fakeAPI{}
	client, err := New(Options{Namespace: "elastic-maintainer", NamePrefix: "elastic-maintainer-target-", StateID: "state-1", API: backend, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	name := "elastic-maintainer-target-prod"
	data := map[string][]byte{"api-key": []byte("credential-sentinel")}
	status, err := client.Upsert(context.Background(), name, "prod", data)
	if err != nil {
		t.Fatal(err)
	}
	if status.ResourceVersion != "1" || backend.created.Namespace != "elastic-maintainer" || backend.created.Type != corev1.SecretTypeOpaque || backend.created.Labels[ManagedByLabel] != ManagedByValue || backend.created.Annotations[StateIDAnnotation] != "state-1" || backend.created.Annotations[TargetIDAnnotation] != "prod" {
		t.Fatalf("created metadata=%s/%s status=%#v", backend.created.Namespace, backend.created.Name, status)
	}
	data["api-key"][0] = 'X'
	if string(backend.created.Data["api-key"]) != "credential-sentinel" {
		t.Fatal("create retained caller data alias")
	}
	backend.secret = backend.created.DeepCopy()
	backend.secret.ResourceVersion = "1"
	clock = clock.Add(time.Hour)
	updatedData := map[string][]byte{"api-key": []byte("rotated-sentinel")}
	status, err = client.Upsert(context.Background(), name, "prod", updatedData)
	if err != nil {
		t.Fatal(err)
	}
	if status.ResourceVersion != "2" || backend.updated.ResourceVersion != "1" || backend.updated.Annotations[UpdatedAtAnnotation] != clock.Format(time.RFC3339Nano) {
		t.Fatalf("updated metadata=%s/%s rv=%s status=%#v", backend.updated.Namespace, backend.updated.Name, backend.updated.ResourceVersion, status)
	}
	backend.secret = backend.updated.DeepCopy()
	material, err := client.Read(context.Background(), name, "prod")
	if err != nil {
		t.Fatal(err)
	}
	material.Data["api-key"][0] = 'X'
	if string(backend.secret.Data["api-key"]) != "rotated-sentinel" {
		t.Fatal("read returned API data alias")
	}
	backend.secret.UID = types.UID("uid-1")
	if err := client.Delete(context.Background(), name, "prod"); err != nil {
		t.Fatal(err)
	}
	if backend.deleted != name || backend.deleteOptions.Preconditions == nil || string(*backend.deleteOptions.Preconditions.UID) != "uid-1" || *backend.deleteOptions.Preconditions.ResourceVersion != "1" {
		t.Fatalf("delete=%q options=%#v", backend.deleted, backend.deleteOptions)
	}
}

func TestRefusesInvalidUnownedAndCrossTargetSecretsBeforeMutation(t *testing.T) {
	owned := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "elastic-maintainer", Name: "elastic-maintainer-target-prod", ResourceVersion: "1", Labels: map[string]string{ManagedByLabel: ManagedByValue}, Annotations: map[string]string{StateIDAnnotation: "other-state", TargetIDAnnotation: "prod"}}}
	backend := &fakeAPI{secret: owned}
	client, err := New(Options{Namespace: "elastic-maintainer", NamePrefix: "elastic-maintainer-target-", StateID: "state-1", API: backend})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"other-secret", "elastic-maintainer-target-BAD", "elastic-maintainer-target-", "elastic-maintainer-target-a..b"} {
		if _, err := client.Status(context.Background(), name, "prod"); !errors.Is(err, ErrInvalidReference) {
			t.Errorf("name=%q error=%v", name, err)
		}
	}
	if backend.gets != 0 {
		t.Fatalf("invalid names made %d API calls", backend.gets)
	}
	if _, err := client.Upsert(context.Background(), owned.Name, "prod", map[string][]byte{"api-key": []byte("never-log-this")}); !errors.Is(err, ErrUnowned) {
		t.Fatalf("unowned update error=%v", err)
	}
	if backend.updated != nil {
		t.Fatal("unowned Secret was mutated")
	}
	owned.Annotations[StateIDAnnotation] = "state-1"
	owned.Annotations[TargetIDAnnotation] = "another-target"
	if err := client.Delete(context.Background(), owned.Name, "prod"); !errors.Is(err, ErrUnowned) {
		t.Fatalf("cross-target delete error=%v", err)
	}
	if backend.deleted != "" {
		t.Fatal("cross-target Secret was deleted")
	}
}

func TestKubernetesErrorsAreClassifiedWithoutSecretValues(t *testing.T) {
	resource := schema.GroupResource{Resource: "secrets"}
	sentinel := "credential-value-must-not-escape"
	cases := []struct{ input, errorWant error }{{apierrors.NewNotFound(resource, sentinel), ErrNotFound}, {apierrors.NewConflict(resource, "name", errors.New(sentinel)), ErrConflict}, {apierrors.NewForbidden(resource, "name", errors.New(sentinel)), ErrForbidden}, {errors.New(sentinel), ErrUnavailable}, {context.Canceled, context.Canceled}, {context.DeadlineExceeded, context.DeadlineExceeded}}
	for _, item := range cases {
		got := classify(item.input)
		if !errors.Is(got, item.errorWant) || strings.Contains(got.Error(), sentinel) {
			t.Errorf("classified=%v want=%v", got, item.errorWant)
		}
	}
}

func TestClientAcceptsFullServerStateIDContract(t *testing.T) {
	if _, err := New(Options{Namespace: "ns", NamePrefix: "target-", StateID: "state.with.dots-" + strings.Repeat("a", 112), API: &fakeAPI{}}); err != nil {
		t.Fatalf("error=%v", err)
	}
}

func TestRejectsMalformedAPIResponses(t *testing.T) {
	backend := &fakeAPI{createResult: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "other", Name: "target-prod"}}}
	client, err := New(Options{Namespace: "ns", NamePrefix: "target-", StateID: "state", API: backend})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Upsert(context.Background(), "target-prod", "prod", map[string][]byte{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("create response error=%v", err)
	}
	owned := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "target-prod", Labels: map[string]string{ManagedByLabel: ManagedByValue}, Annotations: map[string]string{StateIDAnnotation: "state", TargetIDAnnotation: "prod"}}}
	backend.secret = owned
	backend.createResult = nil
	backend.updateResult = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "wrong"}}
	if _, err := client.Upsert(context.Background(), "target-prod", "prod", map[string][]byte{}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("update response error=%v", err)
	}
}

func TestClientConfigurationIsStrict(t *testing.T) {
	backend := &fakeAPI{}
	for _, options := range []Options{{API: backend, Namespace: "Bad", NamePrefix: "elastic-maintainer-target-", StateID: "state"}, {API: backend, Namespace: "ns", NamePrefix: "target", StateID: "state"}, {API: backend, Namespace: "ns", NamePrefix: "target-", StateID: "bad/state"}, {API: backend, Namespace: "ns", NamePrefix: "target-", StateID: strings.Repeat("a", 129)}, {Namespace: "ns", NamePrefix: "target-", StateID: "state"}} {
		if _, err := New(options); err == nil {
			t.Fatalf("options=%#v error=nil", options)
		}
	}
}
