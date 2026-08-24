package credentials

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/kubesecret"
)

type fixedUsage struct {
	inUse bool
	err   error
}

func (usage fixedUsage) DeleteIfUnused(_ context.Context, _ string, operation func() error) error {
	if usage.err != nil {
		return usage.err
	}
	if usage.inUse {
		return ErrInUse
	}
	return operation()
}

type fakeStore struct {
	status                          kubesecret.Status
	statusErr, upsertErr, deleteErr error
	upserts, deletes                int
	data                            map[string][]byte
	metadata                        kubesecret.WriteMetadata
}

func (store *fakeStore) Status(context.Context, string, string) (kubesecret.Status, error) {
	return store.status, store.statusErr
}
func (store *fakeStore) Upsert(_ context.Context, _ string, _ string, data map[string][]byte, metadata kubesecret.WriteMetadata) (kubesecret.Status, error) {
	store.upserts++
	store.data = map[string][]byte{}
	for key, value := range data {
		store.data[key] = append([]byte{}, value...)
	}
	store.metadata = metadata
	if store.upsertErr != nil {
		return kubesecret.Status{}, store.upsertErr
	}
	store.status = kubesecret.Status{ResourceVersion: "2", UpdatedAt: time.Now(), Actor: metadata.Actor, IdempotencyHash: metadata.IdempotencyHash, RequestDigest: metadata.RequestDigest, CertificateSHA256: metadata.CertificateSHA256, CertificateNotAfter: metadata.CertificateNotAfter, Operation: metadata.Operation, MetadataValid: true}
	store.statusErr = nil
	return store.status, nil
}
func (store *fakeStore) Delete(context.Context, string, string) error {
	store.deletes++
	return store.deleteErr
}
func credentialConfig() *config.ServerConfig {
	return &config.ServerConfig{StateID: "state", SecretPolicy: config.KubernetesSecretPolicy{Namespace: "ns", NamePrefix: "target-"}, Targets: map[string]config.TargetConfig{"prod": {CredentialSecret: config.SecretReference{Namespace: "ns", Name: "target-prod"}}}}
}
func administrator() auth.Actor {
	return auth.Actor{Subject: "admin", Roles: []auth.Role{auth.RoleAdministrator}, Method: auth.MethodOIDC}
}
func newCredentialService(t *testing.T, store Store, now time.Time) *Service {
	t.Helper()
	service, err := New(Options{Config: ConfigSourceFunc(func(context.Context) (*config.ServerConfig, error) { return credentialConfig(), nil }), Store: store, Usage: NewUsageTracker(), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestPutIsIdempotentAndNeverReturnsMaterial(t *testing.T) {
	store := &fakeStore{statusErr: kubesecret.ErrNotFound}
	service := newCredentialService(t, store, time.Now())
	result, err := service.Put(context.Background(), "prod", "request-1", administrator(), PutRequest{APIKey: "ApiKey-value-sentinel"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Configured || result.SecretResourceVersion != "2" || store.upserts != 1 || string(store.data[APIKeyDataKey]) != "ApiKey-value-sentinel" || store.metadata.Actor != "admin" {
		t.Fatalf("result=%#v upserts=%d metadata=%#v", result, store.upserts, store.metadata)
	}
	if strings.Contains(strings.ToLower(result.RotatedBy), "apikey") {
		t.Fatal("status exposed material")
	}
	first := store.status
	if _, err := service.Put(context.Background(), "prod", "request-1", administrator(), PutRequest{APIKey: "ApiKey-value-sentinel"}); err != nil || store.upserts != 1 {
		t.Fatalf("idempotent err=%v upserts=%d", err, store.upserts)
	}
	store.status = first
	if _, err := service.Put(context.Background(), "prod", "request-1", administrator(), PutRequest{APIKey: "different"}); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error=%v", err)
	}
}

func TestCertificateBundleValidationAndMetadata(t *testing.T) {
	now := time.Now().UTC()
	bundle, notAfter := testCA(t, now, true)
	store := &fakeStore{statusErr: kubesecret.ErrNotFound}
	service := newCredentialService(t, store, now)
	status, err := service.Put(context.Background(), "prod", "request-ca", administrator(), PutRequest{APIKey: "key", CACertificatePEM: string(bundle)})
	if err != nil {
		t.Fatal(err)
	}
	if status.CertificateSHA256 == "" || !status.CertificateNotAfter.Equal(notAfter) || string(store.data[CACertificateDataKey]) != string(bundle) {
		t.Fatalf("status=%#v", status)
	}
	leaf, _ := testCA(t, now, false)
	for name, value := range map[string]string{"leaf": string(leaf), "private key": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", "junk": "not pem", "preamble": "junk\n" + string(bundle), "trailing": "" + string(bundle) + "junk"} {
		t.Run(name, func(t *testing.T) {
			other := &fakeStore{statusErr: kubesecret.ErrNotFound}
			if _, err := newCredentialService(t, other, now).Put(context.Background(), "prod", "request", administrator(), PutRequest{APIKey: "key", CACertificatePEM: value}); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("error=%v", err)
			}
			if other.upserts != 0 {
				t.Fatal("invalid CA reached store")
			}
		})
	}
}

func TestPermissionTargetsStatusAndDelete(t *testing.T) {
	store := &fakeStore{statusErr: kubesecret.ErrNotFound}
	service := newCredentialService(t, store, time.Now())
	viewer := auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}
	if _, err := service.Put(context.Background(), "prod", "request", viewer, PutRequest{APIKey: "key"}); !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("error=%v", err)
	}
	status, err := service.Status(context.Background(), "prod")
	if err != nil || status.Configured {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if _, err := service.Status(context.Background(), "missing"); !errors.Is(err, ErrTargetNotFound) {
		t.Fatalf("missing error=%v", err)
	}
	if _, err := service.Delete(context.Background(), "prod", "delete-request", administrator()); err != nil || store.deletes != 1 {
		t.Fatalf("delete err=%v calls=%d", err, store.deletes)
	}
}

func TestUsageTrackerMakesDeleteCheckAtomic(t *testing.T) {
	tracker := NewUsageTracker()
	release, err := tracker.Acquire("prod")
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := tracker.DeleteIfUnused(context.Background(), "prod", func() error { called = true; return nil }); !errors.Is(err, ErrInUse) || called {
		t.Fatalf("error=%v called=%v", err, called)
	}
	release()
	if err := tracker.DeleteIfUnused(context.Background(), "prod", func() error { called = true; return nil }); err != nil || !called {
		t.Fatalf("error=%v called=%v", err, called)
	}
}

func TestDeleteRefusesCredentialInUse(t *testing.T) {
	store := &fakeStore{}
	service, err := New(Options{Config: ConfigSourceFunc(func(context.Context) (*config.ServerConfig, error) { return credentialConfig(), nil }), Store: store, Usage: fixedUsage{inUse: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Delete(context.Background(), "prod", "delete-request", administrator()); !errors.Is(err, ErrInUse) || store.deletes != 0 {
		t.Fatalf("error=%v deletes=%d", err, store.deletes)
	}
}

func TestRejectsUnsafeAPIKeysAndMapsStoreErrors(t *testing.T) {
	for _, value := range []string{"", " key", "key value", "key\tvalue", "key\x01value", "key\nvalue", strings.Repeat("a", MaxAPIKeyBytes+1)} {
		store := &fakeStore{statusErr: kubesecret.ErrNotFound}
		if _, err := newCredentialService(t, store, time.Now()).Put(context.Background(), "prod", "request", administrator(), PutRequest{APIKey: value}); !errors.Is(err, ErrInvalidCredential) {
			t.Errorf("value length=%d error=%v", len(value), err)
		}
	}
	store := &fakeStore{statusErr: kubesecret.ErrUnowned}
	if _, err := newCredentialService(t, store, time.Now()).Status(context.Background(), "prod"); !errors.Is(err, ErrConflict) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("mapped error=%v", err)
	}
}

func testCA(t *testing.T, now time.Time, isCA bool) ([]byte, time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := now.Add(24 * time.Hour).Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: now.Add(-time.Hour), NotAfter: notAfter, BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), notAfter
}
