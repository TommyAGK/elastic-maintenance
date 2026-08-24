package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/kubesecret"
)

const (
	APIKeyDataKey        = "api-key"
	CACertificateDataKey = "ca.crt"
	MaxAPIKeyBytes       = 16 << 10
	MaxCABundleBytes     = 256 << 10
)

var (
	ErrTargetNotFound      = errors.New("credential target was not found")
	ErrInvalidCredential   = errors.New("credential request is invalid")
	ErrPermissionDenied    = errors.New("credential operation is forbidden")
	ErrIdempotencyConflict = errors.New("credential idempotency key conflicts")
	ErrConflict            = errors.New("credential operation conflicted")
	ErrInUse               = errors.New("credential is in use")
	ErrUnavailable         = errors.New("credential service is unavailable")
	ErrTargetUnready       = errors.New("target credentials are not ready")
)

type ConfigSource interface {
	Load(context.Context) (*config.ServerConfig, error)
}
type ConfigSourceFunc func(context.Context) (*config.ServerConfig, error)

func (function ConfigSourceFunc) Load(ctx context.Context) (*config.ServerConfig, error) {
	return function(ctx)
}

type Store interface {
	Status(context.Context, string, string) (kubesecret.Status, error)
	Read(context.Context, string, string) (kubesecret.Material, error)
	Upsert(context.Context, string, string, map[string][]byte, kubesecret.WriteMetadata) (kubesecret.Status, error)
	Delete(context.Context, string, string) error
}
type StoreFactory func(*config.ServerConfig) (Store, error)
type UsageCoordinator interface {
	Acquire(string) (func(), error)
	DeleteIfUnused(context.Context, string, func() error) error
}
type usageEntry struct {
	mu     sync.Mutex
	active int
}
type UsageTracker struct {
	mu      sync.Mutex
	entries map[string]*usageEntry
}

func NewUsageTracker() *UsageTracker { return &UsageTracker{entries: map[string]*usageEntry{}} }
func (tracker *UsageTracker) entry(targetID string) *usageEntry {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	entry := tracker.entries[targetID]
	if entry == nil {
		entry = &usageEntry{}
		tracker.entries[targetID] = entry
	}
	return entry
}
func (tracker *UsageTracker) Acquire(targetID string) (func(), error) {
	if !idValue(targetID) {
		return nil, ErrTargetNotFound
	}
	entry := tracker.entry(targetID)
	entry.mu.Lock()
	entry.active++
	entry.mu.Unlock()
	once := sync.Once{}
	return func() {
		once.Do(func() {
			entry.mu.Lock()
			defer entry.mu.Unlock()
			if entry.active > 0 {
				entry.active--
			}
		})
	}, nil
}
func (tracker *UsageTracker) DeleteIfUnused(ctx context.Context, targetID string, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	entry := tracker.entry(targetID)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.active > 0 {
		return ErrInUse
	}
	return operation()
}
func idValue(value string) bool { return len(value) > 0 && len(value) <= 64 }

type Options struct {
	Config       ConfigSource
	Store        Store
	StoreFactory StoreFactory
	Usage        UsageCoordinator
	Now          func() time.Time
}
type Service struct {
	config        ConfigSource
	store         Store
	factory       StoreFactory
	usage         UsageCoordinator
	writeMu       sync.Mutex
	storeIdentity string
	now           func() time.Time
	mu            sync.Mutex
}
type PutRequest struct{ APIKey, CACertificatePEM string }
type Status struct {
	Configured                   bool
	Created                      bool
	SecretResourceVersion        string
	RotatedAt                    time.Time
	RotatedBy, CertificateSHA256 string
	CertificateNotAfter          time.Time
}

func New(options Options) (*Service, error) {
	if options.Config == nil || options.Store == nil && options.StoreFactory == nil {
		return nil, errors.New("credential service dependencies are required")
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	usage := options.Usage
	if usage == nil {
		return nil, errors.New("credential usage coordinator is required")
	}
	return &Service{config: options.Config, store: options.Store, factory: options.StoreFactory, usage: usage, now: now}, nil
}

type MaterialLease struct {
	identity     config.TargetIdentity
	apiKey       []byte
	certificates []*x509.Certificate
	release      func()
	once         sync.Once
}

func (lease *MaterialLease) TargetIdentity() config.TargetIdentity {
	if lease == nil {
		return config.TargetIdentity{}
	}
	return lease.identity
}
func (lease *MaterialLease) APIKey() []byte {
	if lease == nil {
		return nil
	}
	return append([]byte{}, lease.apiKey...)
}
func (lease *MaterialLease) CACertificates() []*x509.Certificate {
	if lease == nil {
		return nil
	}
	return append([]*x509.Certificate{}, lease.certificates...)
}
func (lease *MaterialLease) Close() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		clear(lease.apiKey)
		lease.apiKey = nil
		lease.certificates = nil
		if lease.release != nil {
			lease.release()
		}
	})
}
func (service *Service) AcquireMaterial(ctx context.Context, targetID string) (*MaterialLease, error) {
	cfg, target, store, err := service.inputs(ctx, targetID)
	if err != nil {
		return nil, err
	}
	identity, err := cfg.TargetIdentity(targetID)
	if err != nil {
		return nil, ErrTargetUnready
	}
	release, err := service.usage.Acquire(targetID)
	if err != nil {
		return nil, ErrTargetUnready
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	material, err := store.Read(ctx, target.CredentialSecret.Name, targetID)
	if err == nil {
		defer clearMaterialData(material.Data)
	}
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrTargetUnready
	}
	if !validStoredStatus(material.Status) || !validMaterialData(material, service.now().UTC()) {
		return nil, ErrTargetUnready
	}
	apiKey := append([]byte{}, material.Data[APIKeyDataKey]...)
	certificates, err := parseValidatedCertificates(material.Data[CACertificateDataKey], service.now().UTC())
	if err != nil {
		clear(apiKey)
		return nil, ErrTargetUnready
	}
	success = true
	return &MaterialLease{identity: identity, apiKey: apiKey, certificates: certificates, release: release}, nil
}
func clearMaterialData(data map[string][]byte) {
	for key, value := range data {
		clear(value)
		delete(data, key)
	}
}
func validMaterialData(material kubesecret.Material, now time.Time) bool {
	for key := range material.Data {
		if key != APIKeyDataKey && key != CACertificateDataKey && key != kubesecret.RequestDigestDataKey {
			return false
		}
	}
	apiKey := material.Data[APIKeyDataKey]
	if len(apiKey) == 0 || len(apiKey) > MaxAPIKeyBytes || !printableAPIKey(apiKey) {
		return false
	}
	ca := material.Data[CACertificateDataKey]
	if len(ca) > MaxCABundleBytes || credentialDigest(apiKey, ca) != material.Status.RequestDigest {
		return false
	}
	validated, hash, expiry, err := validateCA(ca, now)
	clear(validated)
	return err == nil && hash == material.Status.CertificateSHA256 && expiry.Equal(material.Status.CertificateNotAfter)
}
func parseValidatedCertificates(contents []byte, now time.Time) ([]*x509.Certificate, error) {
	if len(contents) == 0 {
		return nil, nil
	}
	validated, _, _, err := validateCA(contents, now)
	if err != nil {
		return nil, err
	}
	defer clear(validated)
	contents = validated
	var certificates []*x509.Certificate
	for len(contents) > 0 {
		block, rest := pem.Decode(contents)
		der := append([]byte{}, block.Bytes...)
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, certificate)
		contents = rest
	}
	return certificates, nil
}

func (service *Service) OriginConfig(ctx context.Context) (string, []string, error) {
	cfg, err := service.config.Load(ctx)
	if err != nil || cfg == nil {
		return "", nil, ErrUnavailable
	}
	return cfg.PublicURL, append([]string{}, cfg.TrustedProxies...), nil
}
func (service *Service) Status(ctx context.Context, targetID string) (Status, error) {
	cfg, target, store, err := service.inputs(ctx, targetID)
	if err != nil {
		return Status{}, err
	}
	_ = cfg
	status, err := store.Status(ctx, target.CredentialSecret.Name, targetID)
	if errors.Is(err, kubesecret.ErrNotFound) {
		return Status{Configured: false}, nil
	}
	if err != nil {
		return Status{}, mapStoreError(err)
	}
	if !validStoredStatus(status) {
		return Status{}, ErrUnavailable
	}
	return publicStatus(status), nil
}
func (service *Service) Put(ctx context.Context, targetID, idempotencyKey string, actor auth.Actor, request PutRequest) (Status, error) {
	normalized, normalizeErr := actor.Normalized()
	if normalizeErr != nil || !normalized.HasPermission(auth.PermissionCredentialsWrite) {
		return Status{}, ErrPermissionDenied
	}
	if !printableText(normalized.Subject) {
		return Status{}, ErrPermissionDenied
	}
	actor = normalized
	service.writeMu.Lock()
	defer service.writeMu.Unlock()
	cfg, target, store, err := service.inputs(ctx, targetID)
	if err != nil {
		return Status{}, err
	}
	_ = cfg
	if jobs.ValidateIdempotencyKey(idempotencyKey) != nil {
		return Status{}, ErrInvalidCredential
	}
	apiKey := []byte(request.APIKey)
	defer clear(apiKey)
	if len(apiKey) == 0 || len(apiKey) > MaxAPIKeyBytes || !printableAPIKey(apiKey) {
		return Status{}, ErrInvalidCredential
	}
	ca, certificateHash, notAfter, err := validateCA([]byte(request.CACertificatePEM), service.now().UTC())
	defer clear(ca)
	if err != nil {
		return Status{}, err
	}
	requestDigest := credentialDigest(apiKey, ca)
	idempotencyHash := sha256.Sum256([]byte(idempotencyKey))
	idempotency := hex.EncodeToString(idempotencyHash[:])
	current, currentErr := store.Status(ctx, target.CredentialSecret.Name, targetID)
	if currentErr == nil && !validStoredStatus(current) {
		return Status{}, ErrUnavailable
	}
	if currentErr == nil && current.IdempotencyHash == idempotency {
		if current.RequestDigest != requestDigest {
			return Status{}, ErrIdempotencyConflict
		}
		result := publicStatus(current)
		result.Created = current.Operation == "upload"
		return result, nil
	}
	if currentErr != nil && !errors.Is(currentErr, kubesecret.ErrNotFound) {
		return Status{}, mapStoreError(currentErr)
	}
	creating := errors.Is(currentErr, kubesecret.ErrNotFound)
	data := map[string][]byte{APIKeyDataKey: append([]byte{}, apiKey...)}
	defer clearMaterialData(data)
	if len(ca) != 0 {
		data[CACertificateDataKey] = ca
	}
	operation := "rotate"
	if creating {
		operation = "upload"
	}
	metadata := kubesecret.WriteMetadata{Actor: actor.Subject, IdempotencyHash: idempotency, RequestDigest: requestDigest, CertificateSHA256: certificateHash, CertificateNotAfter: notAfter, Operation: operation}
	written, err := store.Upsert(ctx, target.CredentialSecret.Name, targetID, data, metadata)
	if err != nil {
		if errors.Is(err, kubesecret.ErrConflict) {
			retry, retryErr := store.Status(ctx, target.CredentialSecret.Name, targetID)
			if retryErr == nil && validStoredStatus(retry) && retry.IdempotencyHash == idempotency && retry.RequestDigest == requestDigest {
				result := publicStatus(retry)
				result.Created = retry.Operation == "upload"
				return result, nil
			}
		}
		return Status{}, mapStoreError(err)
	}
	if !validStoredStatus(written) {
		return Status{}, ErrUnavailable
	}
	result := publicStatus(written)
	result.Created = creating
	return result, nil
}
func (service *Service) Delete(ctx context.Context, targetID, idempotencyKey string, actor auth.Actor) (Status, error) {
	normalized, normalizeErr := actor.Normalized()
	if normalizeErr != nil || !normalized.HasPermission(auth.PermissionCredentialsWrite) {
		return Status{}, ErrPermissionDenied
	}
	if jobs.ValidateIdempotencyKey(idempotencyKey) != nil {
		return Status{}, ErrInvalidCredential
	}
	service.writeMu.Lock()
	defer service.writeMu.Unlock()
	_, target, store, err := service.inputs(ctx, targetID)
	if err != nil {
		return Status{}, err
	}
	err = service.usage.DeleteIfUnused(ctx, targetID, func() error { return store.Delete(ctx, target.CredentialSecret.Name, targetID) })
	if errors.Is(err, ErrInUse) {
		return Status{}, ErrInUse
	}
	if errors.Is(err, kubesecret.ErrNotFound) {
		return Status{Configured: false}, nil
	}
	if err != nil {
		return Status{}, mapStoreError(err)
	}
	return Status{Configured: false}, nil
}
func (service *Service) inputs(ctx context.Context, targetID string) (*config.ServerConfig, config.TargetConfig, Store, error) {
	cfg, err := service.config.Load(ctx)
	if err != nil || cfg == nil {
		return nil, config.TargetConfig{}, nil, ErrUnavailable
	}
	target, ok := cfg.Targets[targetID]
	if !ok {
		return nil, config.TargetConfig{}, nil, ErrTargetNotFound
	}
	if kubesecret.ValidatePolicy(cfg.SecretPolicy, cfg.StateID) != nil || target.CredentialSecret.Namespace != cfg.SecretPolicy.Namespace || !strings.HasPrefix(target.CredentialSecret.Name, cfg.SecretPolicy.NamePrefix) {
		return nil, config.TargetConfig{}, nil, ErrUnavailable
	}
	store, err := service.getStore(cfg)
	if err != nil {
		return nil, config.TargetConfig{}, nil, ErrUnavailable
	}
	return cfg, target, store, nil
}
func (service *Service) getStore(cfg *config.ServerConfig) (Store, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	identity := cfg.SecretPolicy.Namespace + "\x00" + cfg.SecretPolicy.NamePrefix + "\x00" + cfg.StateID
	if service.store != nil && service.storeIdentity == "" {
		service.storeIdentity = identity
		return service.store, nil
	}
	if service.store != nil && service.storeIdentity == identity {
		return service.store, nil
	}
	if service.store != nil && service.factory == nil {
		return nil, ErrUnavailable
	}
	store, err := service.factory(cfg)
	if err != nil {
		return nil, err
	}
	service.store = store
	service.storeIdentity = identity
	return store, nil
}
func validStoredStatus(value kubesecret.Status) bool {
	if !value.MetadataValid || (value.Operation != "upload" && value.Operation != "rotate") || value.ResourceVersion == "" || len(value.Actor) == 0 || len(value.Actor) > 256 || !printableText(value.Actor) || !hex64String(value.IdempotencyHash) || !hex64String(value.RequestDigest) {
		return false
	}
	if value.UpdatedAt.IsZero() {
		return false
	}
	return value.CertificateSHA256 == "" && value.CertificateNotAfter.IsZero() || hex64String(value.CertificateSHA256) && !value.CertificateNotAfter.IsZero()
}
func printableText(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}
func hex64String(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}
func publicStatus(value kubesecret.Status) Status {
	return Status{Configured: true, SecretResourceVersion: value.ResourceVersion, RotatedAt: value.UpdatedAt, RotatedBy: value.Actor, CertificateSHA256: value.CertificateSHA256, CertificateNotAfter: value.CertificateNotAfter}
}
func mapStoreError(err error) error {
	switch {
	case errors.Is(err, kubesecret.ErrConflict):
		return ErrConflict
	case errors.Is(err, kubesecret.ErrInvalidReference), errors.Is(err, kubesecret.ErrUnowned):
		return ErrConflict
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrUnavailable
	}
}
func printableAPIKey(value []byte) bool {
	for _, char := range value {
		if char < 0x21 || char > 0x7e {
			return false
		}
	}
	return true
}
func credentialDigest(apiKey, ca []byte) string {
	hash := sha256.New()
	for _, value := range [][]byte{apiKey, ca} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		hash.Write(size[:])
		hash.Write(value)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
func validateCA(contents []byte, now time.Time) ([]byte, string, time.Time, error) {
	if len(contents) == 0 {
		return nil, "", time.Time{}, nil
	}
	if len(contents) > MaxCABundleBytes {
		return nil, "", time.Time{}, ErrInvalidCredential
	}
	remaining := contents
	hash := sha256.New()
	var earliest time.Time
	count := 0
	for len(remaining) > 0 {
		block, rest := pem.Decode(remaining)
		consumed := len(remaining) - len(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || consumed <= 0 || !bytes.Equal(remaining[:consumed], pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})) {
			return nil, "", time.Time{}, ErrInvalidCredential
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.BasicConstraintsValid || !certificate.IsCA || certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, "", time.Time{}, ErrInvalidCredential
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(block.Bytes)))
		hash.Write(size[:])
		hash.Write(block.Bytes)
		if earliest.IsZero() || certificate.NotAfter.Before(earliest) {
			earliest = certificate.NotAfter
		}
		count++
		remaining = rest
	}
	if count == 0 {
		return nil, "", time.Time{}, ErrInvalidCredential
	}
	return append([]byte{}, contents...), hex.EncodeToString(hash.Sum(nil)), earliest.UTC(), nil
}
