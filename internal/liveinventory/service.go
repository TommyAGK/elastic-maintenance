package liveinventory

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/kibana"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
)

const APIVersion = "elastic-maintainer/v1alpha1"
const maxResources = 10000

var ErrUnavailable = errors.New("live inventory service is unavailable")

type Client interface {
	Close()
	TargetIdentity() config.TargetIdentity
	EnsureCompatible(context.Context) error
	Version() string
	InstalledPackages(context.Context) ([]kibana.InstalledPackage, error)
	AgentPolicies(context.Context) ([]kibana.AgentPolicy, error)
	PackagePolicies(context.Context) ([]kibana.PackagePolicy, error)
	Rules(context.Context) ([]kibana.Rule, error)
	PrebuiltStatus(context.Context) (kibana.PrebuiltStatus, error)
}
type AcquireClient func(context.Context, string) (Client, error)
type Resource struct {
	Kind        manifest.Kind           `json:"kind"`
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	Manageable  bool                    `json:"manageable"`
	Fingerprint *kibana.LiveFingerprint `json:"fingerprint,omitempty"`
	Projection  json.RawMessage         `json:"projection"`
}
type Result struct {
	APIVersion    string                `json:"apiVersion"`
	TargetID      string                `json:"targetId"`
	Identity      config.TargetIdentity `json:"identity"`
	KibanaVersion string                `json:"kibanaVersion"`
	CheckedAt     time.Time             `json:"checkedAt"`
	Resources     []Resource            `json:"resources"`
}
type Record struct {
	Job              jobs.Job              `json:"job"`
	TargetID         string                `json:"targetId"`
	ExpectedIdentity config.TargetIdentity `json:"-"`
	Result           *Result               `json:"result,omitempty"`
}
type Probe struct {
	Ready       bool
	Version     string
	CheckedAt   time.Time
	FailureCode string
}
type StartRequest struct {
	TargetID, RequestID, IdempotencyKey string
	Identity                            config.TargetIdentity
	Actor                               auth.Actor
}
type Options struct {
	Acquire       AcquireClient
	QueueCapacity int
	MaxRecords    int
	Now           func() time.Time
}
type Service struct {
	acquire     AcquireClient
	queue       chan string
	maxRecords  int
	now         func() time.Time
	root        context.Context
	stop        context.CancelFunc
	wg          sync.WaitGroup
	mu          sync.Mutex
	closed      bool
	records     map[string]Record
	order       []string
	idempotency map[string]string
}

func New(options Options) (*Service, error) {
	if options.Acquire == nil {
		return nil, errors.New("live inventory client factory is required")
	}
	if options.QueueCapacity < 1 || options.QueueCapacity > 1000 {
		return nil, errors.New("live inventory queue capacity is invalid")
	}
	if options.MaxRecords < 1 || options.MaxRecords > 10000 {
		return nil, errors.New("live inventory record limit is invalid")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	root, stop := context.WithCancel(context.Background())
	service := &Service{acquire: options.Acquire, queue: make(chan string, options.QueueCapacity), maxRecords: options.MaxRecords, now: options.Now, root: root, stop: stop, records: map[string]Record{}, idempotency: map[string]string{}}
	service.wg.Add(1)
	go service.worker()
	return service, nil
}
func (service *Service) Probe(ctx context.Context, expected config.TargetIdentity) Probe {
	targetID := expected.Name
	checked := service.now().UTC()
	client, err := service.acquire(ctx, targetID)
	if err != nil {
		return Probe{CheckedAt: checked, FailureCode: failureCode(err)}
	}
	defer client.Close()
	identity := client.TargetIdentity()
	if identity != expected {
		return Probe{CheckedAt: checked, FailureCode: "target_identity_mismatch"}
	}
	if err = client.EnsureCompatible(ctx); err != nil {
		return Probe{CheckedAt: checked, FailureCode: failureCode(err)}
	}
	return Probe{Ready: true, Version: client.Version(), CheckedAt: checked}
}
func (service *Service) Start(ctx context.Context, request StartRequest) (jobs.Job, error) {
	actor, err := request.Actor.Normalized()
	if err != nil || !actor.HasPermission(auth.PermissionTargetsRead) {
		return jobs.Job{}, auth.ErrPermissionDenied
	}
	if !validID(request.TargetID) || request.Identity.Name != request.TargetID || request.Identity.StateID == "" || request.Identity.URL == "" || request.Identity.Space == "" || jobs.ValidateIdempotencyKey(request.IdempotencyKey) != nil {
		return jobs.Job{}, errors.New("live inventory request is invalid")
	}
	identityJSON, _ := json.Marshal(request.Identity)
	digestBytes := sha256.Sum256(identityJSON)
	digest := hex.EncodeToString(digestBytes[:])
	key := actor.Subject + "\x00" + request.IdempotencyKey
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closed {
		return jobs.Job{}, jobs.ErrQueueClosed
	}
	if existingID := service.idempotency[key]; existingID != "" {
		existing := service.records[existingID]
		if existing.Job.RequestDigest != digest {
			return jobs.Job{}, jobs.ErrConflict
		}
		return existing.Job, nil
	}
	if len(service.queue) >= cap(service.queue) {
		return jobs.Job{}, jobs.ErrQueueFull
	}
	service.evictLocked()
	if len(service.records) >= service.maxRecords {
		return jobs.Job{}, jobs.ErrQueueFull
	}
	id, err := inventoryID()
	if err != nil {
		return jobs.Job{}, ErrUnavailable
	}
	job, err := jobs.NewQueued(jobs.NewJobInput{Type: jobs.TypeTargetInventory, ActorSubject: actor.Subject, RequestID: request.RequestID, IdempotencyKey: request.IdempotencyKey, RequestDigest: digest}, jobs.ClockFunc(service.now), jobs.IDGeneratorFunc(func(jobs.Type) (string, error) { return id, nil }))
	if err != nil {
		return jobs.Job{}, err
	}
	service.records[id] = Record{Job: job, TargetID: request.TargetID, ExpectedIdentity: request.Identity}
	service.order = append(service.order, id)
	service.idempotency[key] = id
	service.queue <- id
	return job, nil
}
func (service *Service) Get(_ context.Context, id string) (Record, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	record, ok := service.records[id]
	if !ok {
		return Record{}, jobs.ErrNotFound
	}
	return cloneRecord(record), nil
}
func (service *Service) Shutdown(ctx context.Context) error {
	service.mu.Lock()
	if !service.closed {
		service.closed = true
		service.stop()
	}
	service.mu.Unlock()
	done := make(chan struct{})
	go func() { service.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (service *Service) worker() {
	defer service.wg.Done()
	for {
		select {
		case <-service.root.Done():
			service.cancelOutstanding()
			return
		case id := <-service.queue:
			service.execute(id)
		}
	}
}
func (service *Service) execute(id string) {
	service.mu.Lock()
	record, ok := service.records[id]
	if !ok || record.Job.Terminal() {
		service.mu.Unlock()
		return
	}
	now := service.now().UTC()
	record.Job.Status = jobs.StatusRunning
	record.Job.StartedAt = &now
	service.records[id] = record
	service.mu.Unlock()
	jobCtx, cancel := context.WithTimeout(service.root, 2*time.Minute)
	result, err := service.collect(jobCtx, record.ExpectedIdentity)
	cancel()
	service.mu.Lock()
	defer service.mu.Unlock()
	record = service.records[id]
	finished := service.now().UTC()
	record.Job.FinishedAt = &finished
	if service.root.Err() != nil {
		record.Job.Status = jobs.StatusCanceled
		record.Result = nil
	} else if err != nil {
		record.Job.Status = jobs.StatusFailed
		record.Job.FailureCode = failureCode(err)
		record.Result = nil
	} else {
		record.Job.Status = jobs.StatusSucceeded
		record.Result = result
	}
	service.records[id] = record
}
func (service *Service) collect(ctx context.Context, expected config.TargetIdentity) (*Result, error) {
	targetID := expected.Name
	client, err := service.acquire(ctx, targetID)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	identity := client.TargetIdentity()
	if identity != expected {
		return nil, errors.New("target identity mismatch")
	}
	if err := client.EnsureCompatible(ctx); err != nil {
		return nil, err
	}
	resources := make([]Resource, 0)
	packages, err := client.InstalledPackages(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range packages {
		projection, fingerprint, err := item.Canonical()
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource(manifest.KindIntegrationPackage, item.Name, item.Title, true, projection, &fingerprint))
	}
	if len(resources) > maxResources {
		return nil, errors.New("live inventory exceeds limit")
	}
	agents, err := client.AgentPolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range agents {
		projection, fingerprint, err := item.Canonical()
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource(manifest.KindAgentPolicy, item.ID, item.Name, true, projection, &fingerprint))
	}
	if len(resources) > maxResources {
		return nil, errors.New("live inventory exceeds limit")
	}
	policies, err := client.PackagePolicies(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range policies {
		projection, fingerprint, err := item.Canonical()
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource(manifest.KindPackagePolicy, item.ID, item.Name, true, projection, &fingerprint))
	}
	if len(resources) > maxResources {
		return nil, errors.New("live inventory exceeds limit")
	}
	rules, err := client.Rules(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range rules {
		if item.Manageable {
			projection, fingerprint, err := item.Canonical()
			if err != nil {
				return nil, err
			}
			resources = append(resources, resource(manifest.KindDetectionRule, item.RuleID, item.Name, true, projection, &fingerprint))
		} else {
			projection := map[string]string{"ruleID": item.RuleID, "name": item.Name, "type": item.Type}
			resources = append(resources, resource(manifest.KindDetectionRule, item.RuleID, item.Name, false, projection, nil))
		}
	}
	if len(resources) > maxResources {
		return nil, errors.New("live inventory exceeds limit")
	}
	prebuilt, err := client.PrebuiltStatus(ctx)
	if err != nil {
		return nil, err
	}
	projection, fingerprint, err := prebuilt.Canonical()
	if err != nil {
		return nil, err
	}
	resources = append(resources, resource(manifest.KindPrebuiltRules, "collective", "Prebuilt rules", true, projection, &fingerprint))
	if len(resources) > maxResources {
		return nil, errors.New("live inventory exceeds limit")
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Kind != resources[j].Kind {
			return resources[i].Kind < resources[j].Kind
		}
		return resources[i].ID < resources[j].ID
	})
	for index := 1; index < len(resources); index++ {
		if resources[index-1].Kind == resources[index].Kind && resources[index-1].ID == resources[index].ID {
			return nil, errors.New("duplicate live resource")
		}
	}
	return &Result{APIVersion: APIVersion, TargetID: targetID, Identity: identity, KibanaVersion: client.Version(), CheckedAt: service.now().UTC(), Resources: resources}, nil
}
func resource(kind manifest.Kind, id, name string, manageable bool, projection any, fingerprint *kibana.LiveFingerprint) Resource {
	encoded, _ := json.Marshal(projection)
	return Resource{Kind: kind, ID: id, Name: name, Manageable: manageable, Fingerprint: fingerprint, Projection: encoded}
}
func (service *Service) cancelOutstanding() {
	service.mu.Lock()
	defer service.mu.Unlock()
	now := service.now().UTC()
	for id, record := range service.records {
		if !record.Job.Terminal() {
			record.Job.Status = jobs.StatusCanceled
			record.Job.FinishedAt = &now
			record.Result = nil
			service.records[id] = record
		}
	}
}
func (service *Service) evictLocked() {
	for len(service.records) >= service.maxRecords && len(service.order) > 0 {
		id := service.order[0]
		record := service.records[id]
		if !record.Job.Terminal() {
			return
		}
		delete(service.records, id)
		service.order = service.order[1:]
		for key, value := range service.idempotency {
			if value == id {
				delete(service.idempotency, key)
			}
		}
	}
}
func cloneRecord(record Record) Record {
	if record.Result != nil {
		copyResult := *record.Result
		copyResult.Resources = append([]Resource{}, record.Result.Resources...)
		for index := range copyResult.Resources {
			copyResult.Resources[index].Projection = append([]byte{}, copyResult.Resources[index].Projection...)
			if copyResult.Resources[index].Fingerprint != nil {
				fingerprint := *copyResult.Resources[index].Fingerprint
				copyResult.Resources[index].Fingerprint = &fingerprint
			}
		}
		record.Result = &copyResult
	}
	return record
}
func inventoryID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return "target-inventory-" + hex.EncodeToString(value[:]), nil
}
func validID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}
func failureCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "target_read_canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "target_timeout"
	}
	if errors.Is(err, kibana.ErrTargetUnready) {
		return "target_credentials_unready"
	}
	var remote *kibana.ResponseError
	if errors.As(err, &remote) {
		switch remote.Kind() {
		case kibana.ErrorAuthentication:
			return "target_authentication_failed"
		case kibana.ErrorAuthorization:
			return "target_authorization_denied"
		case kibana.ErrorUnavailable, kibana.ErrorServer, kibana.ErrorThrottled:
			return "target_unavailable"
		default:
			return "target_protocol_error"
		}
	}
	if strings.Contains(err.Error(), "version") {
		return "unsupported_version"
	}
	return "target_protocol_error"
}
