package liveinventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/config"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/kibana"
)

type fakeClient struct {
	mu       sync.Mutex
	closed   bool
	fail     error
	packages []kibana.InstalledPackage
	agents   []kibana.AgentPolicy
	policies []kibana.PackagePolicy
	rules    []kibana.Rule
	prebuilt kibana.PrebuiltStatus
	identity config.TargetIdentity
}

func (client *fakeClient) Close() { client.mu.Lock(); client.closed = true; client.mu.Unlock() }
func (client *fakeClient) TargetIdentity() config.TargetIdentity {
	return client.identity
}
func (client *fakeClient) EnsureCompatible(context.Context) error { return client.fail }
func (client *fakeClient) Version() string                        { return "9.4.2" }
func (client *fakeClient) InstalledPackages(context.Context) ([]kibana.InstalledPackage, error) {
	return client.packages, client.fail
}
func (client *fakeClient) AgentPolicies(context.Context) ([]kibana.AgentPolicy, error) {
	return client.agents, client.fail
}
func (client *fakeClient) PackagePolicies(context.Context) ([]kibana.PackagePolicy, error) {
	return client.policies, client.fail
}
func (client *fakeClient) Rules(context.Context) ([]kibana.Rule, error) {
	return client.rules, client.fail
}
func (client *fakeClient) PrebuiltStatus(context.Context) (kibana.PrebuiltStatus, error) {
	return client.prebuilt, client.fail
}
func TestInventoryJobCollectsSafeCanonicalResourcesAndClosesLease(t *testing.T) {
	client := inventoryFixtureClient(t)
	service, err := New(Options{Acquire: func(context.Context, string) (Client, error) { return client, nil }, QueueCapacity: 2, MaxRecords: 10})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown(context.Background())
	request := StartRequest{TargetID: "prod", Identity: config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"}, RequestID: "request-1", IdempotencyKey: "inventory-request-1", Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}}
	job, err := service.Start(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	same, err := service.Start(context.Background(), request)
	if err != nil || same.ID != job.ID {
		t.Fatalf("idempotent=%#v error=%v", same, err)
	}
	record := waitRecord(t, service, job.ID)
	if record.Job.Status != jobs.StatusSucceeded || record.Result == nil || len(record.Result.Resources) != 5 {
		t.Fatalf("record=%#v", record)
	}
	encoded, _ := json.Marshal(record)
	for _, forbidden := range []string{"created_by", "updated_by", "inputs", "actions", "credential-sentinel"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("result leaked baseline field %q", forbidden)
		}
	}
	client.mu.Lock()
	closed := client.closed
	client.mu.Unlock()
	if !closed {
		t.Fatal("client lease was not closed")
	}
}
func TestQueuedInventoryRejectsFullTargetIdentityChange(t *testing.T) {
	client := inventoryFixtureClient(t)
	client.identity.URL = "https://changed.example.test"
	service, _ := New(Options{Acquire: func(context.Context, string) (Client, error) { return client, nil }, QueueCapacity: 1, MaxRecords: 2})
	defer service.Shutdown(context.Background())
	expected := config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"}
	job, err := service.Start(context.Background(), StartRequest{TargetID: "prod", Identity: expected, RequestID: "request-identity", IdempotencyKey: "inventory-identity", Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodOIDC}})
	if err != nil {
		t.Fatal(err)
	}
	record := waitRecord(t, service, job.ID)
	if record.Job.Status != jobs.StatusFailed || record.Result != nil || record.Job.FailureCode != "target_protocol_error" {
		t.Fatalf("record=%#v", record)
	}
}

func TestInventoryFailureReturnsNoPartialResult(t *testing.T) {
	client := inventoryFixtureClient(t)
	client.fail = errors.New("credential-sentinel")
	service, _ := New(Options{Acquire: func(context.Context, string) (Client, error) { return client, nil }, QueueCapacity: 1, MaxRecords: 2})
	defer service.Shutdown(context.Background())
	job, err := service.Start(context.Background(), StartRequest{TargetID: "prod", Identity: config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"}, RequestID: "request-2", IdempotencyKey: "inventory-request-2", Actor: auth.Actor{Subject: "viewer", Roles: []auth.Role{auth.RoleViewer}, Method: auth.MethodBearer}})
	if err != nil {
		t.Fatal(err)
	}
	record := waitRecord(t, service, job.ID)
	if record.Job.Status != jobs.StatusFailed || record.Result != nil || record.Job.FailureCode == "" || strings.Contains(record.Job.FailureCode, "sentinel") {
		t.Fatalf("record=%#v", record)
	}
}
func TestProbeIsSafeAndPermissionIsServiceEnforced(t *testing.T) {
	client := inventoryFixtureClient(t)
	service, _ := New(Options{Acquire: func(context.Context, string) (Client, error) { return client, nil }, QueueCapacity: 1, MaxRecords: 2})
	defer service.Shutdown(context.Background())
	probe := service.Probe(context.Background(), config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"})
	if !probe.Ready || probe.Version != "9.4.2" {
		t.Fatalf("probe=%#v", probe)
	}
	_, err := service.Start(context.Background(), StartRequest{TargetID: "prod", Identity: config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"}, RequestID: "request-3", IdempotencyKey: "inventory-request-3", Actor: auth.Actor{Subject: "none", Method: auth.MethodOIDC}})
	if !errors.Is(err, auth.ErrPermissionDenied) {
		t.Fatalf("permission error=%v", err)
	}
}
func waitRecord(t *testing.T, service *Service, id string) Record {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		record, err := service.Get(context.Background(), id)
		if err == nil && record.Job.Terminal() {
			return record
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("job did not finish")
	return Record{}
}
func inventoryFixtureClient(t *testing.T) *fakeClient {
	t.Helper()
	root := filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0")
	read := func(name string) []byte {
		contents, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return contents
	}
	var packageEnvelope struct {
		Item kibana.InstalledPackage `json:"item"`
	}
	json.Unmarshal(read("integration-package.json"), &packageEnvelope)
	var agentEnvelope struct {
		Item kibana.AgentPolicy `json:"item"`
	}
	json.Unmarshal(read("agent-policy.json"), &agentEnvelope)
	var policyEnvelope struct {
		Item kibana.PackagePolicy `json:"item"`
	}
	json.Unmarshal(read("package-policy.json"), &policyEnvelope)
	var rule kibana.Rule
	json.Unmarshal(read("detection-rule.json"), &rule)
	rule.Manageable = true
	var prebuilt kibana.PrebuiltStatus
	json.Unmarshal(read("prebuilt-status.json"), &prebuilt)
	return &fakeClient{identity: config.TargetIdentity{StateID: "state", Name: "prod", URL: "https://example.test", Space: "default"}, packages: []kibana.InstalledPackage{packageEnvelope.Item}, agents: []kibana.AgentPolicy{agentEnvelope.Item}, policies: []kibana.PackagePolicy{policyEnvelope.Item}, rules: []kibana.Rule{rule}, prebuilt: prebuilt}
}
