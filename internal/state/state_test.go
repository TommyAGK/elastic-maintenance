package state

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

var testTime = time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)

func testFingerprint(domain string, character byte) Fingerprint {
	hexCharacter := "abcdef"[int(character)%len("abcdef")]
	return Fingerprint{Domain: domain, Algorithm: "sha256", Version: FingerprintVersion, Value: strings.Repeat(string(hexCharacter), 64)}
}
func desiredFingerprint(character byte) Fingerprint {
	return testFingerprint(DesiredFingerprintDomain, character)
}
func liveFingerprint(character byte) Fingerprint {
	return testFingerprint(KibanaLiveFingerprintDomain, character)
}
func inventoryFingerprint(character byte) Fingerprint {
	return testFingerprint(InventoryFingerprintDomain, character)
}
func configFingerprint(character byte) Fingerprint {
	return testFingerprint(TargetConfigFingerprintDomain, character)
}
func fingerprintPointer(value Fingerprint) *Fingerprint { return &value }
func timePointer(value time.Time) *time.Time            { return &value }

func testActor() Actor {
	return Actor{Subject: "operator@example.test", Roles: []auth.Role{auth.RolePlanner, auth.RoleViewer}, Method: auth.MethodOIDC}
}

func testTarget() manifest.InventoryTargetIdentity {
	return manifest.InventoryTargetIdentity{StateID: "state", Name: "target", URL: "https://kibana.example.test", Space: "default"}
}
func secondTarget() manifest.InventoryTargetIdentity {
	return manifest.InventoryTargetIdentity{StateID: "state", Name: "target-b", URL: "https://kibana-b.example.test", Space: "default"}
}

func testManifestSnapshot() manifest.SourceSnapshot {
	resource := manifest.ResourceSnapshot{
		Resource:      manifest.ResourceIdentity{Kind: manifest.KindAgentPolicy, ID: "agents"},
		Source:        source.Location{ResourceSetID: "sources", RelativePath: "agents.yaml", Document: 1, Line: 1, Column: 1},
		DesiredDigest: manifest.DesiredDigest{Algorithm: "sha256", Version: manifest.DesiredDigestVersion, Value: strings.Repeat("a", 64)},
	}
	return manifest.SourceSnapshot{
		APIVersion:    manifest.SourceSnapshotAPIVersion,
		DigestDomain:  manifest.DesiredDigestDomain,
		DigestVersion: manifest.DesiredDigestVersion,
		ResourceSets: []manifest.ResourceSetSnapshot{{
			ID: "sources", DesiredDigest: manifest.DesiredDigest{Algorithm: "sha256", Version: manifest.DesiredDigestVersion, Value: strings.Repeat("b", 64)},
			Files: []source.RawFileDigest{{RelativePath: "agents.yaml", SHA256: strings.Repeat("c", 64), Bytes: 10}}, Resources: []manifest.ResourceSnapshot{resource},
		}},
		Targets: []manifest.TargetSnapshot{{
			Identity: testTarget(), Labels: []manifest.Label{}, ResourceSetID: "sources", DesiredDigest: manifest.DesiredDigest{Algorithm: "sha256", Version: manifest.DesiredDigestVersion, Value: strings.Repeat("d", 64)}, Resources: []manifest.ResourceSnapshot{resource},
		}},
	}
}

func testSourceDocument() SourceSnapshot {
	return SourceSnapshot{APIVersion: APIVersion, Kind: KindSourceSnapshot, ID: "snapshot-1", CapturedAt: testTime, Snapshot: testManifestSnapshot()}
}

func testInventoryDocument() OwnershipInventory {
	return OwnershipInventory{
		APIVersion: APIVersion, Kind: KindOwnershipInventory, ID: "inventory-1", StateID: "state", Generation: 1,
		CreatedAt: testTime, UpdatedAt: testTime, Fingerprint: inventoryFingerprint('e'),
		Targets: []InventoryTarget{{
			Identity: testTarget(), Generation: 1, Fingerprint: inventoryFingerprint('f'),
			Entries: []InventoryEntry{{Kind: manifest.KindAgentPolicy, LogicalID: "agents", RemoteID: "remote-agents", Marker: MarkerDescription, LastDesiredFingerprint: desiredFingerprint('a')}},
		}},
	}
}

func assertion(presence RemotePresence, fingerprint *Fingerprint) RemoteStateAssertion {
	return RemoteStateAssertion{Presence: presence, Fingerprint: fingerprint}
}
func absent() RemoteStateAssertion { return assertion(PresenceAbsent, nil) }
func present(character byte) RemoteStateAssertion {
	return assertion(PresencePresent, fingerprintPointer(liveFingerprint(character)))
}

func testJournalDocument() PreMutationJournal {
	started, finished, verified, committed := testTime.Add(time.Minute), testTime.Add(2*time.Minute), testTime.Add(3*time.Minute), testTime.Add(4*time.Minute)
	return PreMutationJournal{
		APIVersion: APIVersion, Kind: KindPreMutationJournal, ID: "journal-1", PlanID: "plan-1", OperationID: "operation-1", Target: testTarget(),
		ResourceKind: manifest.KindAgentPolicy, LogicalID: "agents", RemoteID: "remote-agents", Action: ActionUpdate, Marker: MarkerDescription, InventoryGeneration: 1,
		Baseline: present('a'), ExpectedPost: present('b'), Lifecycle: JournalCommitted, CreatedAt: testTime, UpdatedAt: committed,
		MutationStartedAt: &started, MutationFinishedAt: &finished, PostVerifiedAt: &verified, CommittedAt: &committed,
	}
}

func testSourceProvenance(setID string, target byte) SourceProvenance {
	return SourceProvenance{ResourceSetID: setID, Revision: "git-123", ResourceSetDesiredFingerprint: desiredFingerprint('a'), TargetDesiredFingerprint: desiredFingerprint(target), TargetConfigFingerprint: configFingerprint('c')}
}

func credentialMetadata() CredentialMetadata {
	return CredentialMetadata{SecretReference: SecretReference{Namespace: "maintainer", Name: "target-secret", UID: "uid-1", ResourceVersion: "7", Generation: 2}, RotatedAt: testTime, RotatedBy: "operator@example.test", CertificateSHA256: strings.Repeat("d", 64), CertificateNotAfter: timePointer(testTime.Add(24 * time.Hour))}
}

func testPlanDocument() Plan {
	targetA := PlanTarget{Identity: testTarget(), KibanaVersion: "9.2.0", Source: testSourceProvenance("sources-a", 'b'), InventoryGeneration: 1, InventoryFingerprint: inventoryFingerprint('e'), CredentialMetadata: credentialMetadata()}
	targetB := PlanTarget{Identity: secondTarget(), KibanaVersion: "9.2.0", Source: testSourceProvenance("sources-b", 'f'), InventoryGeneration: 3, InventoryFingerprint: inventoryFingerprint('g'), CredentialMetadata: credentialMetadata()}
	return Plan{
		APIVersion: APIVersion, Kind: KindPlan, ID: "plan-1", StateID: "state", CreatedAt: testTime, CreatedBy: testActor(), ToolVersion: "test-1", SourceSnapshotID: "snapshot-1",
		Targets: []PlanTarget{targetA, targetB},
		Operations: []PlanOperation{
			{ID: "operation-1", Target: testTarget(), Phase: 0, ResourceKind: manifest.KindAgentPolicy, LogicalID: "agents", Action: ActionCreate, Dependencies: []string{}, Marker: MarkerNone, DesiredFingerprint: fingerprintPointer(desiredFingerprint('h')), Baseline: absent(), ExpectedPost: present('h')},
			{ID: "operation-2", Target: testTarget(), Phase: 1, ResourceKind: manifest.KindPackagePolicy, LogicalID: "packages", RemoteID: "remote-packages", Action: ActionUpdate, Dependencies: []string{"operation-1"}, Marker: MarkerDescription, DesiredFingerprint: fingerprintPointer(desiredFingerprint('i')), Baseline: present('j'), ExpectedPost: present('i')},
			{ID: "operation-3", Target: secondTarget(), Phase: 0, ResourceKind: manifest.KindDetectionRule, LogicalID: "old-rule", RemoteID: "remote-rule", Action: ActionDelete, Dependencies: []string{}, Marker: MarkerRuleTag, Baseline: present('k'), ExpectedPost: absent(), InventoryGeneration: 3},
		},
		Observations: []PlanObservation{
			{ID: "observation-1", Target: testTarget(), ResourceKind: manifest.KindAgentPolicy, LogicalID: "unchanged", RemoteID: "remote-agents", Marker: MarkerDescription, DesiredFingerprint: fingerprintPointer(desiredFingerprint('l')), LiveState: liveAssertionPointer(present('l')), InventoryGeneration: 1, Code: "unchanged", Severity: SeverityInfo},
			{ID: "observation-2", Target: secondTarget(), ResourceKind: manifest.KindPackagePolicy, LogicalID: "collision", Marker: MarkerNone, InventoryGeneration: 3, Code: "conflict", Severity: SeverityWarning},
		},
	}
}

func liveAssertionPointer(value RemoteStateAssertion) *RemoteStateAssertion { return &value }

func testJobDocument() Job {
	finished := testTime.Add(time.Minute)
	return Job{APIVersion: APIVersion, Kind: KindJob, ID: "job-1", Type: jobs.TypePlan, Status: jobs.StatusSucceeded, CreatedAt: testTime, StartedAt: timePointer(testTime), FinishedAt: &finished, Actor: testActor(), RequestID: "request-1", IdempotencyKey: "idem-key-1", RequestDigest: strings.Repeat("f", 64), PlanID: "plan-1"}
}

func testReportDocument() Report {
	return Report{APIVersion: APIVersion, Kind: KindReport, ID: "report-1", PlanID: "plan-1", JobID: "job-1", CreatedAt: testTime, FinishedAt: testTime.Add(time.Minute), Outcome: ReportSucceeded, Targets: []TargetReport{{Identity: testTarget(), Outcome: ReportSucceeded, Operations: []OperationResult{{ID: "operation-1", ResourceKind: manifest.KindAgentPolicy, LogicalID: "agents", RemoteID: "remote-agents", Action: ActionUpdate, Outcome: OutcomeUpdated, Baseline: present('a'), ExpectedPost: present('b')}}}}}
}

func testIdempotencyDocument() IdempotencyRecord {
	return IdempotencyRecord{APIVersion: APIVersion, Kind: KindIdempotency, ID: "idem-1", Key: "idem-key-1", Actor: testActor(), Action: "custom.mutation", RequestDigest: strings.Repeat("a", 64), JobID: "job-1", CreatedAt: testTime, Outcome: IdempotencyPending}
}

func testAuditDocument() AuditEvent {
	actor := testActor()
	return AuditEvent{APIVersion: APIVersion, Kind: KindAuditEvent, ID: "audit-1", OccurredAt: testTime, Actor: &actor, RequestID: "request-1", Action: "custom.mutation", Outcome: audit.OutcomeSucceeded, PlanID: "plan-1", JobID: "job-1"}
}

func TestRoundTripEveryPersistedKind(t *testing.T) {
	documents := []struct {
		name   string
		value  any
		decode func([]byte) (any, error)
	}{
		{"source snapshot", testSourceDocument(), func(data []byte) (any, error) { return DecodeSourceSnapshot(data) }},
		{"ownership inventory", testInventoryDocument(), func(data []byte) (any, error) { return DecodeOwnershipInventory(data) }},
		{"journal", testJournalDocument(), func(data []byte) (any, error) { return DecodePreMutationJournal(data) }},
		{"plan", testPlanDocument(), func(data []byte) (any, error) { return DecodePlan(data) }},
		{"job", testJobDocument(), func(data []byte) (any, error) { return DecodeJob(data) }},
		{"report", testReportDocument(), func(data []byte) (any, error) { return DecodeReport(data) }},
		{"idempotency", testIdempotencyDocument(), func(data []byte) (any, error) { return DecodeIdempotency(data) }},
		{"audit", testAuditDocument(), func(data []byte) (any, error) { return DecodeAuditEvent(data) }},
	}
	for _, test := range documents {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := Encode(test.value)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := test.decode(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(test.value, decoded) {
				t.Fatalf("round trip changed value:\noriginal %#v\ndecoded %#v", test.value, decoded)
			}
			generic, err := DecodeDocument(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if err := generic.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestFingerprintDomainsAndRemotePresence(t *testing.T) {
	if err := testFingerprint(DesiredFingerprintDomain, 'a').Validate(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name  string
		value Fingerprint
	}{
		{"empty domain", testFingerprint("", 'a')},
		{"live in desired field", liveFingerprint('a')},
		{"wrong version", Fingerprint{Domain: DesiredFingerprintDomain, Algorithm: "sha256", Version: "v2", Value: strings.Repeat("a", 64)}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "live in desired field" {
				plan := testPlanDocument()
				plan.Operations[0].DesiredFingerprint = fingerprintPointer(test.value)
				if _, err := Encode(plan); err == nil {
					t.Fatal("live fingerprint accepted in desired field")
				}
				return
			}
			if test.value.Domain != "" && test.value.Version == FingerprintVersion {
				if err := validateFingerprint("test", test.value, DesiredFingerprintDomain); err == nil {
					t.Fatal("wrong domain accepted")
				}
				return
			}
			if err := test.value.Validate(); err == nil {
				t.Fatal("invalid fingerprint accepted")
			}
		})
	}
	plan := testPlanDocument()
	plan.Operations[0].Baseline = RemoteStateAssertion{Presence: PresenceAbsent, Fingerprint: fingerprintPointer(liveFingerprint('x'))}
	if _, err := Encode(plan); err == nil {
		t.Fatal("fingerprint accepted for absent remote state")
	}
	plan = testPlanDocument()
	plan.Operations[0].ExpectedPost = RemoteStateAssertion{Presence: PresencePresent}
	if _, err := Encode(plan); err == nil {
		t.Fatal("missing fingerprint accepted for present remote state")
	}
	encoded, err := Encode(testPlanDocument())
	if err != nil {
		t.Fatal(err)
	}
	nullFingerprint := bytes.Replace(encoded,
		[]byte(`"expectedPost":{"presence":"present","fingerprint":{"domain":"elastic-maintainer/kibana-live","algorithm":"sha256","version":"v1","value":"`+strings.Repeat("c", 64)+`"}}`),
		[]byte(`"expectedPost":{"presence":"present","fingerprint":null}`), 1)
	var decodedPlan Plan
	if err := Decode(nullFingerprint, &decodedPlan); err == nil {
		t.Fatal("explicit null fingerprint accepted")
	}
}

func TestPlanContract(t *testing.T) {
	plan := testPlanDocument()
	if err := plan.Validate(); err != nil {
		t.Fatal(err)
	}
	unsorted := plan.Clone()
	unsorted.Operations[1], unsorted.Operations[0] = unsorted.Operations[0], unsorted.Operations[1]
	if _, err := Encode(unsorted); err == nil {
		t.Fatal("unsorted phase operations accepted")
	}
	badDependency := plan.Clone()
	badDependency.Operations[1].Dependencies = []string{"operation-3"}
	if _, err := Encode(badDependency); err == nil {
		t.Fatal("dependency on another target accepted")
	}
	badDependency = plan.Clone()
	badDependency.Operations[0].Dependencies = []string{"operation-2"}
	if _, err := Encode(badDependency); err == nil {
		t.Fatal("dependency on a later operation accepted")
	}
	badGeneration := plan.Clone()
	badGeneration.Operations[2].InventoryGeneration = 2
	if _, err := Encode(badGeneration); err == nil {
		t.Fatal("delete with stale inventory generation accepted")
	}
	for _, kind := range []manifest.Kind{manifest.KindIntegrationPackage, manifest.KindPrebuiltRules} {
		blocked := plan.Clone()
		blocked.Operations[2].ResourceKind = kind
		if _, err := Encode(blocked); err == nil {
			t.Fatalf("delete of %s accepted", kind)
		}
	}
	overlap := plan.Clone()
	overlap.Observations[0].LogicalID = "agents"
	if _, err := Encode(overlap); err == nil {
		t.Fatal("operation and observation identity overlap accepted")
	}
	invalidAction := plan.Clone()
	invalidAction.Operations[0].Action = OperationAction("conflict")
	if _, err := Encode(invalidAction); err == nil {
		t.Fatal("observation action accepted as operation")
	}
}

func TestCredentialMetadataAndIdempotencyRules(t *testing.T) {
	plan := testPlanDocument()
	plan.Targets[0].CredentialMetadata.SecretReference.ResourceVersion = ""
	if _, err := Encode(plan); err == nil {
		t.Fatal("credential metadata without resourceVersion accepted")
	}
	plan = testPlanDocument()
	plan.Targets[0].CredentialMetadata.RotatedBy = ""
	if _, err := Encode(plan); err == nil {
		t.Fatal("credential metadata without rotatedBy accepted")
	}
	pending := testIdempotencyDocument()
	pending.JobID = ""
	if _, err := Encode(pending); err == nil {
		t.Fatal("pending synchronous record accepted")
	}
	terminal := pending
	terminal.JobID = ""
	terminal.Outcome = IdempotencySucceeded
	terminal.Result = &ResultReference{Kind: ResultKindReport, ID: "report-1"}
	if _, err := Encode(terminal); err != nil {
		t.Fatalf("synchronous terminal record rejected: %v", err)
	}
	terminal.Action = "not-namespaced"
	if _, err := Encode(terminal); err == nil {
		t.Fatal("un-namespaced action accepted")
	}
}

func mustEncode(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestStrictJSONHeadersTrailingAndNilDestination(t *testing.T) {
	encoded, err := Encode(testJobDocument())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"top-level null", []byte(`null`), ErrInvalidDocument},
		{"top-level array", []byte(`[]`), ErrInvalidDocument},
		{"unknown field", append(encoded[:len(encoded)-1], []byte(`,"unexpected":true}`)...), ErrInvalidDocument},
		{"secret field", append(encoded[:len(encoded)-1], []byte(`,"api-key":"SECRET-SENTINEL-DO-NOT-PERSIST"}`)...), ErrInvalidDocument},
		{"non-canonical field casing", bytes.Replace(encoded, []byte(`"id":"job-1"`), []byte(`"ID":"job-1"`), 1), ErrInvalidDocument},
		{"nested non-canonical field casing", bytes.Replace(mustEncode(t, testSourceDocument()), []byte(`"resource":`), []byte(`"RESOURCE":`), 1), ErrInvalidDocument},
		{"nested desired digest casing", bytes.Replace(mustEncode(t, testSourceDocument()), []byte(`"desiredDigest":`), []byte(`"DESIREDDIGEST":`), 1), ErrInvalidDocument},
		{"nested URL casing", bytes.Replace(mustEncode(t, testSourceDocument()), []byte(`"url":`), []byte(`"URL":`), 1), ErrInvalidDocument},
		{"nested space casing", bytes.Replace(mustEncode(t, testSourceDocument()), []byte(`"space":"default"`), []byte(`"SPACE":"default"`), 1), ErrInvalidDocument},
		{"whitespace only", []byte(" \t\r\n"), ErrInvalidDocument},
		{"truncated JSON", encoded[:len(encoded)-1], ErrInvalidDocument},
		{"malformed JSON", []byte(`{"apiVersion":`), ErrInvalidDocument},
		{"malformed trailing JSON", append(encoded, []byte(` {`)...), ErrTrailingJSON},
		{"invalid UTF-8", append([]byte(`{"apiVersion":"`), append([]byte(APIVersion), []byte{0xff, '"', '}'}...)...), ErrInvalidDocument},
		{"unsupported version", bytes.Replace(encoded, []byte(APIVersion), []byte("elastic-maintainer/state/v2"), 1), ErrUnsupportedVersion},
		{"unsupported kind", bytes.Replace(encoded, []byte(`"Job"`), []byte(`"NotAJob"`), 1), ErrUnsupportedKind},
		{"trailing value", append(encoded, []byte(` {}`)...), ErrTrailingJSON},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			var destination Job
			err := Decode(test.data, &destination)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want errors.Is %v", err, test.want)
			}
		})
	}
	var destination *Job
	if !errors.Is(Decode(encoded, destination), ErrNilDestination) {
		t.Fatal("nil typed destination was accepted")
	}
	if !errors.Is(Decode(encoded, nil), ErrNilDestination) {
		t.Fatal("nil destination was accepted")
	}
}

func TestDuplicateJSONAndSecretScans(t *testing.T) {
	encoded, err := Encode(testJobDocument())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := append(encoded[:len(encoded)-1], []byte(`,"id":"job-2"}`)...)
	var job Job
	if !errors.Is(Decode(duplicate, &job), ErrDuplicateField) {
		t.Fatalf("duplicate JSON key error = %v", Decode(duplicate, &job))
	}
	for _, document := range []any{testSourceDocument(), testInventoryDocument(), testJournalDocument(), testPlanDocument(), testJobDocument(), testReportDocument(), testIdempotencyDocument(), testAuditDocument()} {
		encoded, err := Encode(document)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(encoded))
		for _, forbidden := range []string{"api-key", "ca.crt", "access_token", "csrfToken", "sessionToken", "cookie", "authorization"} {
			if strings.Contains(text, strings.ToLower(forbidden)) {
				t.Fatalf("forbidden secret-related field %q found in %T: %s", forbidden, document, text)
			}
		}
	}
}

func TestCloneAndEncodeDoNotAliasInput(t *testing.T) {
	sourceDocument := testSourceDocument()
	clone := sourceDocument.Clone()
	if clone.Snapshot.Targets[0].Labels == nil {
		t.Fatal("clone converted an empty labels array to null")
	}
	clone.Snapshot.ResourceSets[0].Resources[0].Source.RelativePath = "changed.yaml"
	if sourceDocument.Snapshot.ResourceSets[0].Resources[0].Source.RelativePath == "changed.yaml" {
		t.Fatal("source snapshot clone aliases nested resource")
	}
	plan := testPlanDocument()
	planClone := plan.Clone()
	planClone.CreatedBy.Roles[0] = auth.RoleAdministrator
	planClone.Operations[0].Dependencies = append(planClone.Operations[0].Dependencies, "other")
	planClone.Operations[1].Baseline.Fingerprint.Value = strings.Repeat("f", 64)
	if plan.CreatedBy.Roles[0] == auth.RoleAdministrator || len(plan.Operations[0].Dependencies) != 0 || plan.Operations[1].Baseline.Fingerprint.Value == strings.Repeat("f", 64) {
		t.Fatal("plan clone aliases nested values")
	}
	encoded, err := Encode(plan)
	if err != nil {
		t.Fatal(err)
	}
	plan.Operations[0].Dependencies = []string{"mutated-after-encode"}
	decoded, err := DecodePlan(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Operations[0].Dependencies) != 0 {
		t.Fatal("encoded state retained mutable input aliases")
	}
}

func TestRemoteIdentityAndOutcomeContracts(t *testing.T) {
	plan := testPlanDocument()
	plan.Operations[0].RemoteID = "remote-created"
	if _, err := Encode(plan); err == nil {
		t.Fatal("create plan operation with remote ID accepted")
	}
	plan = testPlanDocument()
	plan.Operations[1].RemoteID = ""
	if _, err := Encode(plan); err == nil {
		t.Fatal("update plan operation without remote ID accepted")
	}
	plan = testPlanDocument()
	plan.Operations[1].Marker = MarkerRuleTag
	if _, err := Encode(plan); err == nil {
		t.Fatal("update plan operation with incompatible marker accepted")
	}

	createJournal := testJournalDocument()
	createJournal.Action = ActionCreate
	createJournal.Marker = MarkerNone
	createJournal.InventoryGeneration = 0
	createJournal.RemoteID = ""
	createJournal.Baseline = absent()
	createJournal.ExpectedPost = present('c')
	createJournal.Lifecycle = JournalPrepared
	createJournal.MutationStartedAt = nil
	createJournal.MutationFinishedAt = nil
	createJournal.PostVerifiedAt = nil
	createJournal.CommittedAt = nil
	createJournal.UpdatedAt = testTime
	if _, err := Encode(createJournal); err != nil {
		t.Fatalf("prepared create journal without remote ID rejected: %v", err)
	}
	createJournal.Lifecycle = JournalMutationSucceeded
	started, finished := testTime.Add(time.Minute), testTime.Add(2*time.Minute)
	createJournal.MutationStartedAt = &started
	createJournal.MutationFinishedAt = &finished
	createJournal.UpdatedAt = finished
	if _, err := Encode(createJournal); err == nil {
		t.Fatal("mutation-succeeded create journal without remote ID accepted")
	}

	updateJournal := testJournalDocument()
	updateJournal.ResourceKind = manifest.KindIntegrationPackage
	updateJournal.LogicalID = "integration"
	updateJournal.Marker = MarkerNone
	if _, err := Encode(updateJournal); err != nil {
		t.Fatalf("integration update journal with compatible marker rejected: %v", err)
	}
	deleteJournal := updateJournal
	deleteJournal.Action = ActionDelete
	deleteJournal.ExpectedPost = absent()
	deleteJournal.Lifecycle = JournalPrepared
	deleteJournal.MutationStartedAt = nil
	deleteJournal.MutationFinishedAt = nil
	deleteJournal.PostVerifiedAt = nil
	deleteJournal.CommittedAt = nil
	deleteJournal.UpdatedAt = testTime
	if _, err := Encode(deleteJournal); err == nil {
		t.Fatal("integration delete journal accepted")
	}

	result := testReportDocument().Targets[0].Operations[0]
	result.RemoteID = ""
	if err := validateOperationResult(result); err == nil {
		t.Fatal("update result without remote ID accepted")
	}
	result = testReportDocument().Targets[0].Operations[0]
	result.Action = ActionCreate
	result.Outcome = OutcomeCreated
	result.Baseline = absent()
	result.ExpectedPost = present('b')
	result.RemoteID = ""
	if err := validateOperationResult(result); err == nil {
		t.Fatal("created result without remote ID accepted")
	}
	result.Outcome = OutcomeFailed
	if err := validateOperationResult(result); err != nil {
		t.Fatalf("failed create without remote ID rejected: %v", err)
	}
	result.Outcome = OutcomeUpdated
	if err := validateOperationResult(result); err == nil {
		t.Fatal("updated outcome accepted for create action")
	}
}

func TestInventoryMarkersStateIDActorsAndSafeDiagnostics(t *testing.T) {
	for _, test := range []struct {
		kind   manifest.Kind
		marker MarkerType
	}{
		{manifest.KindIntegrationPackage, MarkerNone},
		{manifest.KindAgentPolicy, MarkerDescription},
		{manifest.KindPackagePolicy, MarkerDescription},
		{manifest.KindDetectionRule, MarkerRuleTag},
		{manifest.KindPrebuiltRules, MarkerPrebuiltStatus},
	} {
		inventory := testInventoryDocument()
		inventory.Targets[0].Entries[0].Kind = test.kind
		inventory.Targets[0].Entries[0].LogicalID = "resource"
		inventory.Targets[0].Entries[0].RemoteID = "remote-resource"
		inventory.Targets[0].Entries[0].Marker = test.marker
		if _, err := Encode(inventory); err != nil {
			t.Fatalf("marker %s for %s rejected: %v", test.marker, test.kind, err)
		}
	}
	inventory := testInventoryDocument()
	inventory.Targets[0].Entries[0].Marker = MarkerRuleTag
	if _, err := Encode(inventory); err == nil {
		t.Fatal("incompatible inventory marker accepted")
	}

	plan := testPlanDocument()
	plan.StateID = "other-state"
	if _, err := Encode(plan); err == nil {
		t.Fatal("plan target with mismatched state ID accepted")
	}
	plan = testPlanDocument()
	plan.CreatedBy.Subject = " operator@example.test"
	if _, err := Encode(plan); err == nil {
		t.Fatal("actor subject with leading whitespace accepted")
	}
	encoded, err := Encode(testPlanDocument())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(encoded)), "message") {
		t.Fatalf("arbitrary diagnostic message persisted: %s", encoded)
	}
}

func TestTypedIdempotencyResults(t *testing.T) {
	invalidPending := testIdempotencyDocument()
	invalidPending.JobID = "job.with.dot"
	if _, err := Encode(invalidPending); err == nil {
		t.Fatal("invalid durable job ID accepted")
	}
	terminal := testIdempotencyDocument()
	terminal.Outcome = IdempotencySucceeded
	terminal.JobID = ""
	terminal.Result = &ResultReference{Kind: ResultKindReport, ID: "report-1"}
	if _, err := Encode(terminal); err != nil {
		t.Fatalf("typed synchronous result rejected: %v", err)
	}
	jobResult := testIdempotencyDocument()
	jobResult.Outcome = IdempotencySucceeded
	jobResult.Result = &ResultReference{Kind: ResultKindJob, ID: jobResult.JobID}
	if _, err := Encode(jobResult); err != nil {
		t.Fatalf("typed job result rejected: %v", err)
	}
	jobResult.Result.ID = "job-2"
	if _, err := Encode(jobResult); err == nil {
		t.Fatal("job result linked to a different job accepted")
	}
	pending := testIdempotencyDocument()
	pending.Result = &ResultReference{Kind: ResultKindPlan, ID: "plan-1"}
	if _, err := Encode(pending); err == nil {
		t.Fatal("pending idempotency result accepted")
	}
	terminal.Result = &ResultReference{Kind: ResultKind("unknown"), ID: "result-1"}
	if _, err := Encode(terminal); err == nil {
		t.Fatal("unknown idempotency result kind accepted")
	}
}

func TestActorFromAuthNormalizesProjection(t *testing.T) {
	projected, err := ActorFromAuth(auth.Actor{Subject: " operator ", Roles: []auth.Role{auth.RoleViewer, auth.RolePlanner, auth.RoleViewer}, Method: auth.MethodOIDC})
	if err != nil {
		t.Fatal(err)
	}
	if projected.Subject != "operator" || !reflect.DeepEqual(projected.Roles, []auth.Role{auth.RolePlanner, auth.RoleViewer}) {
		t.Fatalf("actor=%#v", projected)
	}
}

func TestInvalidTimeDigestAndEnumsRejected(t *testing.T) {
	job := testJobDocument()
	job.CreatedAt = time.Time{}
	if _, err := Encode(job); err == nil {
		t.Fatal("zero time was accepted")
	}
	job = testJobDocument()
	job.RequestDigest = strings.Repeat("A", 64)
	if _, err := Encode(job); err == nil {
		t.Fatal("uppercase digest was accepted")
	}
	job = testJobDocument()
	job.Status = jobs.Status("unknown")
	if _, err := Encode(job); err == nil {
		t.Fatal("unknown job status was accepted")
	}
	snapshot := testSourceDocument()
	snapshot.Snapshot.ResourceSets[0].Resources[0].Source.RelativePath = "bad\x00path.yaml"
	if _, err := Encode(snapshot); err == nil {
		t.Fatal("control character in source path was accepted")
	}
	encoded := mustEncode(t, testSourceDocument())
	nullFiles := bytes.Replace(encoded, []byte(`"files":[`), []byte(`"files":null`), 1)
	var decodedSnapshot SourceSnapshot
	if err := Decode(nullFiles, &decodedSnapshot); err == nil {
		t.Fatal("null source files accepted")
	}
	missingFiles := bytes.Replace(encoded, []byte(`,"files":[{"relativePath"`), []byte(``), 1)
	if err := Decode(missingFiles, &decodedSnapshot); err == nil {
		t.Fatal("missing source files accepted")
	}
}
