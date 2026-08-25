// Package state defines the versioned, non-secret JSON documents used by the
// maintainer. It deliberately contains schemas only; filesystem I/O,
// locking, and job execution are later phase responsibilities.
package state

import (
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
)

const (
	APIVersion = "elastic-maintainer/state/v1alpha1"

	KindSourceSnapshot     Kind = "SourceSnapshot"
	KindOwnershipInventory Kind = "OwnershipInventory"
	KindPreMutationJournal Kind = "PreMutationJournal"
	KindPlan               Kind = "Plan"
	KindJob                Kind = "Job"
	KindReport             Kind = "Report"
	KindIdempotency        Kind = "Idempotency"
	KindAuditEvent         Kind = "AuditEvent"
)

// Fingerprint domains are intentionally distinct. A fingerprint from one
// domain must never be accepted in a field belonging to another domain.
const (
	FingerprintVersion            = "v1"
	DesiredFingerprintDomain      = "elastic-maintainer/desired"
	KibanaLiveFingerprintDomain   = "elastic-maintainer/kibana-live"
	InventoryFingerprintDomain    = "elastic-maintainer/ownership-inventory"
	TargetConfigFingerprintDomain = "elastic-maintainer/target-config"
)

type Kind string

// Document is implemented by every persisted top-level document.
type Document interface {
	Validate() error
	documentKind() Kind
}

// Fingerprint is the only persisted digest projection. Its domain is part of
// the value so a desired, live, inventory, or target-config digest cannot be
// confused at a call site or by a decoder.
type Fingerprint struct {
	Domain    string `json:"domain"`
	Algorithm string `json:"algorithm"`
	Version   string `json:"version"`
	Value     string `json:"value"`
}

// Actor is the deliberately small actor projection allowed in persisted state.
// In particular, it has no display name, session, CSRF, cookie, or token
// fields.
type Actor struct {
	Subject string      `json:"subject"`
	Roles   []auth.Role `json:"roles"`
	Method  auth.Method `json:"authMethod"`
}

func ActorFromAuth(value auth.Actor) (Actor, error) {
	normalized, err := value.Normalized()
	if err != nil {
		return Actor{}, err
	}
	return Actor{Subject: normalized.Subject, Roles: append([]auth.Role(nil), normalized.Roles...), Method: normalized.Method}, nil
}

// SecretReference contains Kubernetes object metadata only. Secret data and
// credential values are intentionally not representable by this type.
type SecretReference struct {
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	UID             string `json:"uid,omitempty"`
	ResourceVersion string `json:"resourceVersion"`
	Generation      int64  `json:"generation,omitempty"`
}

type CredentialMetadata struct {
	SecretReference     SecretReference `json:"secretReference"`
	RotatedAt           time.Time       `json:"rotatedAt"`
	RotatedBy           string          `json:"rotatedBy"`
	CertificateSHA256   string          `json:"certificateSHA256,omitempty"`
	CertificateNotAfter *time.Time      `json:"certificateNotAfter,omitempty"`
}

type SourceSnapshot struct {
	APIVersion string                  `json:"apiVersion"`
	Kind       Kind                    `json:"kind"`
	ID         string                  `json:"id"`
	CapturedAt time.Time               `json:"capturedAt"`
	Snapshot   manifest.SourceSnapshot `json:"snapshot"`
}

// OwnershipInventory is the durable ownership authority for one state
// instance. Target identities are never reduced to a display name.
type OwnershipInventory struct {
	APIVersion  string            `json:"apiVersion"`
	Kind        Kind              `json:"kind"`
	ID          string            `json:"id"`
	StateID     string            `json:"stateID"`
	Generation  uint64            `json:"generation"`
	CreatedAt   time.Time         `json:"createdAt"`
	UpdatedAt   time.Time         `json:"updatedAt"`
	Fingerprint Fingerprint       `json:"fingerprint"`
	Targets     []InventoryTarget `json:"targets"`
}

type InventoryTarget struct {
	Identity    manifest.InventoryTargetIdentity `json:"identity"`
	Generation  uint64                           `json:"generation"`
	Fingerprint Fingerprint                      `json:"fingerprint"`
	Entries     []InventoryEntry                 `json:"entries"`
}

type InventoryEntry struct {
	Kind                   manifest.Kind `json:"kind"`
	LogicalID              string        `json:"logicalID"`
	RemoteID               string        `json:"remoteID"`
	Marker                 MarkerType    `json:"marker"`
	LastDesiredFingerprint Fingerprint   `json:"lastDesiredFingerprint"`
}

type MarkerType string

const (
	MarkerNone           MarkerType = "none"
	MarkerDescription    MarkerType = "description"
	MarkerRuleTag        MarkerType = "rule-tag"
	MarkerPrebuiltStatus MarkerType = "prebuilt-status"
)

type RemotePresence string

const (
	PresenceAbsent  RemotePresence = "absent"
	PresencePresent RemotePresence = "present"
)

type RemoteStateAssertion struct {
	Presence    RemotePresence `json:"presence"`
	Fingerprint *Fingerprint   `json:"fingerprint,omitempty"`
}

type PreMutationJournal struct {
	APIVersion          string                           `json:"apiVersion"`
	Kind                Kind                             `json:"kind"`
	ID                  string                           `json:"id"`
	PlanID              string                           `json:"planID"`
	OperationID         string                           `json:"operationID"`
	Target              manifest.InventoryTargetIdentity `json:"target"`
	ResourceKind        manifest.Kind                    `json:"resourceKind"`
	LogicalID           string                           `json:"logicalID"`
	RemoteID            string                           `json:"remoteID,omitempty"`
	Action              OperationAction                  `json:"action"`
	Marker              MarkerType                       `json:"marker"`
	InventoryGeneration uint64                           `json:"inventoryGeneration"`
	Baseline            RemoteStateAssertion             `json:"baseline"`
	ExpectedPost        RemoteStateAssertion             `json:"expectedPost"`
	Lifecycle           JournalLifecycle                 `json:"lifecycle"`
	CreatedAt           time.Time                        `json:"createdAt"`
	UpdatedAt           time.Time                        `json:"updatedAt"`
	MutationStartedAt   *time.Time                       `json:"mutationStartedAt,omitempty"`
	MutationFinishedAt  *time.Time                       `json:"mutationFinishedAt,omitempty"`
	PostVerifiedAt      *time.Time                       `json:"postVerifiedAt,omitempty"`
	CommittedAt         *time.Time                       `json:"committedAt,omitempty"`
}

type JournalLifecycle string

const (
	JournalPrepared          JournalLifecycle = "prepared"
	JournalMutating          JournalLifecycle = "mutating"
	JournalMutationSucceeded JournalLifecycle = "mutation-succeeded"
	JournalPostVerified      JournalLifecycle = "post-verified"
	JournalCommitted         JournalLifecycle = "committed"
	JournalRecoveryRequired  JournalLifecycle = "recovery-required"
	JournalAbandoned         JournalLifecycle = "abandoned"
)

type SourceProvenance struct {
	ResourceSetID                 string      `json:"resourceSetID"`
	Revision                      string      `json:"revision,omitempty"`
	ResourceSetDesiredFingerprint Fingerprint `json:"resourceSetDesiredFingerprint"`
	TargetDesiredFingerprint      Fingerprint `json:"targetDesiredFingerprint"`
	TargetConfigFingerprint       Fingerprint `json:"targetConfigFingerprint"`
}

type PlanTarget struct {
	Identity             manifest.InventoryTargetIdentity `json:"identity"`
	KibanaVersion        string                           `json:"kibanaVersion"`
	Source               SourceProvenance                 `json:"source"`
	InventoryGeneration  uint64                           `json:"inventoryGeneration"`
	InventoryFingerprint Fingerprint                      `json:"inventoryFingerprint"`
	CredentialMetadata   CredentialMetadata               `json:"credentialMetadata"`
}

type Plan struct {
	APIVersion       string            `json:"apiVersion"`
	Kind             Kind              `json:"kind"`
	ID               string            `json:"id"`
	StateID          string            `json:"stateID"`
	CreatedAt        time.Time         `json:"createdAt"`
	CreatedBy        Actor             `json:"createdBy"`
	ToolVersion      string            `json:"toolVersion"`
	SourceSnapshotID string            `json:"sourceSnapshotID"`
	Targets          []PlanTarget      `json:"targets"`
	Operations       []PlanOperation   `json:"operations"`
	Observations     []PlanObservation `json:"observations"`
}

type OperationAction string

const (
	ActionCreate OperationAction = "create"
	ActionUpdate OperationAction = "update"
	ActionDelete OperationAction = "delete"
)

type PlanOperation struct {
	ID                  string                           `json:"id"`
	Target              manifest.InventoryTargetIdentity `json:"target"`
	Phase               int                              `json:"phase"`
	ResourceKind        manifest.Kind                    `json:"resourceKind"`
	LogicalID           string                           `json:"logicalID"`
	RemoteID            string                           `json:"remoteID,omitempty"`
	Action              OperationAction                  `json:"action"`
	Dependencies        []string                         `json:"dependencies"`
	Marker              MarkerType                       `json:"marker"`
	DesiredFingerprint  *Fingerprint                     `json:"desiredFingerprint,omitempty"`
	Baseline            RemoteStateAssertion             `json:"baseline"`
	ExpectedPost        RemoteStateAssertion             `json:"expectedPost"`
	InventoryGeneration uint64                           `json:"inventoryGeneration"`
}

type ObservationSeverity string

const (
	SeverityInfo    ObservationSeverity = "info"
	SeverityWarning ObservationSeverity = "warning"
	SeverityError   ObservationSeverity = "error"
)

type PlanObservation struct {
	ID                  string                           `json:"id"`
	Target              manifest.InventoryTargetIdentity `json:"target"`
	ResourceKind        manifest.Kind                    `json:"resourceKind"`
	LogicalID           string                           `json:"logicalID,omitempty"`
	RemoteID            string                           `json:"remoteID,omitempty"`
	Marker              MarkerType                       `json:"marker"`
	DesiredFingerprint  *Fingerprint                     `json:"desiredFingerprint,omitempty"`
	LiveState           *RemoteStateAssertion            `json:"liveState,omitempty"`
	InventoryGeneration uint64                           `json:"inventoryGeneration"`
	Code                string                           `json:"code"`
	Severity            ObservationSeverity              `json:"severity"`
}

// Job is the durable projection of jobs.Job. IdempotencyKey and RequestDigest
// are explicit here because jobs.Job intentionally omits them from JSON.
type Job struct {
	APIVersion            string      `json:"apiVersion"`
	Kind                  Kind        `json:"kind"`
	ID                    string      `json:"id"`
	Type                  jobs.Type   `json:"type"`
	Status                jobs.Status `json:"status"`
	CreatedAt             time.Time   `json:"createdAt"`
	StartedAt             *time.Time  `json:"startedAt,omitempty"`
	FinishedAt            *time.Time  `json:"finishedAt,omitempty"`
	Actor                 Actor       `json:"actor"`
	RequestID             string      `json:"requestId"`
	IdempotencyKey        string      `json:"idempotencyKey"`
	RequestDigest         string      `json:"requestDigest"`
	PlanID                string      `json:"planID,omitempty"`
	ReportID              string      `json:"reportID,omitempty"`
	FailureCode           string      `json:"failureCode,omitempty"`
	CancellationRequested bool        `json:"cancellationRequested,omitempty"`
}

type Report struct {
	APIVersion string         `json:"apiVersion"`
	Kind       Kind           `json:"kind"`
	ID         string         `json:"id"`
	PlanID     string         `json:"planID"`
	JobID      string         `json:"jobID"`
	CreatedAt  time.Time      `json:"createdAt"`
	FinishedAt time.Time      `json:"finishedAt"`
	Outcome    ReportOutcome  `json:"outcome"`
	Targets    []TargetReport `json:"targets"`
}

type ReportOutcome string

const (
	ReportSucceeded ReportOutcome = "succeeded"
	ReportPartial   ReportOutcome = "partial"
	ReportFailed    ReportOutcome = "failed"
	ReportRejected  ReportOutcome = "rejected"
)

type TargetReport struct {
	Identity   manifest.InventoryTargetIdentity `json:"identity"`
	Outcome    ReportOutcome                    `json:"outcome"`
	Operations []OperationResult                `json:"operations"`
}

type OperationOutcome string

const (
	OutcomeCreated    OperationOutcome = "created"
	OutcomeUpdated    OperationOutcome = "updated"
	OutcomeDeleted    OperationOutcome = "deleted"
	OutcomeUnchanged  OperationOutcome = "unchanged"
	OutcomeSkipped    OperationOutcome = "skipped"
	OutcomeConflicted OperationOutcome = "conflicted"
	OutcomeRejected   OperationOutcome = "rejected"
	OutcomeFailed     OperationOutcome = "failed"
)

type OperationResult struct {
	ID           string               `json:"id"`
	ResourceKind manifest.Kind        `json:"resourceKind"`
	LogicalID    string               `json:"logicalID"`
	RemoteID     string               `json:"remoteID,omitempty"`
	Action       OperationAction      `json:"action"`
	Outcome      OperationOutcome     `json:"outcome"`
	Baseline     RemoteStateAssertion `json:"baseline"`
	ExpectedPost RemoteStateAssertion `json:"expectedPost"`
	ReasonCode   string               `json:"reasonCode,omitempty"`
}

// IdempotencyRecord binds a request to an actor/action/digest and a durable
// result. A synchronous mutation may have no job ID, but every terminal record
// still names its result.
type IdempotencyRecord struct {
	APIVersion    string             `json:"apiVersion"`
	Kind          Kind               `json:"kind"`
	ID            string             `json:"id"`
	Key           string             `json:"key"`
	Actor         Actor              `json:"actor"`
	Action        audit.Action       `json:"action"`
	RequestDigest string             `json:"requestDigest"`
	JobID         string             `json:"jobID,omitempty"`
	CreatedAt     time.Time          `json:"createdAt"`
	ExpiresAt     *time.Time         `json:"expiresAt,omitempty"`
	Outcome       IdempotencyOutcome `json:"outcome"`
	Result        *ResultReference   `json:"result,omitempty"`
}

type ResultKind string

const (
	ResultKindJob                ResultKind = "job"
	ResultKindPlan               ResultKind = "plan"
	ResultKindReport             ResultKind = "report"
	ResultKindCredentialMutation ResultKind = "credential-mutation"
)

type ResultReference struct {
	Kind ResultKind `json:"kind"`
	ID   string     `json:"id"`
}

type IdempotencyOutcome string

const (
	IdempotencyPending   IdempotencyOutcome = "pending"
	IdempotencySucceeded IdempotencyOutcome = "succeeded"
	IdempotencyFailed    IdempotencyOutcome = "failed"
)

type AuditEvent struct {
	APIVersion string        `json:"apiVersion"`
	Kind       Kind          `json:"kind"`
	ID         string        `json:"id"`
	OccurredAt time.Time     `json:"occurredAt"`
	Actor      *Actor        `json:"actor,omitempty"`
	RequestID  string        `json:"requestId"`
	Action     audit.Action  `json:"action"`
	Outcome    audit.Outcome `json:"outcome"`
	TargetID   string        `json:"targetID,omitempty"`
	PlanID     string        `json:"planID,omitempty"`
	JobID      string        `json:"jobID,omitempty"`
	ReasonCode string        `json:"reasonCode,omitempty"`
}

func (SourceSnapshot) documentKind() Kind     { return KindSourceSnapshot }
func (OwnershipInventory) documentKind() Kind { return KindOwnershipInventory }
func (PreMutationJournal) documentKind() Kind { return KindPreMutationJournal }
func (Plan) documentKind() Kind               { return KindPlan }
func (Job) documentKind() Kind                { return KindJob }
func (Report) documentKind() Kind             { return KindReport }
func (IdempotencyRecord) documentKind() Kind  { return KindIdempotency }
func (AuditEvent) documentKind() Kind         { return KindAuditEvent }
