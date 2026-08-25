package state

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

var (
	identifierPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	targetIdentifierPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)
	codePattern             = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	actionPattern           = regexp.MustCompile(`^[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+$`)
	jobIDPattern            = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	sha256Pattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	kubeNamePattern         = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

func (document SourceSnapshot) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindSourceSnapshot); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if err := validateTime("capturedAt", document.CapturedAt); err != nil {
		return err
	}
	return validateManifestSnapshot(document.Snapshot)
}

func (document OwnershipInventory) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindOwnershipInventory); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if err := validateID("stateID", document.StateID); err != nil {
		return err
	}
	if document.Generation == 0 {
		return invalidField("generation", "must be positive")
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if err := validateTime("updatedAt", document.UpdatedAt); err != nil {
		return err
	}
	if document.UpdatedAt.Before(document.CreatedAt) {
		return invalidField("updatedAt", "must not precede createdAt")
	}
	if err := validateFingerprint("fingerprint", document.Fingerprint, InventoryFingerprintDomain); err != nil {
		return err
	}
	if document.Targets == nil {
		return invalidField("targets", "must be an array, not null")
	}
	var previous string
	seen := make(map[string]struct{}, len(document.Targets))
	for index, target := range document.Targets {
		if err := validateInventoryTarget(target); err != nil {
			return fmt.Errorf("targets[%d]: %w", index, err)
		}
		if target.Identity.StateID != document.StateID {
			return invalidField(fmt.Sprintf("targets[%d].identity.stateID", index), "must match inventory stateID")
		}
		key := targetIdentityKey(target.Identity)
		if _, exists := seen[key]; exists {
			return invalidField("targets", "contains duplicate target identity %q", key)
		}
		if previous != "" && key < previous {
			return invalidField("targets", "must be sorted by exact target identity")
		}
		previous = key
		seen[key] = struct{}{}
	}
	return nil
}

func (document PreMutationJournal) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindPreMutationJournal); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if err := validateID("planID", document.PlanID); err != nil {
		return err
	}
	if err := validateID("operationID", document.OperationID); err != nil {
		return err
	}
	if err := validateTargetIdentity(document.Target); err != nil {
		return err
	}
	if err := validateManifestKind(document.ResourceKind); err != nil {
		return invalidField("resourceKind", "%v", err)
	}
	if err := validateManifestID("logicalID", document.LogicalID); err != nil {
		return err
	}
	if document.RemoteID != "" {
		if err := validateID("remoteID", document.RemoteID); err != nil {
			return err
		}
	}
	if err := validateOperationAction(document.Action); err != nil {
		return invalidField("action", "%v", err)
	}
	if !validMarker(document.Marker) {
		return invalidField("marker", "is unsupported")
	}
	if err := validateJournalMutationIdentity(document); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("baseline", document.Baseline); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("expectedPost", document.ExpectedPost); err != nil {
		return err
	}
	if err := validateJournalFingerprints(document.Action, document.Baseline, document.ExpectedPost); err != nil {
		return err
	}
	if !validLifecycle(document.Lifecycle) {
		return invalidField("lifecycle", "is unsupported")
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if err := validateTime("updatedAt", document.UpdatedAt); err != nil {
		return err
	}
	if document.UpdatedAt.Before(document.CreatedAt) {
		return invalidField("updatedAt", "must not precede createdAt")
	}
	return validateJournalTimes(document)
}

func (document Plan) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindPlan); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if err := validateID("stateID", document.StateID); err != nil {
		return err
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if err := validateActor("createdBy", document.CreatedBy); err != nil {
		return err
	}
	if err := validateText("toolVersion", document.ToolVersion, 128); err != nil {
		return err
	}
	if err := validateID("sourceSnapshotID", document.SourceSnapshotID); err != nil {
		return err
	}
	if document.Targets == nil || document.Operations == nil || document.Observations == nil {
		return invalid("targets, operations, and observations must be arrays, not null")
	}
	seenTargets := make(map[string]struct{}, len(document.Targets))
	previousTarget := ""
	for index, target := range document.Targets {
		if err := validatePlanTarget(target); err != nil {
			return fmt.Errorf("targets[%d]: %w", index, err)
		}
		if target.Identity.StateID != document.StateID {
			return invalidField(fmt.Sprintf("targets[%d].identity.stateID", index), "must match plan stateID")
		}
		key := targetIdentityKey(target.Identity)
		if _, exists := seenTargets[key]; exists {
			return invalidField("targets", "contains duplicate target identity %q", key)
		}
		if previousTarget != "" && key < previousTarget {
			return invalidField("targets", "must be sorted by exact target identity")
		}
		seenTargets[key] = struct{}{}
		previousTarget = key
	}
	seenOperations := make(map[string]struct{}, len(document.Operations))
	operationIDs := make(map[string]struct{}, len(document.Operations))
	operationIndexes := make(map[string]int, len(document.Operations))
	operationsByID := make(map[string]PlanOperation, len(document.Operations))
	operationKeys := make(map[string]struct{}, len(document.Operations))
	previousOperation := ""
	for index, operation := range document.Operations {
		if err := validatePlanOperation(operation, document.Targets); err != nil {
			return fmt.Errorf("operations[%d]: %w", index, err)
		}
		if _, exists := seenOperations[operation.ID]; exists {
			return invalidField("operations", "contains duplicate operation ID %q", operation.ID)
		}
		operationKey := targetIdentityKey(operation.Target) + "\x00" + string(operation.ResourceKind) + "\x00" + operation.LogicalID
		if _, exists := operationKeys[operationKey]; exists {
			return invalidField("operations", "contains duplicate target/kind/logical identity %q", operationKey)
		}
		if previousOperation != "" && operationSortKey(operation) < previousOperation {
			return invalidField("operations", "must be deterministically sorted by target, phase, kind, logical ID, action, and ID")
		}
		seenOperations[operation.ID] = struct{}{}
		operationIDs[operation.ID] = struct{}{}
		operationIndexes[operation.ID] = index
		operationsByID[operation.ID] = operation
		operationKeys[operationKey] = struct{}{}
		previousOperation = operationSortKey(operation)
	}
	for index, operation := range document.Operations {
		seenDependencies := make(map[string]struct{}, len(operation.Dependencies))
		previousDependency := ""
		for dependencyIndex, dependency := range operation.Dependencies {
			if _, exists := seenDependencies[dependency]; exists {
				return invalidField(fmt.Sprintf("operations[%d].dependencies", index), "contains duplicate dependency %q", dependency)
			}
			if _, exists := operationIDs[dependency]; !exists {
				return invalidField(fmt.Sprintf("operations[%d].dependencies[%d]", index, dependencyIndex), "references unknown operation %q", dependency)
			}
			if dependency == operation.ID {
				return invalidField(fmt.Sprintf("operations[%d].dependencies", index), "must not contain itself")
			}
			if dependencyOperation := operationsByID[dependency]; targetIdentityKey(dependencyOperation.Target) != targetIdentityKey(operation.Target) {
				return invalidField(fmt.Sprintf("operations[%d].dependencies[%d]", index, dependencyIndex), "must target the same exact target")
			}
			if operationIndexes[dependency] >= index {
				return invalidField(fmt.Sprintf("operations[%d].dependencies[%d]", index, dependencyIndex), "must reference an earlier operation")
			}
			if previousDependency != "" && dependency < previousDependency {
				return invalidField(fmt.Sprintf("operations[%d].dependencies", index), "must be sorted")
			}
			seenDependencies[dependency] = struct{}{}
			previousDependency = dependency
		}
	}
	visitState := make(map[string]uint8, len(operationsByID))
	var visit func(string) error
	visit = func(id string) error {
		switch visitState[id] {
		case 1:
			return invalidField("operations", "dependencies contain a cycle at %q", id)
		case 2:
			return nil
		}
		visitState[id] = 1
		for _, dependency := range operationsByID[id].Dependencies {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		visitState[id] = 2
		return nil
	}
	for id := range operationsByID {
		if err := visit(id); err != nil {
			return err
		}
	}
	seenObservations := make(map[string]struct{}, len(document.Observations))
	seenObservationIdentities := make(map[string]struct{}, len(document.Observations))
	previousObservation := ""
	for index, observation := range document.Observations {
		if err := validatePlanObservation(observation, document.Targets); err != nil {
			return fmt.Errorf("observations[%d]: %w", index, err)
		}
		if _, exists := seenObservations[observation.ID]; exists {
			return invalidField("observations", "contains duplicate observation ID %q", observation.ID)
		}
		identityKey := targetIdentityKey(observation.Target) + "\x00" + string(observation.ResourceKind) + "\x00" + observation.LogicalID
		if _, exists := seenObservationIdentities[identityKey]; exists {
			return invalidField("observations", "contains duplicate target/kind/logical identity %q", identityKey)
		}
		if _, exists := operationKeys[identityKey]; exists {
			return invalidField("observations", "identity %q also has an executable operation", identityKey)
		}
		key := observationSortKey(observation)
		if previousObservation != "" && key < previousObservation {
			return invalidField("observations", "must be deterministically sorted")
		}
		seenObservations[observation.ID] = struct{}{}
		seenObservationIdentities[identityKey] = struct{}{}
		previousObservation = key
	}
	return nil
}

func (document Job) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindJob); err != nil {
		return err
	}
	if !jobIDPattern.MatchString(document.ID) {
		return invalidField("id", "must match the durable job ID format")
	}
	if !document.Type.Valid() {
		return invalidField("type", "is unsupported")
	}
	if !document.Status.Valid() {
		return invalidField("status", "is unsupported")
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if err := validateActor("actor", document.Actor); err != nil {
		return err
	}
	if err := validateCode("requestID", document.RequestID); err != nil {
		return err
	}
	if err := jobs.ValidateIdempotencyKey(document.IdempotencyKey); err != nil {
		return invalidField("idempotencyKey", "%v", err)
	}
	if err := validateDigestString("requestDigest", document.RequestDigest); err != nil {
		return err
	}
	for field, value := range map[string]string{"planID": document.PlanID, "reportID": document.ReportID, "failureCode": document.FailureCode} {
		if value != "" {
			if err := validateCode(field, value); err != nil {
				return err
			}
		}
	}
	if err := validateJobTimes(document); err != nil {
		return err
	}
	if document.Status == jobs.StatusFailed || document.Status == jobs.StatusInterrupted {
		if document.FailureCode == "" {
			return invalidField("failureCode", "is required for failed or interrupted jobs")
		}
	} else if document.FailureCode != "" {
		return invalidField("failureCode", "must be empty for this status")
	}
	return nil
}

func (document Report) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindReport); err != nil {
		return err
	}
	for field, value := range map[string]string{"id": document.ID, "planID": document.PlanID, "jobID": document.JobID} {
		if err := validateID(field, value); err != nil {
			return err
		}
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if err := validateTime("finishedAt", document.FinishedAt); err != nil {
		return err
	}
	if document.FinishedAt.Before(document.CreatedAt) {
		return invalidField("finishedAt", "must not precede createdAt")
	}
	if !validReportOutcome(document.Outcome) {
		return invalidField("outcome", "is unsupported")
	}
	if document.Targets == nil {
		return invalidField("targets", "must be an array, not null")
	}
	seenTargets := make(map[string]struct{}, len(document.Targets))
	previousTarget := ""
	for index, target := range document.Targets {
		if err := validateTargetReport(target); err != nil {
			return fmt.Errorf("targets[%d]: %w", index, err)
		}
		key := targetIdentityKey(target.Identity)
		if _, exists := seenTargets[key]; exists {
			return invalidField("targets", "contains duplicate target identity %q", key)
		}
		if previousTarget != "" && key < previousTarget {
			return invalidField("targets", "must be sorted by exact target identity")
		}
		seenTargets[key] = struct{}{}
		previousTarget = key
	}
	return nil
}

func (document IdempotencyRecord) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindIdempotency); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if document.JobID != "" {
		if !jobIDPattern.MatchString(document.JobID) {
			return invalidField("jobID", "must match the durable job ID format")
		}
	}
	if err := jobs.ValidateIdempotencyKey(document.Key); err != nil {
		return invalidField("key", "%v", err)
	}
	if err := validateActor("actor", document.Actor); err != nil {
		return err
	}
	if err := validateAction("action", document.Action); err != nil {
		return err
	}
	if err := validateDigestString("requestDigest", document.RequestDigest); err != nil {
		return err
	}
	if err := validateTime("createdAt", document.CreatedAt); err != nil {
		return err
	}
	if document.ExpiresAt != nil {
		if err := validateTime("expiresAt", *document.ExpiresAt); err != nil {
			return err
		}
		if document.ExpiresAt.Before(document.CreatedAt) {
			return invalidField("expiresAt", "must not precede createdAt")
		}
	}
	if !validIdempotencyOutcome(document.Outcome) {
		return invalidField("outcome", "is unsupported")
	}
	switch document.Outcome {
	case IdempotencyPending:
		if document.JobID == "" {
			return invalidField("jobID", "is required while pending")
		}
		if document.Result != nil {
			return invalidField("result", "must be null while pending")
		}
	case IdempotencySucceeded, IdempotencyFailed:
		if document.Result == nil {
			return invalidField("result", "is required for terminal idempotency records")
		}
	}
	if document.Result != nil {
		if err := validateResultReference(*document.Result); err != nil {
			return err
		}
		if document.Result.Kind == ResultKindJob {
			if document.JobID == "" {
				return invalidField("jobID", "is required when result kind is job")
			}
			if document.Result.ID != document.JobID {
				return invalidField("result.id", "must match jobID when result kind is job")
			}
		}
	}
	return nil
}

func (document AuditEvent) Validate() error {
	if err := checkHeader(document.APIVersion, document.Kind, KindAuditEvent); err != nil {
		return err
	}
	if err := validateID("id", document.ID); err != nil {
		return err
	}
	if err := validateTime("occurredAt", document.OccurredAt); err != nil {
		return err
	}
	if document.Actor != nil {
		if err := validateActor("actor", *document.Actor); err != nil {
			return err
		}
	} else if document.Outcome == audit.OutcomeSucceeded {
		return invalidField("actor", "is required for successful events")
	}
	if err := validateCode("requestID", document.RequestID); err != nil {
		return err
	}
	if err := validateAction("action", document.Action); err != nil {
		return err
	}
	if !validAuditOutcome(document.Outcome) {
		return invalidField("outcome", "is unsupported")
	}
	for field, value := range map[string]string{"targetID": document.TargetID, "planID": document.PlanID, "jobID": document.JobID, "reasonCode": document.ReasonCode} {
		if value != "" {
			if err := validateCode(field, value); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateActor(field string, actor Actor) error {
	if err := validateSubject(field+".subject", actor.Subject); err != nil {
		return err
	}
	if actor.Roles == nil || len(actor.Roles) == 0 {
		return invalidField(field+".roles", "must contain at least one role")
	}
	previous := auth.Role("")
	seen := make(map[auth.Role]struct{}, len(actor.Roles))
	for _, role := range actor.Roles {
		if !knownRole(role) {
			return invalidField(field+".roles", "contains unsupported role %q", role)
		}
		if _, duplicate := seen[role]; duplicate {
			return invalidField(field+".roles", "contains duplicate role %q", role)
		}
		if previous != "" && role < previous {
			return invalidField(field+".roles", "must be sorted")
		}
		seen[role] = struct{}{}
		previous = role
	}
	if !knownAuthMethod(actor.Method) {
		return invalidField(field+".authMethod", "is unsupported")
	}
	return nil
}

func validateSecretReference(field string, value SecretReference) error {
	if !kubeNamePattern.MatchString(value.Namespace) {
		return invalidField(field+".namespace", "is not a valid Kubernetes namespace")
	}
	if !validSecretName(value.Name) {
		return invalidField(field+".name", "is not a valid Kubernetes Secret name")
	}
	if err := validateID(field+".resourceVersion", value.ResourceVersion); err != nil {
		return err
	}
	if value.UID != "" {
		if err := validateID(field+".uid", value.UID); err != nil {
			return err
		}
	}
	if value.Generation < 0 {
		return invalidField(field+".generation", "must not be negative")
	}
	return nil
}

func validSecretName(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !kubeNamePattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validateCredentialMetadata(field string, value CredentialMetadata) error {
	if err := validateSecretReference(field+".secretReference", value.SecretReference); err != nil {
		return err
	}
	if err := validateTime(field+".rotatedAt", value.RotatedAt); err != nil {
		return err
	}
	if err := validateSubject(field+".rotatedBy", value.RotatedBy); err != nil {
		return err
	}
	if value.CertificateSHA256 != "" {
		if err := validateDigestString(field+".certificateSHA256", value.CertificateSHA256); err != nil {
			return err
		}
	}
	if value.CertificateNotAfter != nil {
		if err := validateTime(field+".certificateNotAfter", *value.CertificateNotAfter); err != nil {
			return err
		}
	}
	return nil
}

func validateInventoryTarget(value InventoryTarget) error {
	if err := validateTargetIdentity(value.Identity); err != nil {
		return err
	}
	if value.Generation == 0 {
		return invalidField("generation", "must be positive")
	}
	if err := validateFingerprint("fingerprint", value.Fingerprint, InventoryFingerprintDomain); err != nil {
		return err
	}
	if value.Entries == nil {
		return invalidField("entries", "must be an array, not null")
	}
	seenLogical := make(map[string]struct{}, len(value.Entries))
	seenRemote := make(map[string]struct{}, len(value.Entries))
	previous := ""
	for index, entry := range value.Entries {
		if err := validateInventoryEntry(entry); err != nil {
			return fmt.Errorf("entries[%d]: %w", index, err)
		}
		logicalKey := string(entry.Kind) + "/" + entry.LogicalID
		if _, exists := seenLogical[logicalKey]; exists {
			return invalidField("entries", "contains duplicate kind/logical ID %q", logicalKey)
		}
		remoteKey := string(entry.Kind) + "/" + entry.RemoteID
		if _, exists := seenRemote[remoteKey]; exists {
			return invalidField("entries", "contains duplicate kind/remote ID %q", remoteKey)
		}
		key := inventoryEntrySortKey(entry)
		if previous != "" && key < previous {
			return invalidField("entries", "must be deterministically sorted")
		}
		seenLogical[logicalKey] = struct{}{}
		seenRemote[remoteKey] = struct{}{}
		previous = key
	}
	return nil
}

func validateInventoryEntry(value InventoryEntry) error {
	if err := validateManifestKind(value.Kind); err != nil {
		return invalidField("kind", "%v", err)
	}
	if err := validateManifestID("logicalID", value.LogicalID); err != nil {
		return err
	}
	if err := validateID("remoteID", value.RemoteID); err != nil {
		return err
	}
	if !validMarker(value.Marker) {
		return invalidField("marker", "is unsupported")
	}
	if !validMarkerForKind(value.Kind, value.Marker) {
		return invalidField("marker", "is incompatible with resource kind")
	}
	return validateFingerprint("lastDesiredFingerprint", value.LastDesiredFingerprint, DesiredFingerprintDomain)
}

func validatePlanTarget(value PlanTarget) error {
	if err := validateTargetIdentity(value.Identity); err != nil {
		return err
	}
	if !validSemVer(value.KibanaVersion) {
		return invalidField("kibanaVersion", "must be an exact semantic version")
	}
	if err := validateSourceProvenance("source", value.Source); err != nil {
		return err
	}
	if value.InventoryGeneration == 0 {
		return invalidField("inventoryGeneration", "must be positive")
	}
	if err := validateFingerprint("inventoryFingerprint", value.InventoryFingerprint, InventoryFingerprintDomain); err != nil {
		return err
	}
	return validateCredentialMetadata("credentialMetadata", value.CredentialMetadata)
}

func validatePlanOperation(value PlanOperation, targets []PlanTarget) error {
	if err := validateID("id", value.ID); err != nil {
		return err
	}
	var declaredTarget *PlanTarget
	for index := range targets {
		if targetIdentityKey(targets[index].Identity) == targetIdentityKey(value.Target) {
			declaredTarget = &targets[index]
			break
		}
	}
	if declaredTarget == nil {
		return invalidField("target", "is not declared by the plan")
	}
	if value.Phase < 0 {
		return invalidField("phase", "must not be negative")
	}
	if err := validateManifestKind(value.ResourceKind); err != nil {
		return invalidField("resourceKind", "%v", err)
	}
	if err := validateManifestID("logicalID", value.LogicalID); err != nil {
		return err
	}
	if value.RemoteID != "" {
		if err := validateID("remoteID", value.RemoteID); err != nil {
			return err
		}
	}
	if err := validateOperationAction(value.Action); err != nil {
		return invalidField("action", "%v", err)
	}
	switch value.Action {
	case ActionCreate:
		if value.RemoteID != "" {
			return invalidField("remoteID", "must be empty for create operations")
		}
	case ActionUpdate, ActionDelete:
		if value.RemoteID == "" {
			return invalidField("remoteID", "is required for update and delete operations")
		}
	}
	if value.Dependencies == nil {
		return invalidField("dependencies", "must be an array, not null")
	}
	if !validMarker(value.Marker) {
		return invalidField("marker", "is unsupported")
	}
	if err := validateOptionalFingerprint("desiredFingerprint", value.DesiredFingerprint, DesiredFingerprintDomain); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("baseline", value.Baseline); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("expectedPost", value.ExpectedPost); err != nil {
		return err
	}
	if err := validateOperationFingerprints(value.Action, value.DesiredFingerprint, value.Baseline, value.ExpectedPost); err != nil {
		return err
	}
	if value.Action == ActionUpdate && !validMarkerForKind(value.ResourceKind, value.Marker) {
		return invalidField("marker", "is incompatible with resource kind for update operations")
	}
	if value.Action == ActionDelete {
		if value.Marker == MarkerNone {
			return invalidField("marker", "must identify an ownership marker for delete operations")
		}
		if !validDeleteMarker(value.ResourceKind, value.Marker) {
			return invalidField("marker", "is not compatible with the prunable resource kind")
		}
		if value.InventoryGeneration == 0 || value.InventoryGeneration != declaredTarget.InventoryGeneration {
			return invalidField("inventoryGeneration", "must exactly equal the declared plan target generation for deletes")
		}
	}
	return nil
}

func validatePlanObservation(value PlanObservation, targets []PlanTarget) error {
	if err := validateID("id", value.ID); err != nil {
		return err
	}
	var declaredTarget *PlanTarget
	for index := range targets {
		if targetIdentityKey(targets[index].Identity) == targetIdentityKey(value.Target) {
			declaredTarget = &targets[index]
			break
		}
	}
	if declaredTarget == nil {
		return invalidField("target", "is not declared by the plan")
	}
	if err := validateManifestKind(value.ResourceKind); err != nil {
		return invalidField("resourceKind", "%v", err)
	}
	if value.LogicalID != "" {
		if err := validateManifestID("logicalID", value.LogicalID); err != nil {
			return err
		}
	}
	if value.RemoteID != "" {
		if err := validateID("remoteID", value.RemoteID); err != nil {
			return err
		}
	}
	if !validMarker(value.Marker) {
		return invalidField("marker", "is unsupported")
	}
	if err := validateOptionalFingerprint("desiredFingerprint", value.DesiredFingerprint, DesiredFingerprintDomain); err != nil {
		return err
	}
	if value.LiveState != nil {
		if err := validateRemoteStateAssertion("liveState", *value.LiveState); err != nil {
			return err
		}
	}
	if value.InventoryGeneration == 0 || value.InventoryGeneration != declaredTarget.InventoryGeneration {
		return invalidField("inventoryGeneration", "must exactly equal the declared plan target generation")
	}
	if !validObservationSeverity(value.Severity) {
		return invalidField("severity", "is unsupported")
	}
	return validateCode("code", value.Code)
}

func validateSourceProvenance(field string, value SourceProvenance) error {
	if err := validateID(field+".resourceSetID", value.ResourceSetID); err != nil {
		return err
	}
	if value.Revision != "" {
		if err := validateText(field+".revision", value.Revision, 1024); err != nil {
			return err
		}
	}
	if err := validateFingerprint(field+".resourceSetDesiredFingerprint", value.ResourceSetDesiredFingerprint, DesiredFingerprintDomain); err != nil {
		return err
	}
	if err := validateFingerprint(field+".targetDesiredFingerprint", value.TargetDesiredFingerprint, DesiredFingerprintDomain); err != nil {
		return err
	}
	return validateFingerprint(field+".targetConfigFingerprint", value.TargetConfigFingerprint, TargetConfigFingerprintDomain)
}

func validateTargetIdentity(value manifest.InventoryTargetIdentity) error {
	for field, text := range map[string]string{"stateID": value.StateID, "name": value.Name, "space": value.Space} {
		if len(text) == 0 || len(text) > maxIDLength || !targetIdentifierPattern.MatchString(text) {
			return invalidField("target."+field, "must be a bounded target identifier")
		}
	}
	if len(value.URL) > 2048 {
		return invalidField("target.url", "is too long")
	}
	parsed, err := url.Parse(value.URL)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery || strings.HasSuffix(parsed.Host, ":") {
		return invalidField("target.url", "must be an absolute URL without credentials, query, or fragment")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "https" && !(scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return invalidField("target.url", "must use HTTPS except for loopback development")
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return invalidField("target.url", "contains an invalid port")
		}
	}
	canonical := *parsed
	canonical.Scheme = scheme
	hostname := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if strings.Contains(hostname, ":") {
		hostname = "[" + hostname + "]"
	}
	canonical.Host = hostname
	if port != "" {
		canonical.Host += ":" + port
	}
	if canonical.Path == "/" {
		canonical.Path = ""
		canonical.RawPath = ""
	}
	if canonical.String() != value.URL {
		return invalidField("target.url", "must use normalized target URL form")
	}
	return nil
}

func isLoopbackHost(value string) bool {
	if strings.EqualFold(value, "localhost") {
		return true
	}
	parsed := net.ParseIP(value)
	return parsed != nil && parsed.IsLoopback()
}

func validateManifestSnapshot(value manifest.SourceSnapshot) error {
	if value.APIVersion != manifest.SourceSnapshotAPIVersion {
		return invalidField("snapshot.apiVersion", "is unsupported")
	}
	if value.DigestDomain != manifest.DesiredDigestDomain || value.DigestVersion != manifest.DesiredDigestVersion {
		return invalidField("snapshot.digest", "uses an unsupported digest domain or version")
	}
	if value.ResourceSets == nil || value.Targets == nil {
		return invalid("snapshot.resourceSets and snapshot.targets must be arrays, not null")
	}
	seenSets := make(map[string]struct{}, len(value.ResourceSets))
	resourcesBySet := make(map[string]map[string]manifest.ResourceSnapshot, len(value.ResourceSets))
	filesBySet := make(map[string]map[string]struct{}, len(value.ResourceSets))
	revisionsBySet := make(map[string]string, len(value.ResourceSets))
	previousSet := ""
	for index, set := range value.ResourceSets {
		if err := validateID("snapshot.resourceSets.id", set.ID); err != nil {
			return fmt.Errorf("resourceSets[%d]: %w", index, err)
		}
		if _, exists := seenSets[set.ID]; exists {
			return invalidField("snapshot.resourceSets", "contains duplicate resource set %q", set.ID)
		}
		if previousSet != "" && set.ID < previousSet {
			return invalidField("snapshot.resourceSets", "must be sorted by ID")
		}
		previousSet = set.ID
		seenSets[set.ID] = struct{}{}
		if err := validateOptionalRevision("snapshot.resourceSets.revision", set.Revision); err != nil {
			return err
		}
		if err := validateDigest("snapshot.resourceSets.desiredDigest", set.DesiredDigest); err != nil {
			return err
		}
		if set.Files == nil {
			return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].files", index), "must be an array, not null")
		}
		if err := validateRawFiles(set.Files); err != nil {
			return fmt.Errorf("resourceSets[%d].files: %w", index, err)
		}
		files := make(map[string]struct{}, len(set.Files))
		for _, file := range set.Files {
			files[file.RelativePath] = struct{}{}
		}
		filesBySet[set.ID] = files
		if set.Revision != nil {
			revisionsBySet[set.ID] = set.Revision.Value
			if _, collision := files[set.Revision.RelativePath]; collision {
				return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].revision", index), "revision file must not also be a source file")
			}
		}
		if set.Resources == nil {
			return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].resources", index), "must be an array, not null")
		}
		seenResources := make(map[string]manifest.ResourceSnapshot, len(set.Resources))
		resourcesBySet[set.ID] = seenResources
		previousResource := ""
		for resourceIndex, resource := range set.Resources {
			if err := validateResourceIdentity(resource.Resource); err != nil {
				return fmt.Errorf("resourceSets[%d].resources[%d]: %w", index, resourceIndex, err)
			}
			if err := validateLocation(resource.Source, set.ID); err != nil {
				return fmt.Errorf("resourceSets[%d].resources[%d].source: %w", index, resourceIndex, err)
			}
			if err := validateDigest("resource desiredDigest", resource.DesiredDigest); err != nil {
				return err
			}
			key := manifestIdentityKey(resource.Resource)
			if _, exists := seenResources[key]; exists {
				return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].resources", index), "contains duplicate resource %q", key)
			}
			if previousResource != "" && key < previousResource {
				return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].resources", index), "must be sorted")
			}
			if _, exists := files[resource.Source.RelativePath]; !exists {
				return invalidField(fmt.Sprintf("snapshot.resourceSets[%d].resources[%d].source.relativePath", index, resourceIndex), "is not present in its source files")
			}
			seenResources[key] = resource
			previousResource = key
		}
	}
	seenTargets := make(map[string]struct{}, len(value.Targets))
	previousTarget := ""
	for index, target := range value.Targets {
		if err := validateTargetIdentity(target.Identity); err != nil {
			return fmt.Errorf("snapshot.targets[%d]: %w", index, err)
		}
		if _, exists := seenSets[target.ResourceSetID]; !exists {
			return invalidField(fmt.Sprintf("snapshot.targets[%d].resourceSetID", index), "references an unknown resource set")
		}
		if target.ResourceSetID != "" {
			if err := validateID("snapshot.targets.resourceSetID", target.ResourceSetID); err != nil {
				return err
			}
		}
		if err := validateOptionalRevisionText("snapshot.targets.revision", target.Revision); err != nil {
			return err
		}
		if target.Revision != revisionsBySet[target.ResourceSetID] {
			return invalidField(fmt.Sprintf("snapshot.targets[%d].revision", index), "must match its resource-set revision")
		}
		if err := validateDigest("snapshot.targets.desiredDigest", target.DesiredDigest); err != nil {
			return err
		}
		if target.Labels == nil {
			return invalidField(fmt.Sprintf("snapshot.targets[%d].labels", index), "must be an array, not null")
		}
		if err := validateLabels(target.Labels); err != nil {
			return fmt.Errorf("snapshot.targets[%d].labels: %w", index, err)
		}
		if target.Resources == nil {
			return invalidField(fmt.Sprintf("snapshot.targets[%d].resources", index), "must be an array, not null")
		}
		previousResource := ""
		for resourceIndex, resource := range target.Resources {
			if err := validateResourceIdentity(resource.Resource); err != nil {
				return fmt.Errorf("snapshot.targets[%d].resources[%d]: %w", index, resourceIndex, err)
			}
			if err := validateLocation(resource.Source, target.ResourceSetID); err != nil {
				return fmt.Errorf("snapshot.targets[%d].resources[%d].source: %w", index, resourceIndex, err)
			}
			if err := validateDigest("target resource desiredDigest", resource.DesiredDigest); err != nil {
				return err
			}
			key := manifestIdentityKey(resource.Resource)
			sourceResource, exists := resourcesBySet[target.ResourceSetID][key]
			if !exists {
				return invalidField(fmt.Sprintf("snapshot.targets[%d].resources[%d]", index, resourceIndex), "is not present in its resource set")
			}
			if sourceResource.Source != resource.Source || sourceResource.DesiredDigest != resource.DesiredDigest {
				return invalidField(fmt.Sprintf("snapshot.targets[%d].resources[%d]", index, resourceIndex), "does not match its resource-set snapshot")
			}
			if _, exists := filesBySet[target.ResourceSetID][resource.Source.RelativePath]; !exists {
				return invalidField(fmt.Sprintf("snapshot.targets[%d].resources[%d].source.relativePath", index, resourceIndex), "is not present in its source files")
			}
			if previousResource != "" && key <= previousResource {
				return invalidField(fmt.Sprintf("snapshot.targets[%d].resources", index), "must be unique and sorted")
			}
			previousResource = key
		}
		key := targetIdentityKey(target.Identity)
		if _, exists := seenTargets[key]; exists {
			return invalidField("snapshot.targets", "contains duplicate target identity %q", key)
		}
		if previousTarget != "" && key < previousTarget {
			return invalidField("snapshot.targets", "must be sorted by exact target identity")
		}
		previousTarget = key
		seenTargets[key] = struct{}{}
	}
	return nil
}

func validateRawFiles(values []source.RawFileDigest) error {
	if len(values) > source.DefaultMaxFiles {
		return invalid("source file count exceeds the configured bound")
	}
	seen := make(map[string]struct{}, len(values))
	previous := ""
	var totalBytes int64
	for index, value := range values {
		if err := validateRelativePath("relativePath", value.RelativePath); err != nil {
			return fmt.Errorf("files[%d]: %w", index, err)
		}
		if err := validateDigestString("sha256", value.SHA256); err != nil {
			return fmt.Errorf("files[%d]: %w", index, err)
		}
		if value.Bytes < 0 || value.Bytes > source.DefaultMaxFileBytes {
			return invalidField(fmt.Sprintf("files[%d].bytes", index), "exceeds the configured file-size bound")
		}
		if value.Bytes > source.DefaultMaxTotalBytes-totalBytes {
			return invalidField("files", "exceeds the configured total source-size bound")
		}
		totalBytes += value.Bytes
		if _, exists := seen[value.RelativePath]; exists {
			return invalidField("files", "contains duplicate path %q", value.RelativePath)
		}
		if previous != "" && value.RelativePath < previous {
			return invalidField("files", "must be sorted by relativePath")
		}
		seen[value.RelativePath] = struct{}{}
		previous = value.RelativePath
	}
	return nil
}
