package state

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/jobs"
	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
	"github.com/TommyAGK/elastic-maintenance/internal/source"
)

func validateID(field, value string) error {
	if len(value) == 0 || len(value) > maxIDLength || !identifierPattern.MatchString(value) {
		return invalidField(field, "must be a bounded safe identifier")
	}
	return nil
}

func validateManifestID(field, value string) error {
	if len(value) == 0 || len(value) > maxIDLength {
		return invalidField(field, "must be a bounded manifest ID")
	}
	for index, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '.' && character != '_' && character != '-' {
			return invalidField(field, "contains an invalid character at byte %d", index)
		}
	}
	if value[0] == '.' || value[0] == '_' || value[0] == '-' || value[len(value)-1] == '.' || value[len(value)-1] == '_' || value[len(value)-1] == '-' {
		return invalidField(field, "must start and end with a lowercase letter or digit")
	}
	return nil
}

func validateCode(field, value string) error {
	if len(value) == 0 || len(value) > maxIDLength || !codePattern.MatchString(value) {
		return invalidField(field, "must be a bounded safe code")
	}
	return nil
}

func validateText(field, value string, limit int) error {
	if len(value) == 0 || len(value) > limit || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return invalidField(field, "must be bounded printable UTF-8 text")
	}
	return nil
}

func validateSubject(field, value string) error {
	if value != strings.TrimSpace(value) {
		return invalidField(field, "must not have leading or trailing whitespace")
	}
	return validateText(field, value, maxTextLength)
}

func validateTime(field string, value time.Time) error {
	if value.IsZero() {
		return invalidField(field, "is required")
	}
	// Persisted timestamps are canonical UTC RFC3339 values. This also rejects
	// local/fixed offsets that could otherwise produce multiple encodings.
	if value.Location() != time.UTC {
		return invalidField(field, "must use UTC")
	}
	return nil
}

func validateDigest(field string, value manifest.DesiredDigest) error {
	if value.Algorithm != "sha256" || value.Version != manifest.DesiredDigestVersion {
		return invalidField(field, "must use sha256 digest version %q", manifest.DesiredDigestVersion)
	}
	return validateDigestString(field+".value", value.Value)
}

func validateFingerprint(field string, value Fingerprint, expectedDomain string) error {
	if value.Domain != expectedDomain {
		return invalidField(field+".domain", "must be %q", expectedDomain)
	}
	if value.Algorithm != "sha256" || value.Version != FingerprintVersion {
		return invalidField(field, "must use sha256 fingerprint version %q", FingerprintVersion)
	}
	return validateDigestString(field+".value", value.Value)
}

func validateOptionalFingerprint(field string, value *Fingerprint, expectedDomain string) error {
	if value == nil {
		return nil
	}
	return validateFingerprint(field, *value, expectedDomain)
}

func validateRemoteStateAssertion(field string, value RemoteStateAssertion) error {
	switch value.Presence {
	case PresenceAbsent:
		if value.Fingerprint != nil {
			return invalidField(field+".fingerprint", "must be absent when presence is absent")
		}
	case PresencePresent:
		if value.Fingerprint == nil {
			return invalidField(field+".fingerprint", "is required when presence is present")
		}
		return validateFingerprint(field+".fingerprint", *value.Fingerprint, KibanaLiveFingerprintDomain)
	default:
		return invalidField(field+".presence", "must be absent or present")
	}
	return nil
}

func validateDigestString(field, value string) error {
	if !sha256Pattern.MatchString(value) {
		return invalidField(field, "must be a lowercase SHA-256 digest")
	}
	return nil
}

func validSemVer(value string) bool {
	if value == "" || strings.Count(value, "+") > 1 {
		return false
	}
	coreAndPrerelease := strings.SplitN(value, "+", 2)
	core := coreAndPrerelease[0]
	if len(coreAndPrerelease) == 2 && !validSemVerIdentifiers(coreAndPrerelease[1], false) {
		return false
	}
	majorMinorPatch := strings.SplitN(core, "-", 2)
	if len(strings.Split(majorMinorPatch[0], ".")) != 3 {
		return false
	}
	for _, number := range strings.Split(majorMinorPatch[0], ".") {
		if number == "" || (len(number) > 1 && number[0] == '0') {
			return false
		}
		for _, character := range number {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	if len(majorMinorPatch) == 2 && !validSemVerIdentifiers(majorMinorPatch[1], true) {
		return false
	}
	return true
}

func validSemVerIdentifiers(value string, prerelease bool) bool {
	if value == "" {
		return false
	}
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" || (prerelease && allASCIIDigits(identifier) && len(identifier) > 1 && identifier[0] == '0') {
			return false
		}
		for _, character := range identifier {
			if !(character >= '0' && character <= '9') && !(character >= 'A' && character <= 'Z') && !(character >= 'a' && character <= 'z') && character != '-' {
				return false
			}
		}
	}
	return true
}

func allASCIIDigits(value string) bool {
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validateManifestKind(value manifest.Kind) error {
	switch value {
	case manifest.KindIntegrationPackage, manifest.KindAgentPolicy, manifest.KindPackagePolicy, manifest.KindDetectionRule, manifest.KindPrebuiltRules:
		return nil
	default:
		return fmt.Errorf("unsupported manifest kind %q", value)
	}
}

func validateResourceIdentity(value manifest.ResourceIdentity) error {
	if err := validateManifestKind(value.Kind); err != nil {
		return invalidField("resource.kind", "%v", err)
	}
	return validateManifestID("resource.id", value.ID)
}

func validateLocation(value source.Location, expectedSet string) error {
	if value.ResourceSetID != expectedSet {
		return invalidField("resourceSetID", "does not match its resource set")
	}
	if value.Document < 0 || value.Line < 0 || value.Column < 0 {
		return invalid("source location coordinates must not be negative")
	}
	return validateRelativePath("relativePath", value.RelativePath)
}

func validateRelativePath(field, value string) error {
	if value == "" || len(value) > 1024 || !utf8.ValidString(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 || strings.HasPrefix(value, "/") || path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") || strings.Contains(value, "\\") {
		return invalidField(field, "must be a clean relative path")
	}
	return nil
}

func validateOptionalRevision(field string, value *manifest.RevisionProvenance) error {
	if value == nil {
		return nil
	}
	if err := validateRelativePath(field+".relativePath", value.RelativePath); err != nil {
		return err
	}
	return validateText(field+".value", value.Value, 1024)
}

func validateOptionalRevisionText(field, value string) error {
	if value == "" {
		return nil
	}
	return validateText(field, value, 1024)
}

func validateLabels(values []manifest.Label) error {
	if len(values) > 64 {
		return invalidField("labels", "contains too many entries")
	}
	labelKeyPattern := regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,62}$`)
	labelValuePattern := regexp.MustCompile(`^(?:[A-Za-z0-9](?:[-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$`)
	seen := make(map[string]struct{}, len(values))
	previous := ""
	for _, value := range values {
		if !labelKeyPattern.MatchString(value.Key) {
			return invalidField("label.key", "is invalid")
		}
		if !labelValuePattern.MatchString(value.Value) {
			return invalidField("label.value", "is invalid")
		}
		if _, exists := seen[value.Key]; exists {
			return invalidField("labels", "contains duplicate key %q", value.Key)
		}
		if previous != "" && value.Key < previous {
			return invalidField("labels", "must be sorted by key")
		}
		seen[value.Key] = struct{}{}
		previous = value.Key
	}
	return nil
}

func targetIdentityKey(value manifest.InventoryTargetIdentity) string {
	return value.StateID + "\x00" + value.Name + "\x00" + value.URL + "\x00" + value.Space
}

func manifestIdentityKey(value manifest.ResourceIdentity) string {
	return string(value.Kind) + "\x00" + value.ID
}

func inventoryEntrySortKey(value InventoryEntry) string {
	return string(value.Kind) + "\x00" + value.LogicalID + "\x00" + value.RemoteID
}

func operationSortKey(value PlanOperation) string {
	return fmt.Sprintf("%s\x00%020d\x00%s\x00%s\x00%s\x00%s", targetIdentityKey(value.Target), value.Phase, value.ResourceKind, value.LogicalID, value.Action, value.ID)
}

func observationSortKey(value PlanObservation) string {
	return targetIdentityKey(value.Target) + "\x00" + string(value.ResourceKind) + "\x00" + value.LogicalID + "\x00" + value.Code + "\x00" + value.ID
}

func validateOperationAction(value OperationAction) error {
	switch value {
	case ActionCreate, ActionUpdate, ActionDelete:
		return nil
	default:
		return fmt.Errorf("unsupported operation action %q", value)
	}
}

func validateOperationFingerprints(action OperationAction, desired *Fingerprint, baseline, expected RemoteStateAssertion) error {
	switch action {
	case ActionCreate:
		if desired == nil || baseline.Presence != PresenceAbsent || expected.Presence != PresencePresent {
			return invalid("create operation requires desired fingerprint, absent baseline, and present expected-post state")
		}
	case ActionUpdate:
		if desired == nil || baseline.Presence != PresencePresent || expected.Presence != PresencePresent {
			return invalid("update operation requires desired fingerprint and present baseline and expected-post state")
		}
	case ActionDelete:
		if desired != nil || baseline.Presence != PresencePresent || expected.Presence != PresenceAbsent {
			return invalid("delete operation requires present baseline, absent expected-post state, and no desired fingerprint")
		}
	}
	return nil
}

func validateJournalMutationIdentity(value PreMutationJournal) error {
	switch value.Action {
	case ActionCreate:
		if requiresJournalRemoteID(value.Lifecycle) && value.RemoteID == "" {
			return invalidField("remoteID", "is required after mutation succeeds")
		}
	case ActionUpdate, ActionDelete:
		if value.RemoteID == "" {
			return invalidField("remoteID", "is required for update and delete journals")
		}
		if value.InventoryGeneration == 0 {
			return invalidField("inventoryGeneration", "must be positive for update and delete journals")
		}
		if !validMarkerForKind(value.ResourceKind, value.Marker) {
			return invalidField("marker", "is incompatible with resource kind")
		}
		if value.Action == ActionDelete && !validDeleteMarker(value.ResourceKind, value.Marker) {
			return invalidField("marker", "is not compatible with the prunable resource kind")
		}
	}
	return nil
}

func requiresJournalRemoteID(lifecycle JournalLifecycle) bool {
	switch lifecycle {
	case JournalMutationSucceeded, JournalPostVerified, JournalCommitted:
		return true
	default:
		return false
	}
}

func validateJournalFingerprints(action OperationAction, baseline, expected RemoteStateAssertion) error {
	switch action {
	case ActionCreate:
		if baseline.Presence != PresenceAbsent || expected.Presence != PresencePresent {
			return invalid("create journal requires absent baseline and present expected-post state")
		}
	case ActionUpdate:
		if baseline.Presence != PresencePresent || expected.Presence != PresencePresent {
			return invalid("update journal requires present baseline and expected-post state")
		}
	case ActionDelete:
		if baseline.Presence != PresencePresent || expected.Presence != PresenceAbsent {
			return invalid("delete journal requires present baseline and absent expected-post state")
		}
	}
	return nil
}

func validateOperationResultStates(action OperationAction, baseline, expected RemoteStateAssertion) error {
	switch action {
	case ActionCreate:
		if baseline.Presence != PresenceAbsent || expected.Presence != PresencePresent {
			return invalid("create result requires absent baseline and present expected-post state")
		}
	case ActionUpdate:
		if baseline.Presence != PresencePresent || expected.Presence != PresencePresent {
			return invalid("update result requires present baseline and expected-post state")
		}
	case ActionDelete:
		if baseline.Presence != PresencePresent || expected.Presence != PresenceAbsent {
			return invalid("delete result requires present baseline and absent expected-post state")
		}
	}
	return nil
}

func validateJournalTimes(value PreMutationJournal) error {
	values := []struct {
		field string
		value *time.Time
	}{
		{"mutationStartedAt", value.MutationStartedAt}, {"mutationFinishedAt", value.MutationFinishedAt}, {"postVerifiedAt", value.PostVerifiedAt}, {"committedAt", value.CommittedAt},
	}
	var previous = value.CreatedAt
	var latest time.Time
	for _, item := range values {
		if item.value == nil {
			continue
		}
		if err := validateTime(item.field, *item.value); err != nil {
			return err
		}
		if item.value.Before(previous) {
			return invalidField(item.field, "must not precede the prior lifecycle time")
		}
		previous = *item.value
		latest = *item.value
	}
	if value.UpdatedAt.Before(latest) {
		return invalidField("updatedAt", "must not precede the latest lifecycle time")
	}
	if value.MutationFinishedAt != nil && value.MutationStartedAt == nil {
		return invalidField("mutationFinishedAt", "requires mutationStartedAt")
	}
	if value.PostVerifiedAt != nil && value.MutationFinishedAt == nil {
		return invalidField("postVerifiedAt", "requires mutationFinishedAt")
	}
	switch value.Lifecycle {
	case JournalPrepared:
		if value.MutationStartedAt != nil || value.MutationFinishedAt != nil || value.PostVerifiedAt != nil || value.CommittedAt != nil {
			return invalidField("lifecycle", "prepared journals must not contain mutation lifecycle times")
		}
	case JournalMutating:
		if value.MutationStartedAt == nil || value.MutationFinishedAt != nil || value.PostVerifiedAt != nil || value.CommittedAt != nil {
			return invalidField("lifecycle", "mutating journals require only mutationStartedAt")
		}
	case JournalMutationSucceeded:
		if value.MutationStartedAt == nil || value.MutationFinishedAt == nil || value.PostVerifiedAt != nil || value.CommittedAt != nil {
			return invalidField("lifecycle", "mutation-succeeded journals require start and finish times only")
		}
	case JournalPostVerified:
		if value.MutationStartedAt == nil || value.MutationFinishedAt == nil || value.PostVerifiedAt == nil || value.CommittedAt != nil {
			return invalidField("lifecycle", "post-verified journals require mutation and verification times")
		}
	case JournalCommitted:
		if value.MutationStartedAt == nil || value.MutationFinishedAt == nil || value.PostVerifiedAt == nil || value.CommittedAt == nil {
			return invalidField("lifecycle", "committed journals require the complete lifecycle")
		}
	case JournalRecoveryRequired, JournalAbandoned:
		if value.CommittedAt != nil {
			return invalidField("lifecycle", "recovery or abandoned journals must not be committed")
		}
	}
	return nil
}

func validLifecycle(value JournalLifecycle) bool {
	switch value {
	case JournalPrepared, JournalMutating, JournalMutationSucceeded, JournalPostVerified, JournalCommitted, JournalRecoveryRequired, JournalAbandoned:
		return true
	default:
		return false
	}
}

func validateJobTimes(value Job) error {
	if value.Status == jobs.StatusQueued && (value.StartedAt != nil || value.FinishedAt != nil) {
		return invalid("queued job must not have startedAt or finishedAt")
	}
	if value.Status == jobs.StatusRunning && (value.StartedAt == nil || value.FinishedAt != nil) {
		return invalid("running job requires startedAt and must not have finishedAt")
	}
	terminal := value.Status == jobs.StatusSucceeded || value.Status == jobs.StatusFailed || value.Status == jobs.StatusCanceled || value.Status == jobs.StatusInterrupted
	if terminal && value.FinishedAt == nil {
		return invalid("terminal job requires finishedAt")
	}
	for field, timestamp := range map[string]*time.Time{"startedAt": value.StartedAt, "finishedAt": value.FinishedAt} {
		if timestamp != nil {
			if err := validateTime(field, *timestamp); err != nil {
				return err
			}
			if timestamp.Before(value.CreatedAt) {
				return invalidField(field, "must not precede createdAt")
			}
		}
	}
	if value.StartedAt != nil && value.FinishedAt != nil && value.FinishedAt.Before(*value.StartedAt) {
		return invalid("finishedAt must not precede startedAt")
	}
	return nil
}

func validateTargetReport(value TargetReport) error {
	if err := validateTargetIdentity(value.Identity); err != nil {
		return err
	}
	if !validReportOutcome(value.Outcome) {
		return invalidField("outcome", "is unsupported")
	}
	if value.Operations == nil {
		return invalidField("operations", "must be an array, not null")
	}
	seen := make(map[string]struct{}, len(value.Operations))
	previous := ""
	for index, operation := range value.Operations {
		if err := validateOperationResult(operation); err != nil {
			return fmt.Errorf("operations[%d]: %w", index, err)
		}
		if _, exists := seen[operation.ID]; exists {
			return invalidField("operations", "contains duplicate operation ID %q", operation.ID)
		}
		if previous != "" && operation.ID < previous {
			return invalidField("operations", "must be sorted by ID")
		}
		seen[operation.ID] = struct{}{}
		previous = operation.ID
	}
	return nil
}

func validateOperationResult(value OperationResult) error {
	if err := validateID("id", value.ID); err != nil {
		return err
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
	if !validOperationOutcome(value.Outcome) {
		return invalidField("outcome", "is unsupported")
	}
	if err := validateOperationResultOutcome(value.Action, value.Outcome, value.RemoteID); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("baseline", value.Baseline); err != nil {
		return err
	}
	if err := validateRemoteStateAssertion("expectedPost", value.ExpectedPost); err != nil {
		return err
	}
	if err := validateOperationResultStates(value.Action, value.Baseline, value.ExpectedPost); err != nil {
		return err
	}
	if value.ReasonCode != "" {
		if err := validateCode("reasonCode", value.ReasonCode); err != nil {
			return err
		}
	}
	return nil
}

func knownRole(value auth.Role) bool {
	switch value {
	case auth.RoleViewer, auth.RolePlanner, auth.RoleApplier, auth.RoleAdministrator:
		return true
	default:
		return false
	}
}

func knownAuthMethod(value auth.Method) bool {
	switch value {
	case auth.MethodSession, auth.MethodOIDC, auth.MethodBearer, auth.MethodBreakGlass:
		return true
	default:
		return false
	}
}

func validMarker(value MarkerType) bool {
	switch value {
	case MarkerNone, MarkerDescription, MarkerRuleTag, MarkerPrebuiltStatus:
		return true
	default:
		return false
	}
}

func validMarkerForKind(kind manifest.Kind, marker MarkerType) bool {
	switch kind {
	case manifest.KindIntegrationPackage:
		return marker == MarkerNone
	case manifest.KindAgentPolicy, manifest.KindPackagePolicy:
		return marker == MarkerDescription
	case manifest.KindDetectionRule:
		return marker == MarkerRuleTag
	case manifest.KindPrebuiltRules:
		return marker == MarkerPrebuiltStatus
	default:
		return false
	}
}

func validDeleteMarker(kind manifest.Kind, marker MarkerType) bool {
	switch kind {
	case manifest.KindAgentPolicy, manifest.KindPackagePolicy:
		return marker == MarkerDescription
	case manifest.KindDetectionRule:
		return marker == MarkerRuleTag
	default:
		return false
	}
}

func validObservationSeverity(value ObservationSeverity) bool {
	return value == SeverityInfo || value == SeverityWarning || value == SeverityError
}

func validReportOutcome(value ReportOutcome) bool {
	return value == ReportSucceeded || value == ReportPartial || value == ReportFailed || value == ReportRejected
}

func validOperationOutcome(value OperationOutcome) bool {
	switch value {
	case OutcomeCreated, OutcomeUpdated, OutcomeDeleted, OutcomeUnchanged, OutcomeSkipped, OutcomeConflicted, OutcomeRejected, OutcomeFailed:
		return true
	default:
		return false
	}
}

func validateOperationResultOutcome(action OperationAction, outcome OperationOutcome, remoteID string) error {
	if (action == ActionUpdate || action == ActionDelete) && remoteID == "" {
		return invalidField("remoteID", "is required for update and delete results")
	}
	switch action {
	case ActionCreate:
		switch outcome {
		case OutcomeCreated:
			if remoteID == "" {
				return invalidField("remoteID", "is required when a create result is created")
			}
		case OutcomeSkipped, OutcomeRejected, OutcomeFailed:
			// A create can fail before Kibana assigns a remote ID.
		case OutcomeConflicted:
			if remoteID == "" {
				return invalidField("remoteID", "is required when a create result is conflicted")
			}
		default:
			return invalidField("outcome", "is not sensible for a create action")
		}
	case ActionUpdate:
		switch outcome {
		case OutcomeUpdated, OutcomeUnchanged, OutcomeSkipped, OutcomeConflicted, OutcomeRejected, OutcomeFailed:
		default:
			return invalidField("outcome", "is not sensible for an update action")
		}
	case ActionDelete:
		switch outcome {
		case OutcomeDeleted, OutcomeSkipped, OutcomeConflicted, OutcomeRejected, OutcomeFailed:
		default:
			return invalidField("outcome", "is not sensible for a delete action")
		}
	}
	return nil
}

func validateResultReference(value ResultReference) error {
	switch value.Kind {
	case ResultKindJob:
		if !jobIDPattern.MatchString(value.ID) {
			return invalidField("result.id", "must match the durable job ID format")
		}
	case ResultKindPlan, ResultKindReport, ResultKindCredentialMutation:
		if err := validateID("result.id", value.ID); err != nil {
			return err
		}
	default:
		return invalidField("result.kind", "is unsupported")
	}
	return nil
}

func validIdempotencyOutcome(value IdempotencyOutcome) bool {
	return value == IdempotencyPending || value == IdempotencySucceeded || value == IdempotencyFailed
}

func validateAction(field string, value audit.Action) error {
	if len(value) == 0 || len(value) > 128 || !actionPattern.MatchString(string(value)) {
		return invalidField(field, "must be a bounded namespaced action")
	}
	return nil
}

func validAuditOutcome(value audit.Outcome) bool {
	return value == audit.OutcomeSucceeded || value == audit.OutcomeDenied || value == audit.OutcomeFailed
}

// sortedStrings is shared by callers that need a defensive sorted copy when
// constructing a document. Validation never sorts caller-owned slices.
func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
