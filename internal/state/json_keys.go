package state

import "strings"

// encoding/json intentionally matches struct field names case-insensitively.
// Persisted formats cannot permit that ambiguity, so the scanner checks that
// every known key uses its exact documented spelling before struct decoding.
var canonicalJSONKeys = func() map[string]string {
	values := []string{
		"apiVersion", "kind", "id", "capturedAt", "snapshot", "url",
		"domain", "algorithm", "version", "value",
		"subject", "roles", "authMethod",
		"resourceSets", "stateID", "generation", "createdAt", "updatedAt", "fingerprint", "targets", "identity", "entries",
		"namespace", "name", "uid", "resourceVersion", "lastDesiredFingerprint", "logicalID", "remoteID", "marker", "presence", "space",
		"planID", "operationID", "target", "resourceKind", "action", "phase", "dependencies", "baseline", "expectedPost", "lifecycle", "mutationStartedAt", "mutationFinishedAt", "postVerifiedAt", "committedAt",
		"sourceSnapshotID", "source", "resourceSetID", "revision", "resourceSetDesiredFingerprint", "targetDesiredFingerprint", "targetConfigFingerprint", "kibanaVersion", "inventoryGeneration", "inventoryFingerprint", "credentialMetadata", "secretReference", "rotatedAt", "rotatedBy", "certificateSHA256", "certificateNotAfter",
		"toolVersion", "createdBy", "operations", "observations", "desiredFingerprint", "liveState", "code", "severity",
		"type", "status", "startedAt", "finishedAt", "actor", "requestId", "idempotencyKey", "requestDigest", "reportID", "failureCode", "cancellationRequested",
		"jobID", "outcome", "reasonCode", "key", "expiresAt", "result", "occurredAt", "targetID",
		"digestDomain", "digestVersion", "files", "resources", "resource", "desiredDigest", "bytes", "sha256", "labels", "relativePath", "document", "line", "column",
	}
	result := make(map[string]string, len(values))
	for _, value := range values {
		result[strings.ToLower(value)] = value
	}
	return result
}()

func exactKnownKey(key string) bool {
	canonical, known := canonicalJSONKeys[strings.ToLower(key)]
	return !known || canonical == key
}
