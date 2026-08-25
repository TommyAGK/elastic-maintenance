package state

import (
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

// Clone returns a defensive copy. Validation and encoding never mutate input,
// and these helpers make ownership explicit for code that builds a document
// from an existing manifest or plan.
func (value SourceSnapshot) Clone() SourceSnapshot {
	result := value
	result.Snapshot.ResourceSets = cloneSlice(value.Snapshot.ResourceSets)
	for index := range result.Snapshot.ResourceSets {
		if value.Snapshot.ResourceSets[index].Revision != nil {
			revision := *value.Snapshot.ResourceSets[index].Revision
			result.Snapshot.ResourceSets[index].Revision = &revision
		}
		result.Snapshot.ResourceSets[index].Files = cloneSlice(value.Snapshot.ResourceSets[index].Files)
		result.Snapshot.ResourceSets[index].Resources = cloneSlice(value.Snapshot.ResourceSets[index].Resources)
	}
	result.Snapshot.Targets = cloneSlice(value.Snapshot.Targets)
	for index := range result.Snapshot.Targets {
		result.Snapshot.Targets[index].Labels = cloneSlice(value.Snapshot.Targets[index].Labels)
		result.Snapshot.Targets[index].Resources = cloneSlice(value.Snapshot.Targets[index].Resources)
	}
	return result
}

func (value OwnershipInventory) Clone() OwnershipInventory {
	result := value
	result.Targets = cloneSlice(value.Targets)
	for index := range result.Targets {
		result.Targets[index].Entries = cloneSlice(value.Targets[index].Entries)
	}
	return result
}

func (value Plan) Clone() Plan {
	result := value
	result.CreatedBy.Roles = append([]auth.Role(nil), value.CreatedBy.Roles...)
	result.Targets = cloneSlice(value.Targets)
	for index := range result.Targets {
		result.Targets[index].CredentialMetadata.CertificateNotAfter = cloneTime(value.Targets[index].CredentialMetadata.CertificateNotAfter)
	}
	result.Operations = cloneSlice(value.Operations)
	for index := range result.Operations {
		result.Operations[index].Dependencies = cloneSlice(value.Operations[index].Dependencies)
		result.Operations[index].DesiredFingerprint = cloneFingerprint(value.Operations[index].DesiredFingerprint)
		result.Operations[index].Baseline = cloneRemoteStateAssertion(value.Operations[index].Baseline)
		result.Operations[index].ExpectedPost = cloneRemoteStateAssertion(value.Operations[index].ExpectedPost)
	}
	result.Observations = cloneSlice(value.Observations)
	for index := range result.Observations {
		result.Observations[index].DesiredFingerprint = cloneFingerprint(value.Observations[index].DesiredFingerprint)
		if value.Observations[index].LiveState != nil {
			live := cloneRemoteStateAssertion(*value.Observations[index].LiveState)
			result.Observations[index].LiveState = &live
		}
	}
	return result
}

func (value Report) Clone() Report {
	result := value
	result.Targets = cloneSlice(value.Targets)
	for index := range result.Targets {
		result.Targets[index].Operations = cloneSlice(value.Targets[index].Operations)
		for operationIndex := range result.Targets[index].Operations {
			operation := value.Targets[index].Operations[operationIndex]
			result.Targets[index].Operations[operationIndex].Baseline = cloneRemoteStateAssertion(operation.Baseline)
			result.Targets[index].Operations[operationIndex].ExpectedPost = cloneRemoteStateAssertion(operation.ExpectedPost)
		}
	}
	return result
}

func cloneSlice[T any](value []T) []T {
	if value == nil {
		return nil
	}
	result := make([]T, len(value))
	copy(result, value)
	return result
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneFingerprint(value *Fingerprint) *Fingerprint {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneRemoteStateAssertion(value RemoteStateAssertion) RemoteStateAssertion {
	value.Fingerprint = cloneFingerprint(value.Fingerprint)
	return value
}
