package state

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/TommyAGK/elastic-maintenance/internal/manifest"
)

// Validate exposes the same checks used by top-level document validation for
// reusable metadata projections.
func (value Actor) Validate() error { return validateActor("actor", value) }

func (value Fingerprint) Validate() error {
	switch value.Domain {
	case DesiredFingerprintDomain, KibanaLiveFingerprintDomain, InventoryFingerprintDomain, TargetConfigFingerprintDomain:
		return validateFingerprint("fingerprint", value, value.Domain)
	default:
		return invalidField("fingerprint.domain", "is unsupported")
	}
}

func ValidateFingerprint(value Fingerprint) error { return value.Validate() }

func (value SecretReference) Validate() error {
	return validateSecretReference("secretReference", value)
}

func (value CredentialMetadata) Validate() error {
	return validateCredentialMetadata("credentialMetadata", value)
}

func (value ResultReference) Validate() error {
	return validateResultReference(value)
}

func (value RemoteStateAssertion) Validate() error {
	return validateRemoteStateAssertion("remoteState", value)
}

// UnmarshalJSON preserves the distinction between an omitted fingerprint and
// an explicit null fingerprint. The latter is invalid for both presence values.
func (value *RemoteStateAssertion) UnmarshalJSON(encoded []byte) error {
	var raw struct {
		Presence    RemotePresence  `json:"presence"`
		Fingerprint json.RawMessage `json:"fingerprint"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw.Fingerprint != nil {
		if bytes.Equal(bytes.TrimSpace(raw.Fingerprint), []byte("null")) {
			return fmt.Errorf("remote state assertion fingerprint must not be null")
		}
		var fingerprint Fingerprint
		if err := strictUnmarshal(raw.Fingerprint, &fingerprint); err != nil {
			return err
		}
		value.Fingerprint = &fingerprint
	} else {
		value.Fingerprint = nil
	}
	value.Presence = raw.Presence
	return nil
}

func (value SourceProvenance) Validate() error { return validateSourceProvenance("source", value) }

func ValidateTargetIdentity(value manifest.InventoryTargetIdentity) error {
	return validateTargetIdentity(value)
}
