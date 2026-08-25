package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

// Encode validates a known state document and emits one bounded JSON value.
// It never retains references to the caller's slices or maps.
func Encode(document any) ([]byte, error) {
	if isNilValue(document) {
		return nil, ErrNilDestination
	}
	value, ok := documentValue(document)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported document type %T", ErrInvalidDocument, document)
	}
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode state document: %w", err)
	}
	if len(encoded) > MaxDocumentBytes {
		return nil, ErrDocumentTooLarge
	}
	if err := scanJSON(encoded); err != nil {
		return nil, fmt.Errorf("encode state document: %w", err)
	}
	return encoded, nil
}

// Decode strictly decodes one known document into a non-nil pointer. Unknown
// fields, duplicate object keys, trailing JSON, unsupported headers, invalid
// values, and oversized documents are rejected before the destination is
// changed.
func Decode(encoded []byte, destination any) error {
	if isNilValue(destination) {
		return ErrNilDestination
	}
	if len(encoded) > MaxDocumentBytes {
		return ErrDocumentTooLarge
	}
	if err := scanJSON(encoded); err != nil {
		return err
	}
	switch typed := destination.(type) {
	case *SourceSnapshot:
		if typed == nil {
			return ErrNilDestination
		}
		var value SourceSnapshot
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *OwnershipInventory:
		if typed == nil {
			return ErrNilDestination
		}
		var value OwnershipInventory
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *PreMutationJournal:
		if typed == nil {
			return ErrNilDestination
		}
		var value PreMutationJournal
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *Plan:
		if typed == nil {
			return ErrNilDestination
		}
		var value Plan
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *Job:
		if typed == nil {
			return ErrNilDestination
		}
		var value Job
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *Report:
		if typed == nil {
			return ErrNilDestination
		}
		var value Report
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *IdempotencyRecord:
		if typed == nil {
			return ErrNilDestination
		}
		var value IdempotencyRecord
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	case *AuditEvent:
		if typed == nil {
			return ErrNilDestination
		}
		var value AuditEvent
		if err := strictUnmarshal(encoded, &value); err != nil {
			return err
		}
		if err := value.Validate(); err != nil {
			return err
		}
		*typed = value
	default:
		return fmt.Errorf("%w: decode destination %T", ErrInvalidDocument, destination)
	}
	return nil
}

// DecodeDocument dispatches by the strict top-level kind. A future version is
// reported as unsupported; it is never silently migrated.
func DecodeDocument(encoded []byte) (Document, error) {
	if len(encoded) > MaxDocumentBytes {
		return nil, ErrDocumentTooLarge
	}
	if err := scanJSON(encoded); err != nil {
		return nil, err
	}
	var header struct {
		APIVersion string `json:"apiVersion"`
		Kind       Kind   `json:"kind"`
	}
	if err := strictUnmarshal(encoded, &header); err != nil {
		// DecodeDocument needs to inspect only the header, so unknown body
		// fields are checked by the typed decode below instead.
		var loose struct {
			APIVersion string `json:"apiVersion"`
			Kind       Kind   `json:"kind"`
		}
		if decodeErr := json.Unmarshal(encoded, &loose); decodeErr != nil {
			return nil, err
		}
		header = loose
	}
	if header.APIVersion != APIVersion {
		return nil, &versionError{Got: header.APIVersion, Want: APIVersion}
	}
	if !supportedKind(header.Kind) {
		return nil, &kindError{Got: header.Kind}
	}
	switch header.Kind {
	case KindSourceSnapshot:
		var value SourceSnapshot
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindOwnershipInventory:
		var value OwnershipInventory
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindPreMutationJournal:
		var value PreMutationJournal
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindPlan:
		var value Plan
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindJob:
		var value Job
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindReport:
		var value Report
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindIdempotency:
		var value IdempotencyRecord
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	case KindAuditEvent:
		var value AuditEvent
		if err := Decode(encoded, &value); err != nil {
			return nil, err
		}
		return value, nil
	default:
		return nil, &kindError{Got: header.Kind}
	}
}

func documentValue(document any) (Document, bool) {
	switch value := document.(type) {
	case SourceSnapshot:
		return value, true
	case *SourceSnapshot:
		if value == nil {
			return nil, false
		}
		return *value, true
	case OwnershipInventory:
		return value, true
	case *OwnershipInventory:
		if value == nil {
			return nil, false
		}
		return *value, true
	case PreMutationJournal:
		return value, true
	case *PreMutationJournal:
		if value == nil {
			return nil, false
		}
		return *value, true
	case Plan:
		return value, true
	case *Plan:
		if value == nil {
			return nil, false
		}
		return *value, true
	case Job:
		return value, true
	case *Job:
		if value == nil {
			return nil, false
		}
		return *value, true
	case Report:
		return value, true
	case *Report:
		if value == nil {
			return nil, false
		}
		return *value, true
	case IdempotencyRecord:
		return value, true
	case *IdempotencyRecord:
		if value == nil {
			return nil, false
		}
		return *value, true
	case AuditEvent:
		return value, true
	case *AuditEvent:
		if value == nil {
			return nil, false
		}
		return *value, true
	default:
		return nil, false
	}
}

func isNilValue(value any) bool {
	if value == nil {
		return true
	}
	candidate := reflect.ValueOf(value)
	switch candidate.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return candidate.IsNil()
	default:
		return false
	}
}

func strictUnmarshal(encoded []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("%w: decode state document: %v", ErrInvalidDocument, err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return ErrTrailingJSON
		}
		return invalidJSONError("decode state document", err)
	}
	return nil
}

func scanJSON(encoded []byte) error {
	if len(encoded) == 0 {
		return fmt.Errorf("%w: empty JSON", ErrInvalidDocument)
	}
	if !utf8.Valid(encoded) {
		return fmt.Errorf("%w: JSON is not valid UTF-8", ErrInvalidDocument)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	state := jsonScanState{}
	first, err := decoder.Token()
	if err != nil {
		return invalidJSONError("decode state JSON", err)
	}
	delimiter, object := first.(json.Delim)
	if !object || delimiter != '{' {
		return fmt.Errorf("%w: state document must be a JSON object", ErrInvalidDocument)
	}
	if err := state.walk(decoder, first, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return ErrTrailingJSON
		}
		return invalidJSONError("decode state JSON", err)
	}
	return nil
}

func invalidJSONError(context string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrInvalidDocument, context, err)
}

type jsonScanState struct{ nodes int }

func (state *jsonScanState) walk(decoder *json.Decoder, token json.Token, depth int) error {
	state.nodes++
	if state.nodes > maxJSONNodes {
		return ErrDocumentTooLarge
	}
	if depth > maxJSONDepth {
		return fmt.Errorf("%w: JSON nesting is too deep", ErrInvalidDocument)
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]struct{}{}
			count := 0
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return invalidJSONError("decode state JSON object key", err)
				}
				name, ok := key.(string)
				if !ok {
					return fmt.Errorf("%w: object key is not a string", ErrInvalidDocument)
				}
				if _, exists := seen[name]; exists {
					return fmt.Errorf("%w: %q", ErrDuplicateField, name)
				}
				if !exactKnownKey(name) {
					return fmt.Errorf("%w: JSON field %q uses non-canonical casing", ErrInvalidDocument, name)
				}
				seen[name] = struct{}{}
				count++
				if count > maxJSONObject {
					return ErrDocumentTooLarge
				}
				child, err := decoder.Token()
				if err != nil {
					return invalidJSONError("decode state JSON object value", err)
				}
				if err := state.walk(decoder, child, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return invalidJSONError("decode state JSON object end", err)
			}
			if end != json.Delim('}') {
				return fmt.Errorf("%w: object is not closed", ErrInvalidDocument)
			}
		case '[':
			count := 0
			for decoder.More() {
				child, err := decoder.Token()
				if err != nil {
					return invalidJSONError("decode state JSON array value", err)
				}
				count++
				if count > maxJSONArray {
					return ErrDocumentTooLarge
				}
				if err := state.walk(decoder, child, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil {
				return invalidJSONError("decode state JSON array end", err)
			}
			if end != json.Delim(']') {
				return fmt.Errorf("%w: array is not closed", ErrInvalidDocument)
			}
		default:
			return fmt.Errorf("%w: unexpected delimiter", ErrInvalidDocument)
		}
	case string:
		if len(value) > maxJSONString {
			return ErrDocumentTooLarge
		}
	}
	return nil
}
