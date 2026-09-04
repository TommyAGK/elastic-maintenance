// Package auditsegment provides the pure, bounded JSON codec for durable audit
// segments. It has no filesystem, runtime, or storage dependencies: callers
// bind a decoded segment to a filename or other sequence externally through
// Decode's expectedSequence argument.
package auditsegment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/TommyAGK/elastic-maintenance/internal/auditenvelope"
	"github.com/TommyAGK/elastic-maintenance/internal/state"
)

const (
	// APIVersion identifies the immutable audit-segment JSON contract.
	APIVersion = "elastic-maintainer/audit-segment/v1"

	// MaxSegmentBytes is the complete encoded segment bound. It intentionally
	// matches the current statefs per-file default while this package remains
	// independent of statefs.
	MaxSegmentBytes = 4 << 20

	// MaxRecords bounds both the encoded recordCount and the records retained
	// by one decoded segment.
	MaxRecords = 1024

	// MaxRecordsPerSegment is retained as a descriptive compatibility alias.
	MaxRecordsPerSegment = MaxRecords
)

var (
	// ErrInvalidSequence identifies a zero caller-supplied sequence.
	ErrInvalidSequence = errors.New("invalid audit segment sequence")
	// ErrInvalidEnvelope identifies a zero or invalid envelope supplied to
	// Append. It aliases the envelope package's fixed safe sentinel.
	ErrInvalidEnvelope = auditenvelope.ErrInvalidEnvelope
	// ErrCorruptSegment identifies any malformed, non-canonical, or
	// inconsistent encoded segment.
	ErrCorruptSegment = errors.New("corrupt audit segment")
	// ErrSegmentFull means an otherwise valid append would cross a segment
	// bound.
	ErrSegmentFull = errors.New("audit segment is full")
	// ErrDuplicateEvent identifies an event ID repeated in one segment.
	ErrDuplicateEvent = errors.New("duplicate audit event")

	errInvalidWire = errors.New("invalid audit segment JSON")
)

const (
	segmentPrefix        = `{"apiVersion":"` + APIVersion + `","sequence":`
	segmentCountPrefix   = `,"recordCount":`
	segmentRecordsPrefix = `,"records":`
	segmentSuffix        = `]}`
	recordPrefix         = `{"sha256":"`
	recordEventPrefix    = `","event":`
	recordSuffix         = `}`
	sha256HexBytes       = sha256.Size * 2
	maxScanDepth         = 64
	maxScanObjectKeys    = 100_000
	maxScanArrayItems    = 100_000
	maxScanNodes         = 500_000
)

var (
	segmentFields = map[string]struct{}{
		"apiVersion":  {},
		"sequence":    {},
		"recordCount": {},
		"records":     {},
	}
	recordFields = map[string]struct{}{
		"sha256": {},
		"event":  {},
	}
)

// Segment is an immutable encoded audit segment. Its encoded bytes and event
// ID index are unexported so callers cannot mutate either representation.
type Segment struct {
	encoded  []byte
	sequence uint64
	count    uint32
	records  []Record
}

// Record is one immutable canonical audit-event payload from a validated
// segment. It supports cross-segment ID lookup and exact replay checks without
// exposing mutable segment storage or reparsing the wrapper in the repository.
type Record struct {
	id        string
	canonical []byte
}

// ID returns the validated durable audit-event ID.
func (record Record) ID() string { return record.id }

// Bytes returns a defensive copy of the exact canonical AuditEvent payload.
func (record Record) Bytes() []byte {
	return append([]byte(nil), record.canonical...)
}

// New creates an empty segment for a positive sequence.
func New(sequence uint64) (Segment, error) {
	if sequence == 0 {
		return Segment{}, ErrInvalidSequence
	}
	records := make([]Record, 0)
	encoded, err := marshalSegment(sequence, records)
	if err != nil || len(encoded) > MaxSegmentBytes {
		return Segment{}, ErrCorruptSegment
	}
	return Segment{encoded: encoded, sequence: sequence, records: records}, nil
}

// Decode strictly validates one complete canonical segment. expectedSequence
// binds the caller's filename or other external sequence to the JSON sequence;
// a mismatch is corruption rather than a silently accepted alternate segment.
func Decode(expectedSequence uint64, encoded []byte) (Segment, error) {
	if expectedSequence == 0 {
		return Segment{}, ErrInvalidSequence
	}
	// This check deliberately precedes all decoder work. The bounded scanner
	// and the bounded records decoder below then operate on at most this many
	// caller-controlled bytes.
	if len(encoded) > MaxSegmentBytes {
		return Segment{}, ErrCorruptSegment
	}
	if err := scanWrapperJSON(encoded); err != nil {
		return Segment{}, ErrCorruptSegment
	}

	var wire segmentWire
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return Segment{}, ErrCorruptSegment
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Segment{}, ErrCorruptSegment
	}

	if wire.APIVersion != APIVersion || wire.Sequence == 0 || wire.Sequence != expectedSequence || wire.Records == nil {
		return Segment{}, ErrCorruptSegment
	}
	// boundedRecords prevents encoding/json from retaining an unbounded
	// records list. Keep this post-decode check as a second invariant check for
	// the wire representation.
	if wire.RecordCount > MaxRecords || len(wire.Records) > MaxRecords || uint64(wire.RecordCount) != uint64(len(wire.Records)) {
		return Segment{}, ErrCorruptSegment
	}

	// Only the bounded record list and its event-sized byte copies are retained
	// after all wrapper structure has been decoded.
	records := make([]Record, len(wire.Records))
	seen := make(map[string]struct{}, len(wire.Records))
	for index, item := range wire.Records {
		event, canonical, ok := canonicalAuditEvent(item.Event)
		if !ok || !validSHA256(item.SHA256) {
			return Segment{}, ErrCorruptSegment
		}
		digest := sha256.Sum256(canonical)
		if item.SHA256 != hex.EncodeToString(digest[:]) {
			return Segment{}, ErrCorruptSegment
		}
		if _, exists := seen[event.ID]; exists {
			return Segment{}, ErrDuplicateEvent
		}
		seen[event.ID] = struct{}{}
		records[index] = Record{id: event.ID, canonical: append([]byte(nil), canonical...)}
	}

	// State decoding accepts a small, explicitly documented read-compatibility
	// surface. A segment is stricter: every event and the wrapper must already
	// be in their exact canonical byte representation.
	canonical, err := marshalSegment(wire.Sequence, records)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Segment{}, ErrCorruptSegment
	}
	return Segment{encoded: canonical, sequence: wire.Sequence, count: wire.RecordCount, records: records}, nil
}

// Append returns a new segment containing envelope. The receiver and the
// supplied envelope remain unchanged on both success and error.
func (segment Segment) Append(envelope auditenvelope.Envelope) (Segment, error) {
	if !segment.validForAppend() {
		return segment, ErrCorruptSegment
	}
	if envelope.Validate() != nil {
		return segment, ErrInvalidEnvelope
	}
	payload := envelope.Bytes()
	event, canonical, ok := canonicalAuditEvent(payload)
	if !ok || !bytes.Equal(payload, canonical) {
		return segment, ErrInvalidEnvelope
	}
	for _, record := range segment.records {
		if record.id == event.ID {
			return segment, ErrDuplicateEvent
		}
	}
	if segment.count >= MaxRecords {
		return segment, ErrSegmentFull
	}

	// Compute the exact JSON size before allocating the candidate record list
	// or asking encoding/json to allocate the complete encoded segment. The
	// final marshal is still authoritative, but this makes the full-boundary
	// rejection allocation-safe for valid internal values.
	newSize := segmentJSONSize(segment.sequence, segment.count+1, segment.records, payload)
	if newSize > MaxSegmentBytes {
		return segment, ErrSegmentFull
	}

	records := make([]Record, len(segment.records)+1)
	copy(records, segment.records)
	records[len(segment.records)] = Record{id: event.ID, canonical: append([]byte(nil), canonical...)}
	encoded, err := marshalSegment(segment.sequence, records)
	if err != nil || uint64(len(encoded)) != newSize || len(encoded) > MaxSegmentBytes {
		return segment, ErrCorruptSegment
	}
	return Segment{encoded: encoded, sequence: segment.sequence, count: segment.count + 1, records: records}, nil
}

// Bytes returns a defensive copy of the complete encoded segment.
func (segment Segment) Bytes() []byte {
	return append([]byte(nil), segment.encoded...)
}

// Sequence returns the segment sequence from its validated wrapper.
func (segment Segment) Sequence() uint64 {
	return segment.sequence
}

// Count returns the number of encoded audit events.
func (segment Segment) Count() uint32 {
	return segment.count
}

// Records returns immutable record values in their exact event order. The
// slice and every payload returned by Record.Bytes are defensive copies.
func (segment Segment) Records() []Record {
	result := make([]Record, len(segment.records))
	for index, record := range segment.records {
		result[index] = Record{id: record.id, canonical: append([]byte(nil), record.canonical...)}
	}
	return result
}

// validForAppend checks the immutable metadata needed before extending a
// Segment. External callers cannot construct a value with a different encoded
// body or ID index because all fields are unexported; the size check also
// rejects a zero or internally inconsistent value without parsing untrusted
// bytes.
func (segment Segment) validForAppend() bool {
	if segment.sequence == 0 || segment.encoded == nil || len(segment.encoded) > MaxSegmentBytes {
		return false
	}
	if segment.count > MaxRecords || len(segment.records) != int(segment.count) {
		return false
	}
	return segmentJSONSize(segment.sequence, segment.count, segment.records, nil) == uint64(len(segment.encoded))
}

type segmentWire struct {
	APIVersion  string         `json:"apiVersion"`
	Sequence    uint64         `json:"sequence"`
	RecordCount uint32         `json:"recordCount"`
	Records     boundedRecords `json:"records"`
}

type segmentRecordWire struct {
	SHA256 string          `json:"sha256"`
	Event  json.RawMessage `json:"event"`
}

type boundedRecords []segmentRecordWire

// UnmarshalJSON bounds the retained records list while allowing the outer
// decoder to remain the standard encoding/json strict decoder. The segment
// input has already been capped to MaxSegmentBytes; a hostile array can
// therefore consume at most that many input bytes, while this list retains at
// most MaxRecords entries.
func (records *boundedRecords) UnmarshalJSON(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('[') {
		return errInvalidWire
	}
	values := make(boundedRecords, 0)
	for decoder.More() {
		if len(values) >= MaxRecords {
			return errInvalidWire
		}
		var value segmentRecordWire
		if err := decoder.Decode(&value); err != nil {
			return errInvalidWire
		}
		values = append(values, value)
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim(']') {
		return errInvalidWire
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errInvalidWire
	}
	*records = values
	return nil
}

func marshalSegment(sequence uint64, records []Record) ([]byte, error) {
	wireRecords := make([]segmentRecordWire, len(records))
	for index, record := range records {
		if len(record.canonical) == 0 {
			return nil, errInvalidWire
		}
		digest := sha256.Sum256(record.canonical)
		wireRecords[index] = segmentRecordWire{
			SHA256: hex.EncodeToString(digest[:]),
			Event:  json.RawMessage(record.canonical),
		}
	}
	return json.Marshal(segmentWire{
		APIVersion:  APIVersion,
		Sequence:    sequence,
		RecordCount: uint32(len(records)),
		Records:     boundedRecords(wireRecords),
	})
}

func canonicalAuditEvent(payload []byte) (state.AuditEvent, []byte, bool) {
	event, err := state.DecodeAuditEvent(payload)
	if err != nil {
		return state.AuditEvent{}, nil, false
	}
	canonical, err := state.EncodeAuditEvent(event)
	if err != nil || !bytes.Equal(canonical, payload) {
		return state.AuditEvent{}, nil, false
	}
	return event, canonical, true
}

func validSHA256(value string) bool {
	if len(value) != sha256HexBytes {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// segmentJSONSize computes the exact compact encoding size for records already
// known to contain canonical event bytes. appended is either nil (no append)
// or one additional non-empty canonical event payload.
func segmentJSONSize(sequence uint64, count uint32, records []Record, appended []byte) uint64 {
	size := uint64(len(segmentPrefix)) + uint64(decimalDigits(sequence))
	size += uint64(len(segmentCountPrefix)) + uint64(decimalDigits(uint64(count)))
	size += uint64(len(segmentRecordsPrefix)) + 1 // opening '['
	for index, record := range records {
		if index > 0 {
			size++
		}
		size += uint64(len(recordPrefix) + sha256HexBytes + len(recordEventPrefix) + len(recordSuffix))
		size += uint64(len(record.canonical))
	}
	if appended != nil {
		if len(records) > 0 {
			size++
		}
		size += uint64(len(recordPrefix) + sha256HexBytes + len(recordEventPrefix) + len(recordSuffix))
		size += uint64(len(appended))
	}
	return size + uint64(len(segmentSuffix))
}

func decimalDigits(value uint64) int {
	if value == 0 {
		return 1
	}
	digits := 0
	for value > 0 {
		digits++
		value /= 10
	}
	return digits
}

type scanObjectKind uint8

const (
	scanGenericObject scanObjectKind = iota
	scanSegmentObject
	scanRecordObject
	scanRecordsArray
)

type wrapperScanner struct {
	nodes int
}

// scanWrapperJSON performs the local duplicate and wrapper allowlist pass.
// state.DecodeAuditEvent remains authoritative for the event schema; this
// scanner only adds wrapper-context checks and ensures duplicate keys cannot
// be hidden behind encoding/json's last-key-wins behavior.
func scanWrapperJSON(encoded []byte) error {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return ErrCorruptSegment
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return ErrCorruptSegment
	}
	scanner := wrapperScanner{}
	if err := scanner.walk(decoder, first, 0, scanSegmentObject); err != nil {
		return err
	}
	var trailing json.Token
	trailing, err = decoder.Token()
	if err != io.EOF || trailing != nil {
		return ErrCorruptSegment
	}
	return nil
}

func (scanner *wrapperScanner) walk(decoder *json.Decoder, token json.Token, depth int, kind scanObjectKind) error {
	scanner.nodes++
	if scanner.nodes > maxScanNodes || depth > maxScanDepth {
		return ErrCorruptSegment
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		keys := 0
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return ErrCorruptSegment
			}
			name, ok := key.(string)
			if !ok {
				return ErrCorruptSegment
			}
			if _, exists := seen[name]; exists {
				return ErrCorruptSegment
			}
			seen[name] = struct{}{}
			keys++
			if keys > maxScanObjectKeys {
				return ErrCorruptSegment
			}
			if kind == scanSegmentObject {
				if !exactField(segmentFields, name) {
					return ErrCorruptSegment
				}
			} else if kind == scanRecordObject {
				if !exactField(recordFields, name) {
					return ErrCorruptSegment
				}
			}
			child, err := decoder.Token()
			if err != nil {
				return ErrCorruptSegment
			}
			childKind := scanGenericObject
			if kind == scanSegmentObject && name == "records" {
				childKind = scanRecordsArray
			}
			if err := scanner.walk(decoder, child, depth+1, childKind); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrCorruptSegment
		}
	case '[':
		items := 0
		for decoder.More() {
			items++
			if items > maxScanArrayItems || (kind == scanRecordsArray && items > MaxRecords) {
				return ErrCorruptSegment
			}
			child, err := decoder.Token()
			if err != nil {
				return ErrCorruptSegment
			}
			childKind := scanGenericObject
			if kind == scanRecordsArray {
				childKind = scanRecordObject
			}
			if err := scanner.walk(decoder, child, depth+1, childKind); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrCorruptSegment
		}
	default:
		return ErrCorruptSegment
	}
	return nil
}

func exactField(fields map[string]struct{}, value string) bool {
	_, ok := fields[value]
	return ok
}
