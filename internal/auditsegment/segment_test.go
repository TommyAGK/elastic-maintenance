package auditsegment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/audit"
	"github.com/TommyAGK/elastic-maintenance/internal/auditenvelope"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
)

const goldenEvent = `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"id-1","occurredAt":"2026-01-02T03:04:05Z","requestId":"request-1","action":"auth.login","outcome":"denied"}`

const goldenEmptySegment = `{"apiVersion":"elastic-maintainer/audit-segment/v1","sequence":7,"recordCount":0,"records":[]}`

const goldenOneSegment = `{"apiVersion":"elastic-maintainer/audit-segment/v1","sequence":7,"recordCount":1,"records":[{"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0","event":{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent","id":"id-1","occurredAt":"2026-01-02T03:04:05Z","requestId":"request-1","action":"auth.login","outcome":"denied"}}]}`

func envelopeFor(t *testing.T, id string) auditenvelope.Envelope {
	t.Helper()
	envelope, err := auditenvelope.New(id, audit.Event{
		OccurredAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		RequestID:  "request-1",
		Action:     audit.ActionLogin,
		Outcome:    audit.OutcomeDenied,
	})
	if err != nil {
		t.Fatalf("auditenvelope.New() error = %v", err)
	}
	return envelope
}

func actorEnvelopeFor(t *testing.T, id string, subjectLength int) auditenvelope.Envelope {
	t.Helper()
	envelope, err := auditenvelope.New(id, audit.Event{
		OccurredAt: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC),
		Actor: &auth.Actor{
			Subject: strings.Repeat("a", subjectLength),
			Roles:   []auth.Role{auth.RoleViewer},
			Method:  auth.MethodBearer,
		},
		RequestID: "request-1",
		Action:    audit.ActionLogin,
		Outcome:   audit.OutcomeSucceeded,
	})
	if err != nil {
		t.Fatalf("auditenvelope.New() error = %v", err)
	}
	return envelope
}

func mustNew(t *testing.T, sequence uint64) Segment {
	t.Helper()
	segment, err := New(sequence)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return segment
}

func mustAppend(t *testing.T, segment Segment, envelope auditenvelope.Envelope) Segment {
	t.Helper()
	result, err := segment.Append(envelope)
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	return result
}

func mustDecode(t *testing.T, sequence uint64, encoded []byte) Segment {
	t.Helper()
	segment, err := Decode(sequence, encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return segment
}

func mustCorrupt(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrCorruptSegment) {
		t.Fatalf("error = %v, want errors.Is(..., ErrCorruptSegment)", err)
	}
}

func TestNewAppendAndDecodeGoldenJSON(t *testing.T) {
	empty := mustNew(t, 7)
	if got := string(empty.Bytes()); got != goldenEmptySegment {
		t.Fatalf("empty bytes = %s, want %s", got, goldenEmptySegment)
	}
	if empty.Sequence() != 7 || empty.Count() != 0 || empty.Records() == nil {
		t.Fatalf("empty metadata = sequence %d count %d records=%#v", empty.Sequence(), empty.Count(), empty.Records())
	}

	one := mustAppend(t, empty, envelopeFor(t, "id-1"))
	if got := string(one.Bytes()); got != goldenOneSegment {
		t.Fatalf("one bytes = %s, want %s", got, goldenOneSegment)
	}
	if one.Sequence() != 7 || one.Count() != 1 {
		t.Fatalf("one metadata = sequence %d count %d", one.Sequence(), one.Count())
	}
	decoded := mustDecode(t, 7, []byte(goldenOneSegment))
	if !bytes.Equal(decoded.Bytes(), []byte(goldenOneSegment)) || decoded.Sequence() != 7 || decoded.Count() != 1 {
		t.Fatal("decoded golden segment changed")
	}
	if !bytes.Equal(decoded.Records()[0].Bytes(), []byte(goldenEvent)) || decoded.Records()[0].ID() != "id-1" {
		t.Fatal("decoded record was not the exact canonical event")
	}
}

func TestAppendManyIsDeterministicAndOrdered(t *testing.T) {
	empty := mustNew(t, math.MaxUint64)
	first, second := empty, empty
	for _, id := range []string{"id-1", "id-2", "id-3"} {
		first = mustAppend(t, first, envelopeFor(t, id))
		second = mustAppend(t, second, envelopeFor(t, id))
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("same sequence and envelopes produced different bytes")
	}
	if first.Sequence() != math.MaxUint64 || first.Count() != 3 {
		t.Fatalf("metadata = sequence %d count %d", first.Sequence(), first.Count())
	}
	for index, id := range []string{"id-1", "id-2", "id-3"} {
		if first.Records()[index].ID() != id || !bytes.Equal(first.Records()[index].Bytes(), envelopeFor(t, id).Bytes()) {
			t.Fatalf("record %d changed", index)
		}
	}
}

func TestSegmentAndRecordDefensiveCopies(t *testing.T) {
	segment := mustAppend(t, mustNew(t, 1), envelopeFor(t, "id-1"))
	wantSegment, wantEvent := segment.Bytes(), segment.Records()[0].Bytes()
	encoded := segment.Bytes()
	encoded[0] ^= 0xff
	encoded[len(encoded)-1] ^= 0xff
	if !bytes.Equal(segment.Bytes(), wantSegment) {
		t.Fatal("Bytes() output mutation changed Segment")
	}

	records := segment.Records()
	records[0] = Record{}
	event := segment.Records()[0].Bytes()
	event[0] ^= 0xff
	if segment.Records()[0].ID() != "id-1" || !bytes.Equal(segment.Records()[0].Bytes(), wantEvent) {
		t.Fatal("Records() output mutation changed Segment")
	}
	if len(records) != 1 {
		t.Fatal("Records() did not return an independent slice")
	}

	decoded := mustDecode(t, 1, wantSegment)
	wantSegment[0] ^= 0xff
	if !bytes.Equal(decoded.Bytes(), segment.Bytes()) {
		t.Fatal("Decode() retained caller-owned bytes")
	}

	before := segment.Bytes()
	returned, err := segment.Append(auditenvelope.Envelope{})
	if !errors.Is(err, ErrInvalidEnvelope) || !bytes.Equal(returned.Bytes(), before) || !bytes.Equal(segment.Bytes(), before) {
		t.Fatalf("invalid append changed segment: bytes=%s err=%v", returned.Bytes(), err)
	}
	returned, err = segment.Append(envelopeFor(t, "id-1"))
	if !errors.Is(err, ErrDuplicateEvent) || !bytes.Equal(returned.Bytes(), before) || returned.Count() != 1 {
		t.Fatalf("duplicate append changed segment: count=%d err=%v", returned.Count(), err)
	}
}

func TestNewAndDecodeSequenceVersionAndCountValidation(t *testing.T) {
	if _, err := New(0); !errors.Is(err, ErrInvalidSequence) {
		t.Fatalf("New(0) error = %v", err)
	}
	if _, err := Decode(0, nil); !errors.Is(err, ErrInvalidSequence) {
		t.Fatalf("Decode(0) error = %v", err)
	}
	valid := []byte(goldenOneSegment)
	cases := map[string][]byte{
		"wrong version":       bytes.Replace(valid, []byte(APIVersion), []byte("elastic-maintainer/audit-segment/v2"), 1),
		"zero sequence":       bytes.Replace(valid, []byte(`"sequence":7`), []byte(`"sequence":0`), 1),
		"fractional sequence": bytes.Replace(valid, []byte(`"sequence":7`), []byte(`"sequence":7.0`), 1),
		"count mismatch":      bytes.Replace(valid, []byte(`"recordCount":1`), []byte(`"recordCount":2`), 1),
		"null count":          bytes.Replace(valid, []byte(`"recordCount":1`), []byte(`"recordCount":null`), 1),
		"wrong casing":        bytes.Replace(valid, []byte(`"sequence":7`), []byte(`"Sequence":7`), 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) { _, err := Decode(7, value); mustCorrupt(t, err) })
	}
	if _, err := Decode(8, valid); !errors.Is(err, ErrCorruptSegment) {
		t.Fatalf("wrong expected sequence error = %v", err)
	}
}

func TestDecodeRejectsStrictWrapperForms(t *testing.T) {
	valid := []byte(goldenOneSegment)
	reorderedRoot := []byte(strings.Replace(string(valid),
		`{"apiVersion":"`+APIVersion+`","sequence":7,"recordCount":1,"records":`,
		`{"sequence":7,"apiVersion":"`+APIVersion+`","recordCount":1,"records":`, 1))
	reorderedRecord := []byte(strings.Replace(string(valid),
		`{"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0","event":`,
		`{"event":`+goldenEvent+`,"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0"}`, 1))
	cases := map[string][]byte{
		"unknown root":            append(valid[:len(valid)-1], []byte(`,"unexpected":true}`)...),
		"unknown record":          []byte(strings.Replace(string(valid), `{"sha256":`, `{"unexpected":true,"sha256":`, 1)),
		"duplicate root":          []byte(strings.Replace(string(valid), `,"records":`, `,"apiVersion":"`+APIVersion+`","records":`, 1)),
		"duplicate record":        []byte(strings.Replace(string(valid), `,"event":`, `,"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0","event":`, 1)),
		"root casing":             bytes.Replace(valid, []byte(`"recordCount":1`), []byte(`"RecordCount":1`), 1),
		"record casing":           bytes.Replace(valid, []byte(`"sha256":`), []byte(`"SHA256":`), 1),
		"trailing JSON":           append(valid, []byte(` {}`)...),
		"leading whitespace":      append([]byte(" \n\t"), valid...),
		"trailing whitespace":     append(valid, []byte(" \n\t")...),
		"root key reorder":        reorderedRoot,
		"record key reorder":      reorderedRecord,
		"null records":            bytes.Replace(valid, []byte(`"records":[`), []byte(`"records":null`), 1),
		"noncanonical API escape": bytes.Replace(valid, []byte(`elastic-maintainer/audit-segment/v1`), []byte(`\u0065lastic-maintainer/audit-segment/v1`), 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) { _, err := Decode(7, value); mustCorrupt(t, err) })
	}
}

func TestDecodeChecksumsAndDuplicateEventIDs(t *testing.T) {
	valid := []byte(goldenOneSegment)
	badChecksum := bytes.Replace(valid, []byte(`"sha256":"a6`), []byte(`"sha256":"b6`), 1)
	if _, err := Decode(7, badChecksum); !errors.Is(err, ErrCorruptSegment) {
		t.Fatalf("checksum error = %v", err)
	}
	// Build the two-record value directly so the event checksum remains exact.
	two := `{"apiVersion":"` + APIVersion + `","sequence":7,"recordCount":2,"records":[{"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0","event":` + goldenEvent + `},{"sha256":"a6d3f577dec942f11cbc19c034878f5d727dbb052fa488e14a0a674db9d40ae0","event":` + goldenEvent + `}]}`
	if _, err := Decode(7, []byte(two)); !errors.Is(err, ErrDuplicateEvent) {
		t.Fatalf("duplicate decode error = %v", err)
	}
	segment := mustAppend(t, mustNew(t, 7), envelopeFor(t, "id-1"))
	if _, err := segment.Append(envelopeFor(t, "id-1")); !errors.Is(err, ErrDuplicateEvent) {
		t.Fatalf("duplicate append error = %v", err)
	}
}

func TestDecodeValidatesCanonicalEventsAndCompatibility(t *testing.T) {
	duplicateEvent := goldenEvent[:len(goldenEvent)-1] + `,"id":"id-1"}`
	unknownEvent := goldenEvent[:len(goldenEvent)-1] + `,"unexpected":true}`
	trailingEvent := append(append([]byte(nil), []byte(goldenEvent)...), []byte(` {}`)...)
	cases := map[string][]byte{
		"malformed":     segmentForEvent([]byte(`{"apiVersion":`)),
		"whitespace":    segmentForEvent(append(append([]byte(nil), []byte(goldenEvent)...), ' ')),
		"reordered":     segmentForEvent([]byte(strings.Replace(goldenEvent, `{"apiVersion":"elastic-maintainer/state/v1alpha1","kind":"AuditEvent"`, `{"kind":"AuditEvent","apiVersion":"elastic-maintainer/state/v1alpha1"`, 1))),
		"duplicate":     segmentForEvent([]byte(duplicateEvent)),
		"unknown":       segmentForEvent([]byte(unknownEvent)),
		"wrong casing":  segmentForEvent([]byte(strings.Replace(goldenEvent, `"requestId"`, `"RequestId"`, 1))),
		"trailing JSON": segmentForEvent(trailingEvent),
		"explicit null": segmentForEvent([]byte(strings.Replace(goldenEvent, `,"outcome":"denied"}`, `,"outcome":"denied","reasonCode":null}`, 1))),
		"null":          segmentForEvent([]byte(`null`)),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) { _, err := Decode(7, value); mustCorrupt(t, err) })
	}
	legacy := []byte(strings.Replace(goldenEvent, `,"outcome":"denied"}`, `,"outcome":"denied","jobID":"job.legacy:v1"}`, 1))
	decoded := mustDecode(t, 7, segmentForEvent(legacy))
	if decoded.Records()[0].ID() != "id-1" || !bytes.Equal(decoded.Records()[0].Bytes(), legacy) {
		t.Fatal("legacy dotted job event was not retained canonically")
	}
}

func TestDecodeRejectsTruncationAtEveryByteBoundary(t *testing.T) {
	valid := []byte(goldenOneSegment)
	for length := 0; length < len(valid); length++ {
		if _, err := Decode(7, valid[:length]); !errors.Is(err, ErrCorruptSegment) {
			t.Fatalf("truncation length %d error = %v", length, err)
		}
	}
	if _, err := Decode(7, valid); err != nil {
		t.Fatalf("complete segment error = %v", err)
	}
}

func TestDecodeBoundsHostileArraysAndOversizedInput(t *testing.T) {
	if _, err := Decode(1, bytes.Repeat([]byte("x"), MaxSegmentBytes+1)); !errors.Is(err, ErrCorruptSegment) {
		t.Fatalf("oversized input error = %v", err)
	}
	// This is well below 4 MiB but has a hostile records array. The scanner
	// and boundedRecords parser reject it without retaining a giant slice.
	items := strings.TrimSuffix(strings.Repeat("null,", MaxRecords+2000), ",")
	hostile := []byte(`{"apiVersion":"` + APIVersion + `","sequence":1,"recordCount":` + strconv.Itoa(MaxRecords+2000) + `,"records":[` + items + `]}`)
	if len(hostile) >= MaxSegmentBytes {
		t.Fatal("hostile-array fixture unexpectedly exceeds input bound")
	}
	if _, err := Decode(1, hostile); !errors.Is(err, ErrCorruptSegment) {
		t.Fatalf("hostile array error = %v", err)
	}
}

func TestAppendCountAndExactSizeLimits(t *testing.T) {
	segment := mustNew(t, 8)
	for index := 0; index < MaxRecords; index++ {
		segment = mustAppend(t, segment, envelopeFor(t, "id-"+strconv.Itoa(index)))
	}
	if segment.Count() != MaxRecords {
		t.Fatalf("count = %d, want %d", segment.Count(), MaxRecords)
	}
	if decoded, err := Decode(8, segment.Bytes()); err != nil || decoded.Count() != MaxRecords {
		t.Fatalf("max-count Decode() = count %d, error %v", decoded.Count(), err)
	}
	if _, err := segment.Append(envelopeFor(t, "one-too-many")); !errors.Is(err, ErrSegmentFull) {
		t.Fatalf("record limit error = %v", err)
	}

	// Fill with bounded valid events, then find the subject length that lands
	// exactly on the complete JSON segment bound. A one-byte subject change is
	// a one-byte encoded-size change for this fixture.
	large := mustNew(t, 10)
	for index := 0; index < MaxRecords; index++ {
		next, err := large.Append(actorEnvelopeFor(t, "large-"+strconv.Itoa(index), 64<<10))
		if errors.Is(err, ErrSegmentFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		large = next
	}
	var boundary Segment
	for low, high := 1, 64<<10; low <= high; {
		mid := low + (high-low)/2
		candidate, err := large.Append(actorEnvelopeFor(t, "boundary", mid))
		if errors.Is(err, ErrSegmentFull) {
			high = mid - 1
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(candidate.Bytes()) == MaxSegmentBytes {
			boundary = candidate
			break
		}
		low = mid + 1
	}
	if boundary.Count() == 0 {
		t.Fatal("could not construct exact 4 MiB JSON boundary")
	}
	if len(boundary.Bytes()) != MaxSegmentBytes {
		t.Fatalf("boundary size = %d, want %d", len(boundary.Bytes()), MaxSegmentBytes)
	}
	if _, err := boundary.Append(envelopeFor(t, "after-boundary")); !errors.Is(err, ErrSegmentFull) {
		t.Fatalf("size limit error = %v", err)
	}
	if _, err := Decode(10, boundary.Bytes()); err != nil {
		t.Fatalf("exact-boundary Decode() error = %v", err)
	}
}

func TestErrorsAreFixedAndSecretSafe(t *testing.T) {
	const secret = "AUDIT-SECRET-SENTINEL"
	malformed := segmentForEvent([]byte(`{"apiVersion":"` + secret + `"`))
	_, err := Decode(11, malformed)
	if !errors.Is(err, ErrCorruptSegment) || strings.Contains(err.Error(), secret) {
		t.Fatalf("corrupt error = %q", err)
	}
	if _, err := New(0); !errors.Is(err, ErrInvalidSequence) || strings.Contains(err.Error(), secret) {
		t.Fatalf("sequence error = %q", err)
	}
	if _, err := mustNew(t, 11).Append(auditenvelope.Envelope{}); !errors.Is(err, ErrInvalidEnvelope) || strings.Contains(err.Error(), secret) {
		t.Fatalf("envelope error = %q", err)
	}
}

func segmentForEvent(event []byte) []byte {
	digest := sha256.Sum256(event)
	return []byte(`{"apiVersion":"` + APIVersion + `","sequence":7,"recordCount":1,"records":[{"sha256":"` + hex.EncodeToString(digest[:]) + `","event":` + string(event) + `}]}`)
}
