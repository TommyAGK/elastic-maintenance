package state

// Typed codec helpers keep callers from accidentally decoding one document
// kind into another while retaining the common strict codec underneath.

func EncodeSourceSnapshot(value SourceSnapshot) ([]byte, error) { return Encode(value) }
func EncodeOwnershipInventory(value OwnershipInventory) ([]byte, error) {
	return Encode(value)
}
func EncodePreMutationJournal(value PreMutationJournal) ([]byte, error) { return Encode(value) }
func EncodePlan(value Plan) ([]byte, error)                             { return Encode(value) }
func EncodeJob(value Job) ([]byte, error)                               { return Encode(value) }
func EncodeReport(value Report) ([]byte, error)                         { return Encode(value) }
func EncodeIdempotency(value IdempotencyRecord) ([]byte, error)         { return Encode(value) }
func EncodeAuditEvent(value AuditEvent) ([]byte, error)                 { return Encode(value) }

func DecodeSourceSnapshot(encoded []byte) (SourceSnapshot, error) {
	var value SourceSnapshot
	err := Decode(encoded, &value)
	return value, err
}

func DecodeOwnershipInventory(encoded []byte) (OwnershipInventory, error) {
	var value OwnershipInventory
	err := Decode(encoded, &value)
	return value, err
}

func DecodePreMutationJournal(encoded []byte) (PreMutationJournal, error) {
	var value PreMutationJournal
	err := Decode(encoded, &value)
	return value, err
}

func DecodePlan(encoded []byte) (Plan, error) {
	var value Plan
	err := Decode(encoded, &value)
	return value, err
}

func DecodeJob(encoded []byte) (Job, error) {
	var value Job
	err := Decode(encoded, &value)
	return value, err
}

func DecodeReport(encoded []byte) (Report, error) {
	var value Report
	err := Decode(encoded, &value)
	return value, err
}

func DecodeIdempotency(encoded []byte) (IdempotencyRecord, error) {
	var value IdempotencyRecord
	err := Decode(encoded, &value)
	return value, err
}

func DecodeAuditEvent(encoded []byte) (AuditEvent, error) {
	var value AuditEvent
	err := Decode(encoded, &value)
	return value, err
}
