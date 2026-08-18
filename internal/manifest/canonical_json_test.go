package manifest

import (
	"strings"
	"testing"
)

func TestMarshalCanonicalJSONRFC8785PropertyOrdering(t *testing.T) {
	input := map[string]any{
		"\u20ac": "Euro Sign",
		"\r":     "Carriage Return",
		"\ufb33": "Hebrew Letter Dalet With Dagesh",
		"1":      "One",
		"😀":      "Emoji: Grinning Face",
		"\u0080": "Control",
		"ö":      "Latin Small Letter O With Diaeresis",
	}
	encoded, err := marshalCanonicalJSON(input)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"ö\":\"Latin Small Letter O With Diaeresis\",\"€\":\"Euro Sign\",\"😀\":\"Emoji: Grinning Face\",\"דּ\":\"Hebrew Letter Dalet With Dagesh\"}"
	if string(encoded) != want {
		t.Fatalf("canonical JSON = %s\nwant = %s", encoded, want)
	}
}

func TestMarshalCanonicalJSONDoesNotUseHTMLEscaping(t *testing.T) {
	encoded, err := marshalCanonicalJSON(map[string]any{"value": "<script>&\u2028"})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{\"value\":\"<script>&\u2028\"}" || strings.Contains(string(encoded), `\u003c`) {
		t.Fatalf("canonical JSON = %s", encoded)
	}
}

func TestMarshalCanonicalJSONRejectsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0xff})
	if _, err := marshalCanonicalJSON(map[string]any{"value": invalid}); err == nil {
		t.Fatal("marshalCanonicalJSON() accepted invalid UTF-8")
	}
}

func TestMarshalCanonicalJSONRejectsNumbersInDigestV1(t *testing.T) {
	if _, err := marshalCanonicalJSON(map[string]any{"number": 1}); err == nil {
		t.Fatal("marshalCanonicalJSON() accepted a numeric value")
	}
}
