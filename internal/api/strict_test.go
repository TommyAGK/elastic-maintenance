package api

import (
	"net/url"
	"strings"
	"testing"
)

func TestDecodeStrictJSONRejectsNullAliasesAndDuplicates(t *testing.T) {
	tests := []string{
		`null`,
		`{"targetIds":null}`,
		`{"targetIds":[null]}`,
		`{"TargetIds":[]}`,
		`{"target\u0049ds":[]}`,
		`{"targetIds":[],"targetIds":[]}`,
	}
	for _, input := range tests {
		var request ValidationCreateRequest
		if err := DecodeStrictJSON(strings.NewReader(input), &request); err == nil {
			t.Errorf("DecodeStrictJSON(%s) error = nil", input)
		}
	}
}

func TestPaginationTokensAreBoundedCanonicalAndEndpointScoped(t *testing.T) {
	value := strings.Repeat("nested/", 1000) + "resource.yaml"
	token := PageToken("source-files:source", value)
	if len(token) > 512 {
		t.Fatalf("token length = %d", len(token))
	}
	_, cursor, err := ParsePagination(url.Values{"pageToken": []string{token}}, "source-files:source")
	if err != nil || !PageCursorMatches("source-files:source", value, cursor) {
		t.Fatalf("ParsePagination() = %q, %v", cursor, err)
	}
	if PageCursorMatches("other", value, cursor) {
		t.Fatal("cursor matched another endpoint")
	}
	if _, _, err := ParsePagination(url.Values{"pageToken": []string{token + "="}}, "source-files:source"); err == nil {
		t.Fatal("noncanonical token accepted")
	}
	if _, _, err := ParsePagination(url.Values{"pageToken": []string{strings.Repeat("a", 513)}}, "source-files:source"); err == nil {
		t.Fatal("oversized token accepted")
	}
}
