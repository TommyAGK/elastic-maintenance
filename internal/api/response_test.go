package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteError(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/example", nil)
	WriteError(response, request, http.StatusUnauthorized, "authentication_required", "authentication is required", "request-1")

	if response.Code != http.StatusUnauthorized || response.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status=%d content-type=%q", response.Code, response.Header().Get("Content-Type"))
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Error.Code != "authentication_required" || envelope.Error.Message != "authentication is required" || envelope.Error.RequestID != "request-1" {
		t.Fatalf("envelope = %#v", envelope)
	}
}

func TestWriteJSONSuppressesHEADBody(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodHead, "/health/live", nil)
	WriteJSON(response, request, http.StatusOK, map[string]string{"status": "live"})
	if response.Code != http.StatusOK || response.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestOpenAPIDocumentIsValidAndCopied(t *testing.T) {
	first := OpenAPIDocument()
	var document map[string]any
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatalf("OpenAPIDocument() invalid JSON: %v", err)
	}
	if document["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %#v", document["openapi"])
	}
	first[0] = 'x'
	second := OpenAPIDocument()
	if second[0] == 'x' {
		t.Fatal("OpenAPIDocument returned mutable shared storage")
	}
}
