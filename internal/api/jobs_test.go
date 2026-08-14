package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdempotencyKey(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans", nil)
	request.Header.Set(IdempotencyKeyHeader, "plan-request-1")
	got, err := IdempotencyKey(request)
	if err != nil || got != "plan-request-1" {
		t.Fatalf("IdempotencyKey() = %q, %v", got, err)
	}
}

func TestIdempotencyKeyRejectsMissingOrUnsafeValues(t *testing.T) {
	for _, value := range []string{"", "short", "contains secret value", "line\nfeed"} {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/plans", nil)
		if value != "" {
			request.Header.Set(IdempotencyKeyHeader, value)
		}
		if _, err := IdempotencyKey(request); err == nil {
			t.Errorf("IdempotencyKey(%q) error = nil", value)
		}
	}
	if _, err := IdempotencyKey(nil); err == nil {
		t.Fatal("IdempotencyKey(nil) error = nil")
	}
}
