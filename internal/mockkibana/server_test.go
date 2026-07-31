package mockkibana

import (
	"net/http"
	"testing"
)

func TestServerHandlesCRUDPaths(t *testing.T) {
	srv := New()
	defer srv.Close()

	if got := len(srv.Requests); got != 0 {
		t.Fatalf("expected no requests, got %d", got)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL()+"/api/fleet/epm/packages", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET packages failed: %v", err)
	}
	_ = resp.Body.Close()
	if len(srv.Requests) != 1 {
		t.Fatalf("expected recorded request, got %#v", srv.Requests)
	}
}
