package kibana

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientEndpointTrimsTrailingSlash(t *testing.T) {
	cli := NewClient("http://example.com/", "k")
	if got := cli.endpoint("/api/test"); got != "http://example.com/api/test" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}

func TestGetJSONSurfacesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}))
	defer srv.Close()

	cli := NewClient(srv.URL, "k")
	var out map[string]any
	err := cli.getJSON(context.Background(), "/x", &out)
	if err == nil {
		t.Fatal("expected error")
	}
}
