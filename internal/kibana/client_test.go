package kibana

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientEndpointTrimsTrailingSlash(t *testing.T) {
	cli := NewClient("http://example.com/", "k")
	if got := cli.endpoint("/api/test"); got != "http://example.com/api/test" {
		t.Fatalf("unexpected endpoint: %s", got)
	}
}

func TestTargetResponseBodyIsBounded(t *testing.T) {
	body := &boundedResponseBody{ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", int(maxTargetResponseBytes)+1))), remaining: maxTargetResponseBytes}
	if _, err := io.ReadAll(body); !errors.Is(err, errTargetResponseTooLarge) {
		t.Fatalf("error=%v", err)
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
