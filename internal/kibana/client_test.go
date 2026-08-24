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

func TestPackageInstallRequiresExactSemanticVersion(t *testing.T) {
	client := NewClient("http://127.0.0.1:1", "key")
	defer client.Close()
	for _, version := range []string{"", "latest", "1.2", "01.2.3", "1.2.3-SNAPSHOT"} {
		if err := client.installPackage(context.Background(), "endpoint", version); err == nil {
			t.Errorf("version %q accepted", version)
		}
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
