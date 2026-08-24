package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestContractFixturePaginationForSupportedVersions(t *testing.T) {
	for _, version := range []string{"v9.2.0", "v9.4.2"} {
		t.Run(version, func(t *testing.T) {
			var mu sync.Mutex
			requests := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				requests = append(requests, r.URL.RequestURI())
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/api/status") {
					w.Write([]byte(`{"version":{"number":"` + strings.TrimPrefix(version, "v") + `"}}`))
					return
				}
				fixture := ""
				page := r.URL.Query().Get("page")
				switch r.URL.Path {
				case "/api/fleet/epm/packages/installed":
					if r.URL.Query().Get("searchAfter") == "" {
						fixture = "installed-packages-page-1.json"
					} else {
						var cursor []string
						if json.Unmarshal([]byte(r.URL.Query().Get("searchAfter")), &cursor) != nil || len(cursor) != 2 {
							t.Errorf("cursor=%q", r.URL.Query().Get("searchAfter"))
						}
						fixture = "installed-packages-page-2.json"
					}
				case "/api/fleet/agent_policies":
					fixture = "agent-policies-page-" + page + ".json"
				case "/api/fleet/package_policies":
					fixture = "package-policies-page-" + page + ".json"
				case "/api/detection_engine/rules/_find":
					fixture = "detection-rules-page-" + page + ".json"
				default:
					http.NotFound(w, r)
					return
				}
				contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", version, fixture))
				if err != nil {
					t.Error(err)
					w.WriteHeader(500)
					return
				}
				w.Write(contents)
			}))
			defer server.Close()
			client := NewClient(server.URL, "test-key")
			defer client.Close()
			packages, err := client.InstalledPackages(context.Background())
			if err != nil || len(packages) != 2 {
				t.Fatalf("packages=%d error=%v", len(packages), err)
			}
			agents, err := client.AgentPolicies(context.Background())
			if err != nil || len(agents) != 2 {
				t.Fatalf("agents=%d error=%v", len(agents), err)
			}
			policies, err := client.PackagePolicies(context.Background())
			if err != nil || len(policies) != 2 {
				t.Fatalf("policies=%d error=%v", len(policies), err)
			}
			rules, err := client.Rules(context.Background())
			if err != nil || len(rules) != 2 || len(rules[0].Index) != 1 {
				t.Fatalf("rules=%d error=%v", len(rules), err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 9 {
				t.Fatalf("requests=%v", requests)
			}
		})
	}
}

func TestSpaceAwarePathsAndVersionProbeRemainSeparate(t *testing.T) {
	paths := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.2.0"}}`))
			return
		}
		w.Write([]byte(`{"items":[],"page":1,"perPage":100,"total":0}`))
	}))
	defer server.Close()
	client := NewClient(server.URL+"/base", "key")
	client.space = "security_ops"
	defer client.Close()
	if _, err := client.PackagePolicies(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "/base/api/status,/base/s/security_ops/api/fleet/package_policies" {
		t.Fatalf("paths=%v", paths)
	}
}

func TestVersionCompatibilityFailsClosed(t *testing.T) {
	for _, version := range []string{"9.1.9", "10.0.0", "9.4.2-SNAPSHOT", "", "garbage"} {
		t.Run(version, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"version":{"number":` + strconv.Quote(version) + `}}`))
			}))
			defer server.Close()
			client := NewClient(server.URL, "key")
			defer client.Close()
			err := client.EnsureCompatible(context.Background())
			var remote *ResponseError
			if !errors.As(err, &remote) || remote.Kind() != ErrorProtocol {
				t.Fatalf("version=%q error=%v", version, err)
			}
		})
	}
}

func TestReadRetryIsNarrowAndMutationNeverRetries(t *testing.T) {
	reads, writes := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("kbn-xsrf") != "" {
				t.Error("read sent kbn-xsrf")
			}
			reads++
			if reads == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				w.Write([]byte(`{"message":"credential-sentinel"}`))
				return
			}
			w.Write([]byte(`{"items":[],"total":0}`))
			return
		}
		writes++
		if r.Header.Get("kbn-xsrf") != "elastic-maintenance" {
			t.Error("mutation omitted kbn-xsrf")
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"message":"credential-sentinel"}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	client.retryWait = func(context.Context, time.Duration) error { return nil }
	defer client.Close()
	if _, err := client.InstalledPackages(context.Background()); err != nil || reads != 2 {
		t.Fatalf("reads=%d error=%v", reads, err)
	}
	err := client.postJSON(context.Background(), "/api/fleet/package_policies", map[string]string{"name": "x"}, nil)
	if err == nil || writes != 1 || strings.Contains(err.Error(), "sentinel") {
		t.Fatalf("writes=%d error=%v", writes, err)
	}
}

func TestEveryContractErrorFixtureIsSafelyClassified(t *testing.T) {
	cases := map[int]ErrorKind{401: ErrorAuthentication, 403: ErrorAuthorization, 404: ErrorNotFound, 409: ErrorConflict, 429: ErrorThrottled, 500: ErrorServer}
	for _, version := range []string{"v9.2.0", "v9.4.2"} {
		for status, kind := range cases {
			contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", version, "error-"+strconv.Itoa(status)+".json"))
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				w.Write(contents)
			}))
			client := NewClient(server.URL, "key")
			client.retryWait = func(context.Context, time.Duration) error { return nil }
			err = client.requestJSON(context.Background(), http.MethodGet, "/fixture", nil, &map[string]any{}, true)
			client.Close()
			server.Close()
			var remote *ResponseError
			if !errors.As(err, &remote) || remote.Kind() != kind || strings.Contains(err.Error(), "Request throttled") {
				t.Fatalf("version=%s status=%d error=%v", version, status, err)
			}
		}
	}
}

func TestRemoteErrorClassificationUsesNoRemoteBody(t *testing.T) {
	cases := map[int]ErrorKind{401: ErrorAuthentication, 403: ErrorAuthorization, 404: ErrorNotFound, 409: ErrorConflict, 429: ErrorThrottled, 500: ErrorServer}
	for status, kind := range cases {
		response := &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"message":"credential-sentinel"}`))}
		remote := classifyResponse(response)
		if remote.Kind() != kind || strings.Contains(remote.Error(), "sentinel") {
			t.Errorf("status=%d kind=%s error=%v", status, remote.Kind(), remote)
		}
	}
}

func TestSuccessfulMutationRequiresJSONProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	err := client.requestJSON(context.Background(), http.MethodPost, "/mutation", map[string]string{"name": "x"}, nil, true)
	var remote *ResponseError
	if !errors.As(err, &remote) || remote.Kind() != ErrorProtocol {
		t.Fatalf("error=%v", err)
	}
}

func TestProtocolAndContextFailuresAreBounded(t *testing.T) {
	for name, contentType := range map[string][2]string{"wrong-content-type": {"text/plain", `{"items":[]}`}, "trailing-json": {"application/json", `{"items":[]} {}`}, "malformed": {"application/json", `{"items":`}} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType[0])
				w.Write([]byte(contentType[1]))
			}))
			defer server.Close()
			client := NewClient(server.URL, "key")
			defer client.Close()
			var output map[string]any
			err := client.requestJSON(context.Background(), http.MethodGet, "/fixture", nil, &output, true)
			var remote *ResponseError
			if !errors.As(err, &remote) || remote.Kind() != ErrorProtocol {
				t.Fatalf("error=%v", err)
			}
		})
	}
	client := NewClient("http://127.0.0.1:1", "key")
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.requestJSON(ctx, http.MethodGet, "/fixture", nil, &map[string]any{}, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestTerminalCursorValidationAndPageBounds(t *testing.T) {
	cases := map[string][]string{"oversized-terminal": {`{"items":[],"searchAfter":["` + strings.Repeat("x", 5000) + `"],"total":0}`}, "repeated-terminal": {`{"items":[{"name":"one"}],"searchAfter":["a"],"total":3}`, `{"items":[{"name":"two"}],"searchAfter":["b"],"total":3}`, `{"items":[{"name":"three"}],"searchAfter":["a"],"total":3}`}, "oversized-page": {`{"items":` + string(mustJSON(t, make([]InstalledPackage, listPageSize+1))) + `,"total":101}`}}
	for name, responses := range cases {
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/api/status") {
					w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
					return
				}
				index := calls
				if index >= len(responses) {
					index = len(responses) - 1
				}
				calls++
				w.Write([]byte(responses[index]))
			}))
			defer server.Close()
			client := NewClient(server.URL, "key")
			defer client.Close()
			if _, err := client.InstalledPackages(context.Background()); !isPaginationError(err) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPaginationRequiresStablePresentTotals(t *testing.T) {
	for name, responses := range map[string][]string{"missing-total": {`{"items":[]}`}, "changing-total": {`{"items":[{"id":"one"}],"page":1,"perPage":100,"total":2}`, `{"items":[],"page":2,"perPage":100,"total":3}`}} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/api/status") {
					w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
					return
				}
				index := calls
				if index >= len(responses) {
					index = len(responses) - 1
				}
				calls++
				w.Write([]byte(responses[index]))
			}))
			defer server.Close()
			client := NewClient(server.URL, "key")
			defer client.Close()
			if _, err := client.PackagePolicies(context.Background()); !isPaginationError(err) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestPaginationRejectsRepeatedCursorAndInconsistentTotals(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		w.Write([]byte(`{"items":[],"searchAfter":["same"],"total":1}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	if _, err := client.InstalledPackages(context.Background()); !isPaginationError(err) {
		t.Fatalf("error=%v", err)
	}
}
