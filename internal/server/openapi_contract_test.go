package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/api"
	"github.com/TommyAGK/elastic-maintenance/internal/auth"
	"github.com/TommyAGK/elastic-maintenance/internal/auth/authtest"
)

var openAPIPathParameter = regexp.MustCompile(`\{[^}]+\}`)

func TestOpenAPIOperationsAreRegisteredWithMatchingMethods(t *testing.T) {
	var document struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(api.OpenAPIDocument(), &document); err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(HandlerOptions{
		Authenticator: authtest.Authenticator{Actor: auth.Actor{
			Subject: "administrator-1",
			Roles:   []auth.Role{auth.RoleAdministrator},
		}},
	})

	var checked []string
	for path, pathItem := range document.Paths {
		for method := range pathItem {
			method = strings.ToUpper(method)
			if !isContractHTTPMethod(method) {
				continue
			}
			requestPath := openAPIPathParameter.ReplaceAllString(path, "fixture-1")
			request := httptest.NewRequest(method, requestPath, strings.NewReader(`{"confirm":true}`))
			if method == http.MethodPost || method == http.MethodPut || method == http.MethodDelete || method == http.MethodPatch {
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set(api.IdempotencyKeyHeader, "contract-request-1")
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code == http.StatusNotFound || response.Code == http.StatusMethodNotAllowed {
				t.Errorf("documented operation is not registered: %s %s returned %d", method, path, response.Code)
			}
			checked = append(checked, method+" "+path)
		}
	}
	sort.Strings(checked)
	if len(checked) != 27 {
		t.Fatalf("checked %d operations, want 27:\n%s", len(checked), strings.Join(checked, "\n"))
	}
}

func isContractHTTPMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}
