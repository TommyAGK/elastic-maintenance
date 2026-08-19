package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var pathParameterPattern = regexp.MustCompile(`\{([^}]+)\}`)

func TestOpenAPIContractStructureAndReferences(t *testing.T) {
	document := openAPITestDocument(t)
	if document["openapi"] != "3.0.3" {
		t.Fatalf("openapi = %#v", document["openapi"])
	}

	operationIDs := map[string]string{}
	paths := objectAt(t, document, "paths")
	for path, rawPathItem := range paths {
		pathItem := rawPathItem.(map[string]any)
		for method, rawOperation := range pathItem {
			if !isHTTPMethod(method) {
				continue
			}
			operation := rawOperation.(map[string]any)
			operationID, ok := operation["operationId"].(string)
			if !ok || operationID == "" {
				t.Errorf("%s %s has no operationId", strings.ToUpper(method), path)
			} else if previous, duplicate := operationIDs[operationID]; duplicate {
				t.Errorf("operationId %q is shared by %s and %s %s", operationID, previous, strings.ToUpper(method), path)
			} else {
				operationIDs[operationID] = strings.ToUpper(method) + " " + path
			}
			if responses, ok := operation["responses"].(map[string]any); !ok || len(responses) == 0 {
				t.Errorf("%s %s has no responses", strings.ToUpper(method), path)
			}
			assertPathParameters(t, document, path, operation)
		}
	}

	walkJSON(document, func(location string, value any) {
		object, ok := value.(map[string]any)
		if !ok {
			return
		}
		if reference, ok := object["$ref"].(string); ok {
			if _, err := resolveLocalReference(document, reference); err != nil {
				t.Errorf("%s: %v", location, err)
			}
		}
	})
}

func TestOpenAPICoversInitialWebFirstSurface(t *testing.T) {
	document := openAPITestDocument(t)
	paths := objectAt(t, document, "paths")
	required := []string{
		"/health/live",
		"/health/ready",
		"/auth/login",
		"/auth/callback",
		"/auth/logout",
		"/api/v1/openapi.json",
		"/api/v1/session",
		"/api/v1/sources",
		"/api/v1/sources/{sourceId}",
		"/api/v1/targets",
		"/api/v1/targets/{targetId}",
		"/api/v1/targets/{targetId}/credential-status",
		"/api/v1/targets/{targetId}/credentials",
		"/api/v1/validations",
		"/api/v1/validations/{jobId}",
		"/api/v1/plans",
		"/api/v1/plans/{planId}",
		"/api/v1/plans/{planId}/apply",
		"/api/v1/jobs",
		"/api/v1/jobs/{jobId}",
		"/api/v1/reports",
		"/api/v1/reports/{reportId}",
		"/api/v1/audit",
	}
	for _, path := range required {
		if _, ok := paths[path]; !ok {
			t.Errorf("OpenAPI path is missing: %s", path)
		}
	}
}

func TestOpenAPIUnfinishedRoutesAreExplicit(t *testing.T) {
	document := openAPITestDocument(t)
	paths := objectAt(t, document, "paths")
	implemented := map[string]bool{
		"GET /health/live": true, "GET /health/ready": true, "GET /auth/login": true, "GET /auth/callback": true, "POST /auth/logout": true, "GET /api/v1/openapi.json": true, "GET /api/v1/session": true,
		"GET /api/v1/sources": true, "GET /api/v1/sources/{sourceId}": true,
		"GET /api/v1/targets": true, "GET /api/v1/targets/{targetId}": true,
		"GET /api/v1/validations": true, "POST /api/v1/validations": true, "GET /api/v1/validations/{jobId}": true,
	}
	for path, rawPathItem := range paths {
		for method, rawOperation := range rawPathItem.(map[string]any) {
			if !isHTTPMethod(method) {
				continue
			}
			operation := strings.ToUpper(method) + " " + path
			responses := rawOperation.(map[string]any)["responses"].(map[string]any)
			_, hasNotImplemented := responses["501"]
			if implemented[operation] && hasNotImplemented {
				t.Errorf("implemented operation %s still documents 501", operation)
			}
			if !implemented[operation] && !hasNotImplemented {
				t.Errorf("unfinished operation %s does not document 501", operation)
			}
		}
	}
}

func TestOpenAPIResponseSchemasAreVersioned(t *testing.T) {
	document := openAPITestDocument(t)
	schemas := objectAt(t, objectAt(t, document, "components"), "schemas")
	for name, rawSchema := range schemas {
		if !strings.HasSuffix(name, "Response") && name != "ErrorEnvelope" {
			continue
		}
		schema := rawSchema.(map[string]any)
		required := stringSet(schema["required"])
		if !required["apiVersion"] {
			t.Errorf("response schema %s does not require apiVersion", name)
		}
		properties, _ := schema["properties"].(map[string]any)
		if _, ok := properties["apiVersion"]; !ok {
			t.Errorf("response schema %s has no apiVersion property", name)
		}
	}
}

func TestOpenAPICredentialValuesAreWriteOnlyAndAbsentFromResponses(t *testing.T) {
	document := openAPITestDocument(t)
	schemas := objectAt(t, objectAt(t, document, "components"), "schemas")
	credentialRequest := schemas["CredentialPutRequest"].(map[string]any)
	properties := credentialRequest["properties"].(map[string]any)
	for _, name := range []string{"apiKey", "caCertificatePem"} {
		property := properties[name].(map[string]any)
		if property["writeOnly"] != true {
			t.Errorf("CredentialPutRequest.%s is not writeOnly", name)
		}
	}

	reachable := responseReachableValues(t, document)
	encoded, err := json.Marshal(reachable)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"\"apiKey\"", "\"caCertificatePem\"", "PRIVATE KEY", "Authorization: ApiKey", "Authorization: Bearer"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("response-reachable OpenAPI content contains forbidden credential material %q", forbidden)
		}
	}

	walkJSON(document, func(location string, value any) {
		object, ok := value.(map[string]any)
		if !ok {
			return
		}
		for _, key := range []string{"example", "examples"} {
			if example, exists := object[key]; exists {
				encoded, _ := json.Marshal(example)
				for _, forbidden := range []string{"PRIVATE KEY", "ApiKey ", "Bearer ", "api_key"} {
					if strings.Contains(string(encoded), forbidden) {
						t.Errorf("%s.%s contains credential-like example material", location, key)
					}
				}
			}
		}
	})
}

func openAPITestDocument(t *testing.T) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(OpenAPIDocument(), &document); err != nil {
		t.Fatalf("OpenAPI document is invalid JSON: %v", err)
	}
	return document
}

func objectAt(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", key)
	}
	return value
}

func isHTTPMethod(value string) bool {
	switch value {
	case "get", "post", "put", "patch", "delete", "head", "options":
		return true
	default:
		return false
	}
}

func assertPathParameters(t *testing.T, document map[string]any, path string, operation map[string]any) {
	t.Helper()
	want := map[string]bool{}
	for _, match := range pathParameterPattern.FindAllStringSubmatch(path, -1) {
		want[match[1]] = true
	}
	got := map[string]bool{}
	parameters, _ := operation["parameters"].([]any)
	for _, rawParameter := range parameters {
		parameter := rawParameter.(map[string]any)
		if reference, ok := parameter["$ref"].(string); ok {
			resolved, err := resolveLocalReference(document, reference)
			if err != nil {
				t.Errorf("%s: %v", path, err)
				continue
			}
			parameter = resolved.(map[string]any)
		}
		if parameter["in"] == "path" {
			name, _ := parameter["name"].(string)
			got[name] = true
			if parameter["required"] != true {
				t.Errorf("path parameter %s on %s is not required", name, path)
			}
		}
	}
	if fmt.Sprint(sortedKeys(want)) != fmt.Sprint(sortedKeys(got)) {
		t.Errorf("path parameter mismatch on %s: template=%v declared=%v", path, sortedKeys(want), sortedKeys(got))
	}
}

func resolveLocalReference(document map[string]any, reference string) (any, error) {
	if !strings.HasPrefix(reference, "#/") {
		return nil, fmt.Errorf("only local references are allowed: %s", reference)
	}
	var current any = document
	for _, rawPart := range strings.Split(strings.TrimPrefix(reference, "#/"), "/") {
		part := strings.ReplaceAll(strings.ReplaceAll(rawPart, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("reference traverses non-object: %s", reference)
		}
		current, ok = object[part]
		if !ok {
			return nil, fmt.Errorf("unresolved reference: %s", reference)
		}
	}
	return current, nil
}

func walkJSON(value any, visit func(string, any)) {
	var walk func(string, any)
	walk = func(location string, current any) {
		visit(location, current)
		switch typed := current.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				walk(location+"."+key, typed[key])
			}
		case []any:
			for index, child := range typed {
				walk(fmt.Sprintf("%s[%d]", location, index), child)
			}
		}
	}
	walk("$", value)
}

func responseReachableValues(t *testing.T, document map[string]any) []any {
	t.Helper()
	var roots []any
	paths := objectAt(t, document, "paths")
	for _, rawPathItem := range paths {
		for method, rawOperation := range rawPathItem.(map[string]any) {
			if isHTTPMethod(method) {
				roots = append(roots, rawOperation.(map[string]any)["responses"])
			}
		}
	}
	components := objectAt(t, document, "components")
	roots = append(roots, components["responses"])

	seenReferences := map[string]bool{}
	for index := 0; index < len(roots); index++ {
		walkJSON(roots[index], func(_ string, value any) {
			object, ok := value.(map[string]any)
			if !ok {
				return
			}
			reference, ok := object["$ref"].(string)
			if !ok || seenReferences[reference] {
				return
			}
			seenReferences[reference] = true
			resolved, err := resolveLocalReference(document, reference)
			if err != nil {
				t.Errorf("%v", err)
				return
			}
			roots = append(roots, resolved)
		})
	}
	return roots
}

func stringSet(value any) map[string]bool {
	result := map[string]bool{}
	values, _ := value.([]any)
	for _, raw := range values {
		if item, ok := raw.(string); ok {
			result[item] = true
		}
	}
	return result
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
