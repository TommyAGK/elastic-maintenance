package kibana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

func TestTypedReadAdaptersDecodeBothContractVersions(t *testing.T) {
	fingerprints := map[string][]string{}
	for _, version := range []string{"v9.2.0", "v9.4.2"} {
		t.Run(version, func(t *testing.T) {
			requested := []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested = append(requested, r.URL.RequestURI())
				w.Header().Set("Content-Type", "application/json")
				if strings.HasSuffix(r.URL.Path, "/api/status") {
					w.Write([]byte(`{"version":{"number":"` + strings.TrimPrefix(version, "v") + `"}}`))
					return
				}
				fixture := ""
				switch {
				case strings.HasSuffix(r.URL.Path, "/api/fleet/epm/packages/endpoint/9.2.0"):
					fixture = "integration-package.json"
				case strings.HasSuffix(r.URL.Path, "/api/fleet/agent_policies/agent-policy-1"):
					fixture = "agent-policy.json"
				case strings.HasSuffix(r.URL.Path, "/api/fleet/package_policies/package-policy-1"):
					fixture = "package-policy.json"
				case strings.HasSuffix(r.URL.Path, "/api/detection_engine/rules") && r.URL.Query().Get("rule_id") == "managed-rule-1":
					fixture = "detection-rule.json"
				case strings.HasSuffix(r.URL.Path, "/api/detection_engine/rules/prepackaged/_status"):
					fixture = "prebuilt-status.json"
				default:
					http.NotFound(w, r)
					return
				}
				contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", version, fixture))
				if err != nil {
					t.Error(err)
					return
				}
				w.Write(contents)
			}))
			defer server.Close()
			client := NewClient(server.URL, "key")
			client.space = "security_ops"
			defer client.Close()
			integration, err := client.IntegrationPackage(context.Background(), "endpoint", "9.2.0")
			if err != nil {
				t.Fatal(err)
			}
			agent, err := client.AgentPolicy(context.Background(), "agent-policy-1")
			if err != nil {
				t.Fatal(err)
			}
			policy, err := client.PackagePolicy(context.Background(), "package-policy-1")
			if err != nil {
				t.Fatal(err)
			}
			rule, err := client.Rule(context.Background(), "managed-rule-1")
			if err != nil {
				t.Fatal(err)
			}
			prebuilt, err := client.PrebuiltStatus(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, integrationFingerprint, integrationErr := integration.Canonical()
			_, agentFingerprint, agentErr := agent.Canonical()
			policyProjection, policyFingerprint, policyErr := policy.Canonical()
			ruleProjection, ruleFingerprint, ruleErr := rule.Canonical()
			_, prebuiltFingerprint, prebuiltErr := prebuilt.Canonical()
			if integrationErr != nil || agentErr != nil || policyErr != nil || ruleErr != nil || prebuiltErr != nil {
				t.Fatalf("canonical errors: %v %v %v %v %v", integrationErr, agentErr, policyErr, ruleErr, prebuiltErr)
			}
			fingerprints[version] = []string{integrationFingerprint.Value, agentFingerprint.Value, policyFingerprint.Value, ruleFingerprint.Value, prebuiltFingerprint.Value}
			if !reflect.DeepEqual(policyProjection.AgentPolicyIDs, []string{"agent-policy-1"}) || !reflect.DeepEqual(ruleProjection.Index, []string{"logs-*"}) {
				t.Fatal("canonical projection mismatch")
			}
			if !strings.Contains(string(rule.Baseline()), `"actions"`) || !strings.Contains(string(policy.Baseline()), `"inputs"`) {
				t.Fatal("complete-update baseline was not preserved")
			}
			for _, request := range requested[1:] {
				if !strings.Contains(request, "/s/security_ops/") {
					t.Fatalf("unscoped adapter request %q", request)
				}
			}
		})
	}
	if !reflect.DeepEqual(fingerprints["v9.2.0"], fingerprints["v9.4.2"]) {
		t.Fatalf("fingerprints differ: %#v", fingerprints)
	}
}

func TestCanonicalLiveJSONUsesRFCKeyOrdering(t *testing.T) {
	encoded, err := marshalLiveCanonicalJSON(struct {
		Z string `json:"z"`
		A string `json:"a"`
	}{Z: "last", A: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"a":"first","z":"last"}` {
		t.Fatalf("canonical=%s", encoded)
	}
}

func TestLiveFingerprintGoldenVector(t *testing.T) {
	fingerprint, err := liveFingerprint("integration-package", IntegrationPackageProjection{Name: "endpoint", Version: "9.2.0"})
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint.Value != "3f1c3603bd3b3a4ac16ca0bf599e7af75489c89e9367e8a59a3854d27ebb7845" {
		t.Fatalf("fingerprint=%s", fingerprint.Value)
	}
}

func TestCanonicalFingerprintsExcludeServerManagedDrift(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "detection-rule.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rule Rule
	if err := json.Unmarshal(contents, &rule); err != nil {
		t.Fatal(err)
	}
	projection, first, err := rule.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	rule.Revision = 999
	rule.Version = 999
	rule.ID = "different-server-id"
	var baseline map[string]any
	if json.Unmarshal(rule.Baseline(), &baseline) != nil {
		t.Fatal("baseline decode")
	}
	baseline["serverManaged"] = "changed"
	rule.updateBaseline, _ = json.Marshal(baseline)
	secondProjection, second, err := rule.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projection, secondProjection) || first != second {
		t.Fatalf("server drift changed canonical fingerprint")
	}
	rule.Query = "event.kind:alert"
	_, changed, _ := rule.Canonical()
	if changed.Value == first.Value {
		t.Fatal("managed query change did not alter fingerprint")
	}
}

func TestRuleListSkipsUnsupportedAndImmutableRules(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "detection-rules-page-1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var page map[string]any
	if json.Unmarshal(fixture, &page) != nil {
		t.Fatal("fixture decode")
	}
	data := page["data"].([]any)
	data = append(data, map[string]any{"rule_id": "prebuilt", "name": "Prebuilt", "type": "query", "immutable": true}, map[string]any{"rule_id": "threshold", "name": "Threshold", "type": "threshold", "immutable": false})
	page["data"] = data
	page["total"] = 3
	page["perPage"] = 3
	encoded, _ := json.Marshal(page)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		w.Write(encoded)
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	rules, err := client.Rules(context.Background())
	if err != nil || len(rules) != 3 || rules[0].RuleID != "managed-rule-1" || !rules[0].Manageable || rules[1].Manageable || rules[2].Manageable {
		t.Fatalf("rules=%#v error=%v", rules, err)
	}
}

func TestRuleCanonicalMatchesManifestBoundaries(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "detection-rule.json"))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Rule){"empty-index": func(rule *Rule) { rule.Index = []string{} }, "too-many-indexes": func(rule *Rule) {
		rule.Index = make([]string, 1025)
		for index := range rule.Index {
			rule.Index[index] = fmt.Sprintf("index-%d", index)
		}
	}, "long-index": func(rule *Rule) { rule.Index = []string{strings.Repeat("x", 257)} }, "control-query": func(rule *Rule) { rule.Query = "query\u202e" }, "long-interval": func(rule *Rule) { rule.Interval = strings.Repeat("9", 129) + "m" }}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var rule Rule
			if json.Unmarshal(contents, &rule) != nil {
				t.Fatal("decode")
			}
			mutate(&rule)
			if _, _, err := rule.Canonical(); !isAdapterProtocolError(err) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestAdapterRejectsNormalizedDuplicates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		w.Write([]byte(`{"items":[{"name":"Endpoint","version":"9.2.0","status":"installed"},{"name":"endpoint","version":"9.1.0","status":"installed"}],"total":2}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	if _, err := client.InstalledPackages(context.Background()); !isAdapterProtocolError(err) {
		t.Fatalf("error=%v", err)
	}
}

func TestRuleMutationsPreflightEntireBatch(t *testing.T) {
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		if r.Method != http.MethodGet {
			mutations++
			w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Write([]byte(`{"data":[],"page":1,"perPage":100,"total":0}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	valid := config.Rule{RuleID: "rule-one", Name: "Rule one", Type: "query", Query: "event.kind:event", Severity: "low", Interval: "5m", Language: "kuery", Index: "logs-*"}
	invalid := valid
	invalid.RuleID = ""
	if _, err := client.EnsureRules([]config.Rule{valid, invalid}); !errors.Is(err, ErrResourceNotManageable) {
		t.Fatalf("error=%v", err)
	}
	if mutations != 0 {
		t.Fatalf("mutations=%d", mutations)
	}
}

func TestLegacyMutationHelpersRefuseUnmanagedCollisions(t *testing.T) {
	packageFixture, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "package-policies-page-1.json"))
	packageFixture = []byte(strings.Replace(strings.Replace(string(packageFixture), "[managed-by:elastic-maintainer] fixture", "[managed-by:elastic-maintainer]forged", 1), `"total": 2`, `"total": 1`, 1))
	ruleFixture, _ := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "detection-rules-page-1.json"))
	ruleFixture = []byte(strings.Replace(strings.Replace(string(ruleFixture), "elastic-maintainer:managed", "elastic-maintainer:managed-forged", 1), `"total": 2`, `"total": 1`, 1))
	mutations := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		if r.Method != http.MethodGet {
			mutations++
			w.Write([]byte(`{"ok":true}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/api/fleet/package_policies") {
			w.Write(packageFixture)
			return
		}
		w.Write(ruleFixture)
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	if _, err := client.EnsureFleetPolicies([]config.FleetPolicy{{Name: "endpoint-policy"}}); !errors.Is(err, ErrResourceNotManageable) {
		t.Fatalf("package error=%v", err)
	}
	if _, err := client.EnsureRules([]config.Rule{{RuleID: "managed-rule-1", Name: "Managed fixture rule", Type: "query", Query: "event.kind:event", Severity: "low", Interval: "5m", Language: "kuery", Index: "logs-*"}}); !errors.Is(err, ErrResourceNotManageable) {
		t.Fatalf("rule error=%v", err)
	}
	if mutations != 0 {
		t.Fatalf("mutations=%d", mutations)
	}
}

func TestAdaptersRejectInvalidUTF8AndLoneSurrogates(t *testing.T) {
	for name, contents := range map[string][]byte{"invalid-utf8": append([]byte(`{"rule_id":"rule","name":"`), 0xff, '"', '}'), "lone-surrogate": []byte(`{"rule_id":"rule","name":"\ud800"}`)} {
		t.Run(name, func(t *testing.T) {
			var rule Rule
			if err := json.Unmarshal(contents, &rule); err == nil {
				t.Fatal("invalid wire string accepted")
			}
		})
	}
}

func TestBaselineAccessIsDefensivelyCloned(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "contracts", "kibana", "v9.2.0", "agent-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		Item AgentPolicy `json:"item"`
	}
	if json.Unmarshal(contents, &envelope) != nil {
		t.Fatal("decode")
	}
	first := envelope.Item.Baseline()
	first[0] = 'X'
	second := envelope.Item.Baseline()
	if len(second) == 0 || second[0] == 'X' {
		t.Fatal("baseline accessor exposed mutable backing storage")
	}
}

func TestAdapterReadsRejectIdentityMismatchAndUnsafeInputs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/api/status") {
			w.Write([]byte(`{"version":{"number":"9.4.2"}}`))
			return
		}
		w.Write([]byte(`{"item":{"name":"other","version":"9.2.0","status":"installed"}}`))
	}))
	defer server.Close()
	client := NewClient(server.URL, "key")
	defer client.Close()
	if _, err := client.IntegrationPackage(context.Background(), "endpoint", "9.2.0"); !isAdapterProtocolError(err) {
		t.Fatalf("identity error=%v", err)
	}
	for _, input := range []string{"../escape", "value/escape", "value?query", ""} {
		if _, err := client.AgentPolicy(context.Background(), input); err == nil {
			t.Errorf("unsafe id %q accepted", input)
		}
	}
}

func isAdapterProtocolError(err error) bool {
	remote, ok := err.(*ResponseError)
	return ok && remote.Kind() == ErrorProtocol
}
