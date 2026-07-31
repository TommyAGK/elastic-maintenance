package mockkibana

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type Server struct {
	mu sync.Mutex
	server *httptest.Server
	InstalledPackages []InstalledPackage
	PackagePolicies []PackagePolicy
	Rules []Rule
	Requests []string
}

type InstalledPackage struct { Name, Version string }
type PackagePolicy struct { ID, Name, Namespace string }
type Rule struct { ID, RuleID, Name, Type, Query, Index string; Enabled bool }

func New() *Server {
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/fleet/epm/packages", s.handlePackages)
	mux.HandleFunc("/api/fleet/package_policies", s.handlePackagePolicies)
	mux.HandleFunc("/api/detection_engine/rules/_find", s.handleRulesFind)
	mux.HandleFunc("/api/fleet/epm/packages/", s.handleInstallPackage)
	mux.HandleFunc("/api/detection_engine/rules", s.handleRules)
	s.server = httptest.NewServer(mux)
	return s
}

func (s *Server) URL() string { return s.server.URL }
func (s *Server) Close() { if s.server != nil { s.server.Close() } }

func (s *Server) record(r *http.Request) {
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
}

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.record(r)
	writeJSON(w, map[string]any{"items": s.InstalledPackages})
}

func (s *Server) handlePackagePolicies(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.record(r)
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]any{"items": s.PackagePolicies})
	case http.MethodPost:
		var req struct { Name, Namespace string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.PackagePolicies = append(s.PackagePolicies, PackagePolicy{Name: req.Name, Namespace: req.Namespace})
		writeJSON(w, map[string]any{"item": req})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesFind(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.record(r)
	writeJSON(w, map[string]any{"data": s.Rules})
}

func (s *Server) handleInstallPackage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.record(r)
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/fleet/epm/packages/"), "/")
	if len(parts) >= 2 {
		s.InstalledPackages = append(s.InstalledPackages, InstalledPackage{Name: parts[0], Version: parts[1]})
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock(); defer s.mu.Unlock()
	s.record(r)
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	var req struct { RuleID, Name, Type, Query, Index string; Enabled bool }
	_ = json.NewDecoder(r.Body).Decode(&req)
	s.Rules = append(s.Rules, Rule{RuleID: req.RuleID, Name: req.Name, Type: req.Type, Query: req.Query, Index: req.Index, Enabled: req.Enabled})
	writeJSON(w, map[string]any{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
