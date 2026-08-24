package mockkibana

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

type Server struct {
	mu                sync.Mutex
	server            *httptest.Server
	InstalledPackages []InstalledPackage
	PackagePolicies   []PackagePolicy
	Rules             []Rule
	Requests          []string
}

type InstalledPackage struct{ Name, Version string }

type PackagePolicy struct{ ID, Name, Namespace string }

type Rule struct {
	ID, RuleID, Name, Type, Query, Index string
	Enabled                              bool
}

func New() *Server {
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{"version": map[string]any{"number": "9.4.2"}})
	})
	mux.HandleFunc("/api/fleet/epm/packages/installed", s.handlePackages)
	mux.HandleFunc("/api/fleet/epm/packages", s.handlePackages)
	mux.HandleFunc("/api/fleet/package_policies", s.handlePackagePolicies)
	mux.HandleFunc("/api/fleet/package_policies/", s.handlePackagePoliciesByID)
	mux.HandleFunc("/api/detection_engine/rules/_find", s.handleRulesFind)
	mux.HandleFunc("/api/fleet/epm/packages/", s.handleInstallPackage)
	mux.HandleFunc("/api/detection_engine/rules/", s.handleRulesByID)
	mux.HandleFunc("/api/detection_engine/rules", s.handleRules)
	s.server = httptest.NewServer(mux)
	return s
}

func (s *Server) URL() string { return s.server.URL }
func (s *Server) Close() {
	if s.server != nil {
		s.server.Close()
	}
}

func (s *Server) record(r *http.Request) {
	s.Requests = append(s.Requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
}

func (s *Server) handlePackages(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	items := s.InstalledPackages
	if items == nil {
		items = []InstalledPackage{}
	}
	writeJSON(w, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handlePackagePolicies(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	switch r.Method {
	case http.MethodGet:
		items := s.PackagePolicies
		if items == nil {
			items = []PackagePolicy{}
		}
		writeJSON(w, map[string]any{"items": items, "page": 1, "perPage": 100, "total": len(items)})
	case http.MethodPost:
		var req struct{ Name, Namespace string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		item := PackagePolicy{ID: req.Name, Name: req.Name, Namespace: req.Namespace}
		s.PackagePolicies = append(s.PackagePolicies, item)
		writeJSON(w, map[string]any{"item": item})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePackagePoliciesByID(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/fleet/package_policies/"), "/")
	id := parts[0]
	var req struct{ Name, Namespace string }
	_ = json.NewDecoder(r.Body).Decode(&req)
	for i := range s.PackagePolicies {
		if s.PackagePolicies[i].ID == id {
			s.PackagePolicies[i].Name = req.Name
			s.PackagePolicies[i].Namespace = req.Namespace
			writeJSON(w, map[string]any{"item": s.PackagePolicies[i]})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (s *Server) handleRulesFind(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	items := make([]map[string]any, 0, len(s.Rules))
	for _, rule := range s.Rules {
		indexes := []string{}
		if rule.Index != "" {
			indexes = strings.Split(rule.Index, ",")
		}
		items = append(items, map[string]any{"id": rule.ID, "rule_id": rule.RuleID, "name": rule.Name, "type": rule.Type, "query": rule.Query, "index": indexes, "enabled": rule.Enabled})
	}
	writeJSON(w, map[string]any{"data": items, "page": 1, "perPage": 100, "total": len(items)})
}

func (s *Server) handleInstallPackage(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/fleet/epm/packages/"), "/")
	if len(parts) >= 2 {
		s.InstalledPackages = append(s.InstalledPackages, InstalledPackage{Name: parts[0], Version: parts[1]})
	}
	writeJSON(w, map[string]any{"status": "ok"})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		var req struct {
			RuleID, Name, Type, Query string
			Index                     []string
			Enabled                   bool
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if r.Method == http.MethodPut {
			id := r.URL.Query().Get("rule_id")
			for index := range s.Rules {
				if s.Rules[index].RuleID == id {
					s.Rules[index].Name = req.Name
					s.Rules[index].Type = req.Type
					s.Rules[index].Query = req.Query
					s.Rules[index].Index = strings.Join(req.Index, ",")
					s.Rules[index].Enabled = req.Enabled
					writeJSON(w, map[string]any{"item": s.Rules[index]})
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
		item := Rule{ID: req.RuleID, RuleID: req.RuleID, Name: req.Name, Type: req.Type, Query: req.Query, Index: strings.Join(req.Index, ","), Enabled: req.Enabled}
		if item.ID == "" {
			item.ID = req.Name
		}
		s.Rules = append(s.Rules, item)
		writeJSON(w, map[string]any{"status": "ok"})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesByID(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.record(r)
	if r.Method != http.MethodPut {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/detection_engine/rules/")
	var req struct {
		RuleID, Name, Type, Query string
		Index                     []string
		Enabled                   bool
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	for i := range s.Rules {
		if s.Rules[i].ID == id || s.Rules[i].RuleID == id {
			s.Rules[i].Name = req.Name
			s.Rules[i].Type = req.Type
			s.Rules[i].Query = req.Query
			s.Rules[i].Index = strings.Join(req.Index, ",")
			s.Rules[i].Enabled = req.Enabled
			writeJSON(w, map[string]any{"item": s.Rules[i]})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
