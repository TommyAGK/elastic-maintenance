package kibana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

type ResponseError struct {
	StatusCode int
	Message    string
}

func (e *ResponseError) Error() string { return fmt.Sprintf("kibana api %d: %s", e.StatusCode, e.Message) }

type InstalledPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type PackagePolicy struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type Rule struct {
	ID      string `json:"id"`
	RuleID  string `json:"rule_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Enabled bool   `json:"enabled"`
	Query   string `json:"query"`
	Index   string `json:"index"`
}

type ReviewChange struct {
	Kind    string
	Name    string
	Action  string
	Details string
}

type CreatePackagePolicyRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	PolicyID  string `json:"policy_id,omitempty"`
	Package   struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

type CreateRuleRequest struct {
	RuleID   string `json:"rule_id,omitempty"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Enabled  bool   `json:"enabled"`
	Query    string `json:"query,omitempty"`
	Severity string `json:"severity,omitempty"`
	Interval string `json:"interval,omitempty"`
	Language string `json:"language,omitempty"`
	Index    string `json:"index,omitempty"`
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{baseURL: baseURL, apiKey: apiKey, httpClient: &http.Client{}}
}

func (c *Client) do(_ context.Context, req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "ApiKey "+c.apiKey)
	req.Header.Set("kbn-xsrf", "elastic-maintenance")
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.httpClient.Do(req)
}

func (c *Client) endpoint(path string) string {
	return fmt.Sprintf("%s%s", strings.TrimRight(c.baseURL, "/"), path)
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
	if err != nil { return err }
	resp, err := c.do(ctx, req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { return decodeErr(resp) }
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) postJSON(ctx context.Context, path string, body any, v any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(b))
	if err != nil { return err }
	resp, err := c.do(ctx, req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { return decodeErr(resp) }
	if v != nil { return json.NewDecoder(resp.Body).Decode(v) }
	return nil
}

func decodeErr(resp *http.Response) error {
	b, _ := io.ReadAll(resp.Body)
	return &ResponseError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(b))}
}

func (c *Client) InstalledPackages(ctx context.Context) ([]InstalledPackage, error) {
	var resp struct { Items []InstalledPackage `json:"items"` }
	if err := c.getJSON(ctx, "/api/fleet/epm/packages", &resp); err != nil { return nil, err }
	return resp.Items, nil
}

func (c *Client) PackagePolicies(ctx context.Context) ([]PackagePolicy, error) {
	var resp struct { Items []PackagePolicy `json:"items"` }
	if err := c.getJSON(ctx, "/api/fleet/package_policies", &resp); err != nil { return nil, err }
	return resp.Items, nil
}

func (c *Client) Rules(ctx context.Context) ([]Rule, error) {
	var resp struct { Data []Rule `json:"data"` }
	if err := c.getJSON(ctx, "/api/detection_engine/rules/_find?per_page=10000", &resp); err != nil { return nil, err }
	return resp.Data, nil
}
