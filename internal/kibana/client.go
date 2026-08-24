package kibana

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Client struct {
	baseURL    string
	apiKey     []byte
	httpClient *http.Client
	mu         sync.Mutex
	closed     bool
	closeOnce  sync.Once
	closeHook  func()
	inFlight   sync.WaitGroup
}

const maxTargetResponseBytes int64 = 8 << 20

var errTargetResponseTooLarge = errors.New("Kibana response exceeds limit")

type ResponseError struct {
	StatusCode int
	Message    string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("kibana api %d: %s", e.StatusCode, e.Message)
}

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

type UpdatePackagePolicyRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
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
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 30 * time.Second
	return newClient(baseURL, []byte(apiKey), &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, func() { transport.TLSClientConfig.RootCAs = nil })
}
func newClient(baseURL string, apiKey []byte, httpClient *http.Client, closeHook func()) *Client {
	return &Client{baseURL: baseURL, apiKey: append([]byte{}, apiKey...), httpClient: httpClient, closeHook: closeHook}
}
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.inFlight.Wait()
		c.mu.Lock()
		clear(c.apiKey)
		c.apiKey = nil
		c.mu.Unlock()
		if closer, ok := c.httpClient.Transport.(interface{ CloseIdleConnections() }); ok {
			closer.CloseIdleConnections()
		}
		if c.closeHook != nil {
			c.closeHook()
		}
	})
}
func (c *Client) do(_ context.Context, req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errors.New("kibana client is closed")
	}
	apiKey := append([]byte("ApiKey "), c.apiKey...)
	c.inFlight.Add(1)
	c.mu.Unlock()
	defer clear(apiKey)
	req.Header.Set("Authorization", string(apiKey))
	req.Header.Set("kbn-xsrf", "elastic-maintenance")
	if req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
		req.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		c.inFlight.Done()
		return nil, err
	}
	response.Body = &trackedResponseBody{ReadCloser: &boundedResponseBody{ReadCloser: response.Body, remaining: maxTargetResponseBytes}, done: c.inFlight.Done}
	return response, nil
}

type boundedResponseBody struct {
	io.ReadCloser
	remaining int64
}

func (body *boundedResponseBody) Read(buffer []byte) (int, error) {
	if body.remaining == 0 {
		var probe [1]byte
		n, err := body.ReadCloser.Read(probe[:])
		if n > 0 {
			return 0, errTargetResponseTooLarge
		}
		return 0, err
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	n, err := body.ReadCloser.Read(buffer)
	body.remaining -= int64(n)
	return n, err
}

type trackedResponseBody struct {
	io.ReadCloser
	once sync.Once
	done func()
}

func (body *trackedResponseBody) Close() error {
	err := body.ReadCloser.Close()
	body.once.Do(body.done)
	return err
}

func (c *Client) endpoint(path string) string {
	return fmt.Sprintf("%s%s", strings.TrimRight(c.baseURL, "/"), path)
}

func (c *Client) getJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return decodeErr(resp)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func (c *Client) postJSON(ctx context.Context, path string, body any, v any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(path), bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return decodeErr(resp)
	}
	if v != nil {
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return nil
}

func (c *Client) putJSON(ctx context.Context, path string, body any, v any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint(path), bytes.NewReader(b))
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return decodeErr(resp)
	}
	if v != nil {
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return nil
}

func decodeErr(resp *http.Response) error {
	_, _ = io.Copy(io.Discard, resp.Body)
	message := http.StatusText(resp.StatusCode)
	if message == "" {
		message = "remote request failed"
	}
	return &ResponseError{StatusCode: resp.StatusCode, Message: message}
}

func (c *Client) InstalledPackages(ctx context.Context) ([]InstalledPackage, error) {
	var resp struct {
		Items []InstalledPackage `json:"items"`
	}
	if err := c.getJSON(ctx, "/api/fleet/epm/packages", &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

func (c *Client) PackagePolicies(ctx context.Context) ([]PackagePolicy, error) {
	var resp struct {
		Items []PackagePolicy `json:"items"`
	}
	if err := c.getJSON(ctx, "/api/fleet/package_policies", &resp); err != nil {
		return nil, err
	}
	return resp.Items, nil
}

func (c *Client) Rules(ctx context.Context) ([]Rule, error) {
	var resp struct {
		Data []Rule `json:"data"`
	}
	if err := c.getJSON(ctx, "/api/detection_engine/rules/_find?per_page=10000", &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}
