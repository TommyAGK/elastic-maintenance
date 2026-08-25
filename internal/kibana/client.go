package kibana

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
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
	space      string
	versionMu  sync.Mutex
	version    string
	retryWait  func(context.Context, time.Duration) error
	identity   config.TargetIdentity
}

const maxTargetResponseBytes int64 = 8 << 20

var errTargetResponseTooLarge = errors.New("Kibana response exceeds limit")

type ResponseError struct {
	StatusCode int
	Message    string
	kind       ErrorKind
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("kibana api %d: %s", e.StatusCode, e.Message)
}

type ReviewChange struct {
	Kind    string
	Name    string
	Action  string
	Details string
}

type CreatePackagePolicyRequest struct {
	ID          string `json:"id,omitempty"`
	Description string `json:"description,omitempty"`
	Name        string `json:"name"`
	Namespace   string `json:"namespace"`
	PolicyID    string `json:"policy_id,omitempty"`
	Package     struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

type UpdatePackagePolicyRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type CreateRuleRequest struct {
	RuleID   string   `json:"rule_id,omitempty"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Enabled  bool     `json:"enabled"`
	Query    string   `json:"query,omitempty"`
	Severity string   `json:"severity,omitempty"`
	Interval string   `json:"interval,omitempty"`
	Language string   `json:"language,omitempty"`
	Index    []string `json:"index,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

func NewClient(baseURL, apiKey string) *Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxResponseHeaderBytes = 64 << 10
	return newClient(baseURL, []byte(apiKey), &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, func() { transport.TLSClientConfig.RootCAs = nil })
}
func newClient(baseURL string, apiKey []byte, httpClient *http.Client, closeHook func()) *Client {
	return &Client{baseURL: baseURL, apiKey: append([]byte{}, apiKey...), httpClient: httpClient, closeHook: closeHook, space: "default", retryWait: waitForRetry}
}
func (c *Client) TargetIdentity() config.TargetIdentity {
	if c == nil {
		return config.TargetIdentity{}
	}
	return c.identity
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
	if req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodOptions {
		req.Header.Set("kbn-xsrf", "elastic-maintenance")
	}
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
	endpoint, err := c.endpointURL(path, true)
	if err != nil {
		return ""
	}
	return endpoint
}
func (c *Client) getJSON(ctx context.Context, path string, value any) error {
	if err := c.EnsureCompatible(ctx); err != nil {
		return err
	}
	return c.requestJSON(ctx, http.MethodGet, path, nil, value, true)
}
func (c *Client) postJSON(ctx context.Context, path string, body, value any) error {
	if err := c.EnsureCompatible(ctx); err != nil {
		return err
	}
	return c.requestJSON(ctx, http.MethodPost, path, body, value, true)
}
func (c *Client) putJSON(ctx context.Context, path string, body, value any) error {
	if err := c.EnsureCompatible(ctx); err != nil {
		return err
	}
	return c.requestJSON(ctx, http.MethodPut, path, body, value, true)
}
