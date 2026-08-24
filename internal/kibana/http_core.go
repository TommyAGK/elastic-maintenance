package kibana

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ErrorKind string

const (
	ErrorAuthentication ErrorKind = "authentication"
	ErrorAuthorization  ErrorKind = "authorization"
	ErrorNotFound       ErrorKind = "not_found"
	ErrorConflict       ErrorKind = "conflict"
	ErrorThrottled      ErrorKind = "throttled"
	ErrorServer         ErrorKind = "server"
	ErrorProtocol       ErrorKind = "protocol"
	ErrorUnavailable    ErrorKind = "unavailable"
)

var exactPackageVersionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var safeSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,255}$`)
var versionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)

func (e *ResponseError) Retryable() bool {
	return e != nil && (e.StatusCode == http.StatusTooManyRequests || e.StatusCode == http.StatusBadGateway || e.StatusCode == http.StatusServiceUnavailable || e.StatusCode == http.StatusGatewayTimeout)
}

func (e *ResponseError) Kind() ErrorKind {
	if e == nil {
		return ErrorProtocol
	}
	if e.kind != "" {
		return e.kind
	}
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrorAuthentication
	case http.StatusForbidden:
		return ErrorAuthorization
	case http.StatusNotFound:
		return ErrorNotFound
	case http.StatusConflict:
		return ErrorConflict
	case http.StatusTooManyRequests:
		return ErrorThrottled
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, http.StatusInternalServerError:
		return ErrorServer
	default:
		return ErrorProtocol
	}
}

func safePathSegment(value string) (string, error) {
	if !safeSegmentPattern.MatchString(value) {
		return "", errors.New("Kibana resource identifier is invalid")
	}
	return value, nil
}
func (c *Client) endpointURL(reference string, scoped bool) (string, error) {
	if len(reference) == 0 || len(reference) > 8192 {
		return "", errors.New("Kibana API path is invalid")
	}
	base, err := url.Parse(c.baseURL)
	if err != nil || base.Scheme == "" || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return "", errors.New("Kibana target URL is invalid")
	}
	ref, err := url.Parse(reference)
	if err != nil || !strings.HasPrefix(reference, "/") || ref.IsAbs() || ref.Host != "" || ref.Fragment != "" || ref.RawPath != "" {
		return "", errors.New("Kibana API path is invalid")
	}
	prefix := ""
	if scoped && c.space != "" && c.space != "default" {
		prefix = "/s/" + url.PathEscape(c.space)
	}
	base.Path = strings.TrimRight(base.Path, "/") + prefix + ref.Path
	base.RawPath = ""
	base.RawQuery = ref.RawQuery
	result := base.String()
	if len(result) > 16384 {
		return "", errors.New("Kibana API URL exceeds limit")
	}
	return result, nil
}

func (c *Client) EnsureCompatible(ctx context.Context) error {
	c.versionMu.Lock()
	if c.version != "" {
		c.versionMu.Unlock()
		return nil
	}
	c.versionMu.Unlock()
	var response struct {
		Version struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if err := c.requestJSON(ctx, http.MethodGet, "/api/status", nil, &response, false); err != nil {
		return err
	}
	match := versionPattern.FindStringSubmatch(response.Version.Number)
	if len(match) != 4 {
		return &ResponseError{StatusCode: 0, Message: "unsupported Kibana version", kind: ErrorProtocol}
	}
	major, majorErr := strconv.Atoi(match[1])
	minor, minorErr := strconv.Atoi(match[2])
	patch, patchErr := strconv.Atoi(match[3])
	if majorErr != nil || minorErr != nil || patchErr != nil || strconv.Itoa(major) != match[1] || strconv.Itoa(minor) != match[2] || strconv.Itoa(patch) != match[3] {
		return &ResponseError{StatusCode: 0, Message: "unsupported Kibana version", kind: ErrorProtocol}
	}
	if major != 9 || minor < 2 {
		return &ResponseError{StatusCode: 0, Message: "unsupported Kibana version", kind: ErrorProtocol}
	}
	c.versionMu.Lock()
	if c.version == "" {
		c.version = response.Version.Number
	}
	c.versionMu.Unlock()
	return nil
}

func (c *Client) Version() string { c.versionMu.Lock(); defer c.versionMu.Unlock(); return c.version }

func (c *Client) requestJSON(ctx context.Context, method, path string, body, output any, scoped bool) error {
	endpoint, err := c.endpointURL(path, scoped)
	if err != nil {
		return err
	}
	var encoded []byte
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return errors.New("Kibana request body is invalid")
		}
		if len(encoded) > 2<<20 {
			return errors.New("Kibana request body exceeds limit")
		}
	}
	attempts := 1
	if method == http.MethodGet || method == http.MethodHead {
		attempts = 2
	}
	for attempt := 0; attempt < attempts; attempt++ {
		req, requestErr := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(encoded))
		if requestErr != nil {
			return errors.New("Kibana request is invalid")
		}
		response, requestErr := c.do(ctx, req)
		if requestErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if attempt+1 < attempts && retryableTransportError(requestErr) {
				if err := c.retryWait(ctx, 50*time.Millisecond); err != nil {
					return err
				}
				continue
			}
			return &ResponseError{StatusCode: 0, Message: "Kibana target is unavailable", kind: ErrorUnavailable}
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			remote := classifyResponse(response)
			response.Body.Close()
			if attempt+1 < attempts && remote.Retryable() {
				if err := c.retryWait(ctx, retryDelay(response.Header.Get("Retry-After"))); err != nil {
					return err
				}
				continue
			}
			return remote
		}
		decodeErr := decodeJSONResponse(response, output)
		response.Body.Close()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return decodeErr
	}
	return &ResponseError{StatusCode: 0, Message: "Kibana target is unavailable", kind: ErrorUnavailable}
}

func decodeJSONResponse(response *http.Response, output any) error {
	if output == nil {
		var discarded any
		output = &discarded
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return &ResponseError{StatusCode: 0, Message: "Kibana response protocol is invalid", kind: ErrorProtocol}
	}
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(output); err != nil {
		return &ResponseError{StatusCode: 0, Message: "Kibana response protocol is invalid", kind: ErrorProtocol}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return &ResponseError{StatusCode: 0, Message: "Kibana response protocol is invalid", kind: ErrorProtocol}
	}
	return nil
}

func classifyResponse(response *http.Response) *ResponseError {
	_, _ = io.Copy(io.Discard, response.Body)
	message := http.StatusText(response.StatusCode)
	if message == "" {
		message = "remote request failed"
	}
	return &ResponseError{StatusCode: response.StatusCode, Message: message}
}

func retryableTransportError(err error) bool {
	var network net.Error
	return errors.As(err, &network) && (network.Timeout() || network.Temporary())
}

func retryDelay(value string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < 0 {
		return 50 * time.Millisecond
	}
	delay := time.Duration(seconds) * time.Second
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
