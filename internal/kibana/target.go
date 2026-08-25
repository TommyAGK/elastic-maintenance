package kibana

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

var ErrTargetUnready = errors.New("Kibana target is not ready")

type CredentialMaterial interface {
	TargetIdentity() config.TargetIdentity
	APIKey() []byte
	CACertificates() []*x509.Certificate
	Close()
}
type AcquireCredentialMaterial func(context.Context, string) (CredentialMaterial, error)

type TargetClientOptions struct {
	AcquireMaterial AcquireCredentialMaterial
	SystemCertPool  func() (*x509.CertPool, error)
	DialContext     func(context.Context, string, string) (net.Conn, error)
}

type TargetClientFactory struct {
	acquireMaterial AcquireCredentialMaterial
	systemRoots     func() (*x509.CertPool, error)
	dialContext     func(context.Context, string, string) (net.Conn, error)
}

func NewTargetClientFactory(options TargetClientOptions) (*TargetClientFactory, error) {
	if options.AcquireMaterial == nil {
		return nil, errors.New("target credential source is required")
	}
	roots := options.SystemCertPool
	if roots == nil {
		roots = x509.SystemCertPool
	}
	dial := options.DialContext
	if dial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		dial = dialer.DialContext
	}
	return &TargetClientFactory{acquireMaterial: options.AcquireMaterial, systemRoots: roots, dialContext: dial}, nil
}

func (factory *TargetClientFactory) Acquire(ctx context.Context, targetID string) (*Client, error) {
	if factory == nil || factory.acquireMaterial == nil {
		return nil, ErrTargetUnready
	}
	lease, err := factory.acquireMaterial(ctx, targetID)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, ErrTargetUnready
	}
	if lease == nil {
		return nil, ErrTargetUnready
	}
	success := false
	defer func() {
		if !success {
			lease.Close()
		}
	}()
	roots, err := factory.systemRoots()
	if err != nil {
		return nil, ErrTargetUnready
	}
	if roots == nil {
		roots = x509.NewCertPool()
	} else {
		roots = roots.Clone()
	}
	for _, certificate := range lease.CACertificates() {
		if certificate == nil {
			return nil, ErrTargetUnready
		}
		roots.AddCert(certificate)
	}
	apiKey := lease.APIKey()
	if len(apiKey) == 0 {
		return nil, ErrTargetUnready
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            factory.dialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           20,
		MaxIdleConnsPerHost:    4,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ExpectContinueTimeout:  time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    roots,
		},
	}
	httpClient := &http.Client{Transport: transport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	identity := lease.TargetIdentity()
	if identity.Name != targetID || identity.URL == "" {
		clear(apiKey)
		return nil, ErrTargetUnready
	}
	client := newClient(identity.URL, apiKey, httpClient, func() { transport.TLSClientConfig.RootCAs = nil; lease.Close() })
	client.space = identity.Space
	client.identity = identity
	clear(apiKey)
	success = true
	return client, nil
}
