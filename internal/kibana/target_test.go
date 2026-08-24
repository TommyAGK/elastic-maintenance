package kibana

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TommyAGK/elastic-maintenance/internal/config"
)

type fakeTargetMaterial struct {
	identity     config.TargetIdentity
	key          []byte
	certificates []*x509.Certificate
	closed       bool
}

func (material *fakeTargetMaterial) TargetIdentity() config.TargetIdentity { return material.identity }
func (material *fakeTargetMaterial) APIKey() []byte                        { return append([]byte{}, material.key...) }
func (material *fakeTargetMaterial) CACertificates() []*x509.Certificate {
	return append([]*x509.Certificate{}, material.certificates...)
}
func (material *fakeTargetMaterial) Close() {
	clear(material.key)
	material.key = nil
	material.closed = true
}

func TestTargetClientUsesUploadedCATrustAndAPIKeyForLeaseLifetime(t *testing.T) {
	ca, serverCertificate := targetTLSFixture(t)
	var authorization string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[]}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCertificate}}
	server.StartTLS()
	defer server.Close()
	material := &fakeTargetMaterial{identity: config.TargetIdentity{Name: "prod", URL: server.URL, Space: "default"}, key: []byte("target-secret-sentinel"), certificates: []*x509.Certificate{ca}}
	factory, err := NewTargetClientFactory(TargetClientOptions{AcquireMaterial: func(context.Context, string) (CredentialMaterial, error) { return material, nil }, SystemCertPool: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	client, err := factory.Acquire(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.InstalledPackages(context.Background()); err != nil {
		t.Fatal(err)
	}
	if authorization != "ApiKey target-secret-sentinel" {
		t.Fatalf("authorization=%q", authorization)
	}
	transport := client.httpClient.Transport.(*http.Transport)
	client.Close()
	if transport.TLSClientConfig.RootCAs != nil {
		t.Fatal("uploaded roots retained after close")
	}
	if !material.closed || len(material.key) != 0 {
		t.Fatal("credential lease was not released and cleared")
	}
	if _, err := client.InstalledPackages(context.Background()); err == nil {
		t.Fatal("closed client remained usable")
	}
}

func TestTargetClientRejectsNilMaterial(t *testing.T) {
	factory, _ := NewTargetClientFactory(TargetClientOptions{AcquireMaterial: func(context.Context, string) (CredentialMaterial, error) { return nil, nil }})
	if _, err := factory.Acquire(context.Background(), "prod"); !errors.Is(err, ErrTargetUnready) {
		t.Fatalf("error=%v", err)
	}
}

func TestTargetClientFailsClosedAndReleasesLease(t *testing.T) {
	material := &fakeTargetMaterial{identity: config.TargetIdentity{Name: "prod", URL: "https://kibana.example.test"}, key: []byte("secret")}
	factory, err := NewTargetClientFactory(TargetClientOptions{AcquireMaterial: func(context.Context, string) (CredentialMaterial, error) { return material, nil }, SystemCertPool: func() (*x509.CertPool, error) { return nil, errors.New("roots unavailable") }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.Acquire(context.Background(), "prod"); !errors.Is(err, ErrTargetUnready) {
		t.Fatalf("error=%v", err)
	}
	if !material.closed || len(material.key) != 0 {
		t.Fatal("failed acquisition retained lease")
	}
}

func TestTargetClientNeverForwardsAuthorizationAcrossRedirect(t *testing.T) {
	ca, certificate := targetTLSFixture(t)
	received := false
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received = true }))
	defer destination.Close()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, http.StatusFound) }))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
	server.StartTLS()
	defer server.Close()
	material := &fakeTargetMaterial{identity: config.TargetIdentity{Name: "prod", URL: server.URL}, key: []byte("redirect-secret"), certificates: []*x509.Certificate{ca}}
	factory, _ := NewTargetClientFactory(TargetClientOptions{AcquireMaterial: func(context.Context, string) (CredentialMaterial, error) { return material, nil }, SystemCertPool: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }})
	client, err := factory.Acquire(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.InstalledPackages(context.Background()); err == nil {
		t.Fatal("redirect was accepted")
	}
	if received {
		t.Fatal("redirect destination received a request")
	}
}

func TestTargetClientDoesNotUseEnvironmentProxy(t *testing.T) {
	material := &fakeTargetMaterial{identity: config.TargetIdentity{Name: "prod", URL: "https://kibana.example.test"}, key: []byte("secret")}
	factory, _ := NewTargetClientFactory(TargetClientOptions{AcquireMaterial: func(context.Context, string) (CredentialMaterial, error) { return material, nil }, SystemCertPool: func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }})
	client, err := factory.Acquire(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport := client.httpClient.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Fatal("target transport permits environment proxying")
	}
	if len(transport.TLSClientConfig.Certificates) != 0 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("target transport enabled client certificates or insecure TLS")
	}
}

func targetTLSFixture(t *testing.T) (*x509.Certificate, tls.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	serverTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "127.0.0.1"}, DNSNames: []string{"localhost"}, IPAddresses: nil, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	serverTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return ca, tls.Certificate{Certificate: [][]byte{serverDER, caDER}, PrivateKey: serverKey}
}
