package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/cookiejar"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Config configures a shared HTTP client.
type Config struct {
	Timeout        time.Duration
	VerifyCert     bool
	Jar            http.CookieJar
	CheckRedirect  func(req *http.Request, via []*http.Request) error
	Transport      http.RoundTripper
	RootCAs        *x509.CertPool
	ForceTLSConfig bool
}

// TransportConfig configures a shared HTTP transport.
type TransportConfig struct {
	VerifyCert     bool
	RootCAs        *x509.CertPool
	ForceTLSConfig bool
}

// New creates an HTTP client with consistent timeout and TLS settings.
func New(cfg Config) *http.Client {
	transport := cfg.Transport
	if transport == nil {
		transport = NewTransport(TransportConfig{
			VerifyCert:     cfg.VerifyCert,
			RootCAs:        cfg.RootCAs,
			ForceTLSConfig: cfg.ForceTLSConfig,
		})
	}

	return &http.Client{
		Jar:           cfg.Jar,
		Transport:     transport,
		Timeout:       cfg.Timeout,
		CheckRedirect: cfg.CheckRedirect,
	}
}

// NewTransport creates an HTTP transport with consistent TLS settings.
func NewTransport(cfg TransportConfig) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if !cfg.VerifyCert || cfg.RootCAs != nil || cfg.ForceTLSConfig {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: !cfg.VerifyCert, // #nosec G402
		}
		if cfg.RootCAs != nil {
			tlsConfig.RootCAs = cfg.RootCAs
		}
		transport.TLSClientConfig = tlsConfig
	}

	return transport
}

// NewJar creates a cookie jar with a public suffix list.
func NewJar() (*cookiejar.Jar, error) {
	return cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
}
