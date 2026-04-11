package httpclient

import (
	"crypto/x509"
	"net/http"
	"testing"
	"time"
)

func TestNewTransport(t *testing.T) {
	rootCAs := x509.NewCertPool()

	tests := []struct {
		name           string
		cfg            TransportConfig
		wantTLSConfig  bool
		wantSkipVerify bool
		wantRootCAs    *x509.CertPool
	}{
		{
			name: "default verified transport",
			cfg: TransportConfig{
				VerifyCert: true,
			},
			wantTLSConfig: false,
		},
		{
			name: "insecure transport",
			cfg: TransportConfig{
				VerifyCert: false,
			},
			wantTLSConfig:  true,
			wantSkipVerify: true,
		},
		{
			name: "custom root CAs",
			cfg: TransportConfig{
				VerifyCert: true,
				RootCAs:    rootCAs,
			},
			wantTLSConfig:  true,
			wantSkipVerify: false,
			wantRootCAs:    rootCAs,
		},
		{
			name: "forced TLS config",
			cfg: TransportConfig{
				VerifyCert:     true,
				ForceTLSConfig: true,
			},
			wantTLSConfig:  true,
			wantSkipVerify: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := NewTransport(tt.cfg)
			if transport == nil {
				t.Fatal("expected transport")
			}

			if !tt.wantTLSConfig {
				if transport.TLSClientConfig != nil {
					if transport.TLSClientConfig.InsecureSkipVerify {
						t.Fatal("expected verified transport to keep InsecureSkipVerify disabled")
					}
					if transport.TLSClientConfig.RootCAs != nil {
						t.Fatal("expected verified transport to keep custom RootCAs unset")
					}
				}
				return
			}
			if transport.TLSClientConfig == nil {
				t.Fatal("expected TLSClientConfig to be set")
			}

			if transport.TLSClientConfig.InsecureSkipVerify != tt.wantSkipVerify {
				t.Fatalf("InsecureSkipVerify = %v, want %v", transport.TLSClientConfig.InsecureSkipVerify, tt.wantSkipVerify)
			}
			if transport.TLSClientConfig.RootCAs != tt.wantRootCAs {
				t.Fatalf("RootCAs = %p, want %p", transport.TLSClientConfig.RootCAs, tt.wantRootCAs)
			}
		})
	}
}

func TestNew(t *testing.T) {
	jar, err := NewJar()
	if err != nil {
		t.Fatalf("NewJar failed: %v", err)
	}

	checkRedirect := func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	client := New(Config{
		Timeout:        15 * time.Second,
		VerifyCert:     false,
		Jar:            jar,
		CheckRedirect:  checkRedirect,
		ForceTLSConfig: true,
	})

	if client.Timeout != 15*time.Second {
		t.Fatalf("Timeout = %v, want %v", client.Timeout, 15*time.Second)
	}
	if client.Jar != jar {
		t.Fatal("expected client jar to be preserved")
	}
	if client.CheckRedirect == nil {
		t.Fatal("expected CheckRedirect to be set")
	}

	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport type = %T, want *http.Transport", client.Transport)
	}
	if transport.TLSClientConfig == nil {
		t.Fatal("expected TLSClientConfig to be set")
	}
	if !transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("expected insecure TLS config")
	}
}
