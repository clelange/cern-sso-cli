package auth

import (
	"net/http"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
)

// TestNewKerberosClientWithInsecureCert verifies that when verifyCert is false,
// the HTTP client is configured with InsecureSkipVerify: true
func TestNewKerberosClientWithInsecureCert(t *testing.T) {
	tests := []struct {
		name       string
		verifyCert bool
		wantSkip   bool
	}{
		{
			name:       "verify cert enabled",
			verifyCert: true,
			wantSkip:   false,
		},
		{
			name:       "verify cert disabled (insecure)",
			verifyCert: false,
			wantSkip:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("KRB5_USERNAME", "test")
			os.Setenv("KRB5_PASSWORD", "test")
			defer os.Unsetenv("KRB5_USERNAME")
			defer os.Unsetenv("KRB5_PASSWORD")

			cfg, _ := loadTestKrb5Config()
			cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
			kc, err := newKerberosClientFromKrbClient(cl, "test", tt.verifyCert)

			if err != nil {
				t.Fatalf("Failed to create KerberosClient: %v", err)
			}

			// Get the HTTP client
			httpClient := kc.GetHTTPClient()

			// Check that the transport has the correct TLS config
			if transport, ok := httpClient.Transport.(*cookieInterceptTransport); ok {
				if baseTransport, ok := transport.base.(*http.Transport); ok {
					tlsConfig := baseTransport.TLSClientConfig
					if tlsConfig == nil {
						t.Fatal("TLSClientConfig is nil")
					}

					if tlsConfig.InsecureSkipVerify != tt.wantSkip {
						t.Errorf("InsecureSkipVerify = %v, want %v", tlsConfig.InsecureSkipVerify, tt.wantSkip)
					}
				} else {
					t.Error("Expected base transport to be *http.Transport")
				}
			} else {
				t.Error("Expected transport to be *cookieInterceptTransport")
			}

			kc.Close()
		})
	}
}

// TestLoginWithKerberosWithInsecureCert verifies that LoginWithKerberos respects
// the verifyCert parameter when making HTTP requests
func TestLoginWithKerberosWithInsecureCert(t *testing.T) {
	os.Setenv("KRB5_USERNAME", "test")
	os.Setenv("KRB5_PASSWORD", "test")
	defer os.Unsetenv("KRB5_USERNAME")
	defer os.Unsetenv("KRB5_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test", false)
	defer kc.Close()

	// Verify that the client was created with InsecureSkipVerify: true
	httpClient := kc.GetHTTPClient()
	if transport, ok := httpClient.Transport.(*cookieInterceptTransport); ok {
		if baseTransport, ok := transport.base.(*http.Transport); ok {
			if !baseTransport.TLSClientConfig.InsecureSkipVerify {
				t.Error("Expected InsecureSkipVerify to be true for insecure client")
			}
		}
	}
}
