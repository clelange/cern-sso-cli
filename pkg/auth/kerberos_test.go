package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

func TestTryLoginWithCookies_NoCookies(t *testing.T) {
	// Set up credentials for the test
	os.Setenv("KRB_USERNAME", "test")
	os.Setenv("KRB_PASSWORD", "test")
	defer os.Unsetenv("KRB_USERNAME")
	defer os.Unsetenv("KRB_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test")

	result, err := kc.TryLoginWithCookies("https://example.com", "auth.example.com", nil)

	if err == nil {
		t.Error("Expected error when no cookies provided")
	}
	if result != nil {
		t.Error("Expected nil result when no cookies provided")
	}
}

func TestTryLoginWithCookies_InvalidRedirect(t *testing.T) {
	// Set up credentials for the test
	os.Setenv("KRB_USERNAME", "test")
	os.Setenv("KRB_PASSWORD", "test")
	defer os.Unsetenv("KRB_USERNAME")
	defer os.Unsetenv("KRB_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test")

	// Create a mock server that redirects to auth (simulating invalid cookies)
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://auth.example.com/login", http.StatusFound)
	}))
	defer authServer.Close()

	cookies := []*http.Cookie{
		{Name: "test", Value: "value"},
	}

	_, err := kc.TryLoginWithCookies(authServer.URL, "auth.example.com", cookies)

	if err == nil {
		t.Error("Expected error when cookies cause redirect to auth")
	}
}

func TestTryLoginWithCookies_Success(t *testing.T) {
	// Set up credentials for the test
	os.Setenv("KRB_USERNAME", "test")
	os.Setenv("KRB_PASSWORD", "test")
	defer os.Unsetenv("KRB_USERNAME")
	defer os.Unsetenv("KRB_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test")

	// Create a mock server that returns success (valid cookies)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer targetServer.Close()

	cookies := []*http.Cookie{
		{Name: "session", Value: "valid123"},
	}

	result, err := kc.TryLoginWithCookies(targetServer.URL, "auth.example.com", cookies)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result on success")
	}
}

func loadTestKrb5Config() (*config.Config, error) {
	return config.NewFromString(defaultKrb5Conf)
}

func TestTryLoginWithCookies_VerifiesCookiesSent(t *testing.T) {
	// Set up credentials for the test
	os.Setenv("KRB_USERNAME", "test")
	os.Setenv("KRB_PASSWORD", "test")
	defer os.Unsetenv("KRB_USERNAME")
	defer os.Unsetenv("KRB_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test")

	// Create a mock server that verifies cookies are received
	cookiesReceived := make([]string, 0)
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture all cookies from the request
		for _, cookie := range r.Cookies() {
			cookiesReceived = append(cookiesReceived, cookie.Name)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer targetServer.Close()

	// Provide cookies to the client
	testCookies := []*http.Cookie{
		{Name: "AUTH_SESSION", Value: "test-session-123"},
		{Name: "AUTH_TOKEN", Value: "test-token-456"},
	}

	result, err := kc.TryLoginWithCookies(targetServer.URL, "auth.example.com", testCookies)

	// Verify success
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result on success")
	}

	// Verify that the cookies were actually sent
	if len(cookiesReceived) != 2 {
		t.Errorf("Expected 2 cookies to be sent, got %d: %v", len(cookiesReceived), cookiesReceived)
	}

	// Verify specific cookie names
	cookieMap := make(map[string]bool)
	for _, name := range cookiesReceived {
		cookieMap[name] = true
	}

	if !cookieMap["AUTH_SESSION"] {
		t.Error("Expected AUTH_SESSION cookie to be sent")
	}
	if !cookieMap["AUTH_TOKEN"] {
		t.Error("Expected AUTH_TOKEN cookie to be sent")
	}

	t.Logf("Successfully verified that cookies were sent: %v", cookiesReceived)
}

func TestTryLoginWithCookies_DomainFixing(t *testing.T) {
	// Set up credentials for the test
	os.Setenv("KRB_USERNAME", "test")
	os.Setenv("KRB_PASSWORD", "test")
	defer os.Unsetenv("KRB_USERNAME")
	defer os.Unsetenv("KRB_PASSWORD")

	cfg, _ := loadTestKrb5Config()
	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, _ := newKerberosClientFromKrbClient(cl, "test")

	// Create a mock server
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Success"))
	}))
	defer targetServer.Close()

	// Test with cookies that have empty domains (should be fixed)
	cookiesWithoutDomain := []*http.Cookie{
		{Name: "session", Value: "value1", Domain: ""},
	}

	result, err := kc.TryLoginWithCookies(targetServer.URL, "auth.example.com", cookiesWithoutDomain)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if result == nil {
		t.Error("Expected non-nil result on success")
	}

	// Verify the domain was fixed
	if cookiesWithoutDomain[0].Domain == "" {
		t.Error("Expected cookie domain to be fixed (populated)")
	}
	t.Logf("Cookie domain fixed to: %s", cookiesWithoutDomain[0].Domain)
}
