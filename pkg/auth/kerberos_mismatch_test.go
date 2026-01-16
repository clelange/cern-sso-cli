package auth

import (
	"os"
	"strings"
	"testing"
)

func TestNewKerberosClient_UserMismatch_SkipsPassword(t *testing.T) {
	// Set up environment with credentials for User A
	os.Setenv("KRB5_USERNAME", "userA")
	os.Setenv("KRB5_PASSWORD", "passwordA")
	// Ensure no ccache or keytab is picked up
	os.Setenv("KRB5CCNAME", "/nonexistent/file")
	os.Setenv("KRB5_KTNAME", "/nonexistent/file")

	defer os.Unsetenv("KRB5_USERNAME")
	defer os.Unsetenv("KRB5_PASSWORD")
	defer os.Unsetenv("KRB5CCNAME")
	defer os.Unsetenv("KRB5_KTNAME")

	// Attempt to authenticate as User B
	// This should NOT use passwordA.
	client, err := NewKerberosClientWithConfig("dev", Krb5ConfigEmbedded, "userB", false, AuthConfig{})

	if err == nil {
		t.Fatalf("Expected error, got success for %s", client.username)
	}

	// If the password was used, we would likely get a KDC error or a network error
	// (because we're using embedded config which points to real CERN KDC, or it tries to dial).
	// If the password was correctly skipped, we fall through to other methods.
	// Since we disabled ccache and keytab, we expect "no authentication method available".

	errStr := err.Error()
	if !strings.Contains(errStr, "no authentication method available") {
		t.Errorf("Expected 'no authentication method available' error, proving password was skipped. Got: %v", err)
	}
}
