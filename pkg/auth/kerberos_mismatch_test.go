package auth

import (
	"strings"
	"testing"
)

func TestNewKerberosClient_UserMismatch_SkipsPassword(t *testing.T) {
	// Set up environment with credentials for User A
	t.Setenv("KRB5_USERNAME", "userA")
	t.Setenv("KRB5_PASSWORD", "passwordA")
	// Ensure no ccache is picked up and force the post-password path to surface.
	t.Setenv("KRB5CCNAME", "/nonexistent/file")
	t.Setenv("KRB5_KTNAME", "/nonexistent/file")

	// Attempt to authenticate as User B
	// This should NOT use passwordA.
	client, err := NewKerberosClientWithConfig("dev", Krb5ConfigEmbedded, "userB", false, AuthConfig{})

	if err == nil {
		t.Fatalf("Expected error, got success for %s", client.username)
	}

	errStr := err.Error()
	if !strings.Contains(errStr, "KRB5_KTNAME") {
		t.Errorf("Expected KRB5_KTNAME error, proving password auth was skipped. Got: %v", err)
	}
}

func TestNewKerberosClient_InvalidKRB5KTNAMEFailsFast(t *testing.T) {
	t.Setenv("KRB5CCNAME", "/nonexistent/file")
	t.Setenv("KRB5_KTNAME", "/nonexistent/file")

	_, err := NewKerberosClientWithConfig("dev", Krb5ConfigEmbedded, "", false, AuthConfig{})
	if err == nil {
		t.Fatal("expected error for invalid KRB5_KTNAME")
	}
	if !strings.Contains(err.Error(), "KRB5_KTNAME") {
		t.Fatalf("expected KRB5_KTNAME error, got: %v", err)
	}
}
