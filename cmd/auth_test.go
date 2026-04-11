package cmd

import (
	"strings"
	"testing"
)

func TestValidateAuthCLIOptionsRejectsConflicting2FAMethods(t *testing.T) {
	oldUseOTP := useOTP
	oldUseWebAuthn := useWebAuthn
	defer func() {
		useOTP = oldUseOTP
		useWebAuthn = oldUseWebAuthn
	}()

	useOTP = true
	useWebAuthn = true

	err := validateAuthCLIOptions()
	if err == nil {
		t.Fatal("expected error for conflicting 2FA flags")
	}
	if !strings.Contains(err.Error(), "--use-otp and --use-webauthn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateAuthCLIOptionsRejectsConflictingAuthMethods(t *testing.T) {
	oldUsePassword := usePassword
	oldUseKeytab := useKeytab
	oldUseCCache := useCCache
	oldKeytabPath := keytabPath
	defer func() {
		usePassword = oldUsePassword
		useKeytab = oldUseKeytab
		useCCache = oldUseCCache
		keytabPath = oldKeytabPath
	}()

	usePassword = true
	useKeytab = false
	useCCache = true
	keytabPath = ""

	err := validateAuthCLIOptions()
	if err == nil {
		t.Fatal("expected error for conflicting auth method flags")
	}
	if !strings.Contains(err.Error(), "--use-password, --use-keytab, and --use-ccache") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewConfiguredKerberosClientPropagatesInitError(t *testing.T) {
	oldKrb5Config := krb5Config
	oldKeytabPath := keytabPath
	oldUsePassword := usePassword
	oldUseKeytab := useKeytab
	oldUseCCache := useCCache
	oldKrbUser := krbUser
	defer func() {
		krb5Config = oldKrb5Config
		keytabPath = oldKeytabPath
		usePassword = oldUsePassword
		useKeytab = oldUseKeytab
		useCCache = oldUseCCache
		krbUser = oldKrbUser
	}()

	krb5Config = "/nonexistent/krb5.conf"
	keytabPath = ""
	usePassword = false
	useKeytab = false
	useCCache = false
	krbUser = ""

	_, err := newConfiguredKerberosClient(false)
	if err == nil {
		t.Fatal("expected initialization error")
	}
	if !strings.Contains(err.Error(), "failed to initialize Kerberos") {
		t.Fatalf("unexpected error: %v", err)
	}
}
