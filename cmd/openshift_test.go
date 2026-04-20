package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateOpenShiftCommandRejectsUnknownFlow(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	openshiftFlow = "unknown"

	if err := validateOpenShiftCommand(newOpenShiftValidationTestCommand()); err == nil {
		t.Fatal("expected error for invalid flow")
	}
}

func TestValidateOpenShiftCommandRejectsCustomAuthHostForDeviceExchange(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	cmd := newOpenShiftValidationTestCommand()
	mustSetOpenShiftTestFlag(t, cmd, "auth-host", "custom-auth.example")

	openshiftFlow = openShiftFlowDeviceExchange

	err := validateOpenShiftCommand(cmd)
	if err == nil {
		t.Fatal("expected error for auth-host with device-exchange flow")
	}
	want := "--flow=device-exchange does not support these flags: --auth-host"
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func TestValidateOpenShiftCommandRejectsExplicitDefaultBrowserFlagForDeviceExchange(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	cmd := newOpenShiftValidationTestCommand()
	mustSetOpenShiftTestFlag(t, cmd, "browser", "false")

	openshiftFlow = openShiftFlowDeviceExchange

	err := validateOpenShiftCommand(cmd)
	if err == nil {
		t.Fatal("expected error for explicitly set browser flag with device-exchange flow")
	}
	want := "--flow=device-exchange does not support these flags: --browser"
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func TestValidateOpenShiftCommandRejectsMultipleUnsupportedFlagsInStableOrder(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	cmd := newOpenShiftValidationTestCommand()
	mustSetOpenShiftTestFlag(t, cmd, "auth-host", "custom-auth.example")
	mustSetOpenShiftTestFlag(t, cmd, "otp", "123456")
	mustSetOpenShiftTestFlag(t, cmd, "use-keytab", "true")

	openshiftFlow = openShiftFlowDeviceExchange

	err := validateOpenShiftCommand(cmd)
	if err == nil {
		t.Fatal("expected error for unsupported device-exchange flags")
	}
	want := "--flow=device-exchange does not support these flags: --auth-host, --otp, --use-keytab"
	if err.Error() != want {
		t.Fatalf("expected error %q, got %q", want, err.Error())
	}
}

func TestValidateOpenShiftCommandAllowsDeviceExchangeWithDefaults(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	openshiftFlow = openShiftFlowDeviceExchange

	if err := validateOpenShiftCommand(newOpenShiftValidationTestCommand()); err != nil {
		t.Fatalf("expected defaults to pass for device-exchange flow, got %v", err)
	}
}

func TestValidateOpenShiftCommandSkipsGenericAuthValidationForDeviceExchange(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	openshiftFlow = openShiftFlowDeviceExchange
	usePassword = true
	useCCache = true

	if err := validateOpenShiftCommand(newOpenShiftValidationTestCommand()); err != nil {
		t.Fatalf("expected device-exchange validation to skip generic auth validation, got %v", err)
	}
}

func TestValidateOpenShiftCommandKeepsAuthValidationForWebFlow(t *testing.T) {
	restore := saveOpenShiftValidationGlobals()
	defer restore()

	openshiftFlow = openShiftFlowWeb
	usePassword = true
	useCCache = true

	err := validateOpenShiftCommand(newOpenShiftValidationTestCommand())
	if err == nil {
		t.Fatal("expected web flow to keep generic auth validation")
	}
	if !strings.Contains(err.Error(), "--use-password, --use-keytab, and --use-ccache") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func newOpenShiftValidationTestCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "openshift"}

	cmd.Flags().String("auth-host", defaultAuthHostname, "")
	cmd.Flags().String("user", "", "")
	cmd.Flags().String("krb5-config", "", "")
	cmd.Flags().String("otp", "", "")
	cmd.Flags().String("otp-command", "", "")
	cmd.Flags().String("otp-keychain", "", "")
	cmd.Flags().Int("otp-retries", 3, "")
	cmd.Flags().String("webauthn-pin", "", "")
	cmd.Flags().String("webauthn-device", "", "")
	cmd.Flags().Int("webauthn-device-index", -1, "")
	cmd.Flags().Int("webauthn-timeout", 30, "")
	cmd.Flags().Bool("browser", false, "")
	cmd.Flags().Bool("use-otp", false, "")
	cmd.Flags().Bool("use-webauthn", false, "")
	cmd.Flags().String("keytab", "", "")
	cmd.Flags().Bool("use-password", false, "")
	cmd.Flags().Bool("use-keytab", false, "")
	cmd.Flags().Bool("use-ccache", false, "")

	return cmd
}

func mustSetOpenShiftTestFlag(t *testing.T, cmd *cobra.Command, name string, value string) {
	t.Helper()

	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatalf("failed to set flag %q: %v", name, err)
	}
}

func saveOpenShiftValidationGlobals() func() {
	oldFlow := openshiftFlow
	oldAuthHost := openshiftAuthHost
	oldUsePassword := usePassword
	oldUseKeytab := useKeytab
	oldUseCCache := useCCache
	oldKeytabPath := keytabPath
	oldUseOTP := useOTP
	oldUseWebAuthn := useWebAuthn

	return func() {
		openshiftFlow = oldFlow
		openshiftAuthHost = oldAuthHost
		usePassword = oldUsePassword
		useKeytab = oldUseKeytab
		useCCache = oldUseCCache
		keytabPath = oldKeytabPath
		useOTP = oldUseOTP
		useWebAuthn = oldUseWebAuthn
	}
}
