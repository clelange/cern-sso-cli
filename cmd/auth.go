package cmd

import (
	"fmt"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

func validateAuthCLIOptions() error {
	if err := ValidateMethodFlags(); err != nil {
		return err
	}
	if err := ValidateAuthMethodFlags(); err != nil {
		return err
	}
	return nil
}

func newConfiguredKerberosClient(insecure bool) (*auth.KerberosClient, error) {
	authConfig := GetAuthConfig()
	kerbClient, err := auth.NewKerberosClientWithConfig(version, krb5Config, krbUser, !insecure, authConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Kerberos: %w", err)
	}

	kerbClient.SetOTPProvider(GetOTPProvider())
	kerbClient.SetWebAuthnProvider(GetWebAuthnProvider())
	kerbClient.SetPreferredMethod(GetPreferredMethod())

	return kerbClient, nil
}

func newLoggedKerberosClient(insecure bool) (*auth.KerberosClient, error) {
	logPrintln("Initializing Kerberos client...")
	return newConfiguredKerberosClient(insecure)
}

func loginWithKerberosSession(targetURL, authHost string, insecure bool) (*auth.KerberosClient, *auth.LoginResult, error) {
	kerbClient, err := newLoggedKerberosClient(insecure)
	if err != nil {
		return nil, nil, err
	}

	logPrintln("Logging in with Kerberos...")
	result, err := kerbClient.LoginWithKerberos(targetURL, authHost, !insecure)
	if err != nil {
		kerbClient.Close()
		return nil, nil, fmt.Errorf("login failed: %w", err)
	}

	return kerbClient, result, nil
}
