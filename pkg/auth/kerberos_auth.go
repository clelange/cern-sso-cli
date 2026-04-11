package auth

import (
	"fmt"
	"os"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// NewKerberosClient creates a new Kerberos client with automatic authentication.
// This is a convenience wrapper that uses automatic authentication method selection.
// krb5ConfigSource can be "embedded" (default), "system", or a file path.
func NewKerberosClient(version string, krb5ConfigSource string, verifyCert bool) (*KerberosClient, error) {
	return NewKerberosClientWithConfig(version, krb5ConfigSource, "", verifyCert, AuthConfig{})
}

// NewKerberosClientWithUser creates a new Kerberos client for a specific user.
// This is a convenience wrapper that uses automatic authentication method selection.
// krb5ConfigSource can be "embedded" (default), "system", or a file path.
func NewKerberosClientWithUser(version string, krb5ConfigSource string, krbUsername string, verifyCert bool) (*KerberosClient, error) {
	return NewKerberosClientWithConfig(version, krb5ConfigSource, krbUsername, verifyCert, AuthConfig{})
}

// tryPasswordAuth attempts password-based Kerberos authentication.
// Returns the client if successful, or an error if login fails.
func tryPasswordAuth(cfg *config.Config, username, password string) (*client.Client, error) {
	// Strip @CERN.CH suffix for the client
	shortUsername := username
	if strings.HasSuffix(strings.ToLower(username), "@cern.ch") {
		shortUsername = strings.Split(username, "@")[0]
	}
	cl := client.NewWithPassword(shortUsername, "CERN.CH", password, cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login failed for %s: %w", username, err)
	}
	return cl, nil
}

// tryUserCacheAuth attempts to authenticate using a specific user's cache on macOS.
// Returns the client and principal if successful, or an error if not found/failed.
func tryUserCacheAuth(cfg *config.Config, username string) (*client.Client, string, error) {
	if !IsMacOSAPICCache() {
		return nil, "", fmt.Errorf("not macOS API cache")
	}

	cacheInfo, err := FindCacheByUsername(username)
	if err != nil {
		return nil, "", err // Includes list of available caches
	}

	// Convert API cache to file-based cache
	filePath, err := ConvertSpecificCacheToFile(cacheInfo)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert cache: %w", err)
	}

	_ = os.Setenv("KRB5CCNAME", filePath)
	cl, err := NewClientFromCCache(cfg)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load converted cache: %w", err)
	}

	return cl, cacheInfo.Principal, nil
}

// tryDefaultCacheAuth attempts authentication from the default credential cache.
// On macOS with API cache, attempts conversion first.
// Returns the client and extracted principal if successful.
func tryDefaultCacheAuth(cfg *config.Config) (*client.Client, string, error) {
	// Try file-based cache directly
	cl, err := NewClientFromCCache(cfg)
	if err == nil {
		username := extractUsernameFromClient(cl)
		return cl, username, nil
	}

	// On macOS, try to convert API cache to file cache
	if IsMacOSAPICCache() {
		filePath, convErr := ConvertAPICacheToFile()
		if convErr == nil {
			_ = os.Setenv("KRB5CCNAME", filePath)
			cl, err = NewClientFromCCache(cfg)
			if err == nil {
				username := extractUsernameFromClient(cl)
				return cl, username, nil
			}
		}
	}

	return nil, "", fmt.Errorf("no credential cache available")
}

// NewKerberosClientWithConfig creates a new Kerberos client with full configuration.
// This function supports explicit authentication method selection via AuthConfig,
// and automatic method selection when no explicit method is specified.
//
// Authentication priority (when no explicit method is specified):
//  1. Password (if KRB5_USERNAME and KRB5_PASSWORD are set)
//  2. Keytab (if KRB5_KTNAME is set)
//  3. Credential cache (ccache)
//  4. Default keytab locations (~/.keytab, /etc/krb5.keytab)
//
//nolint:cyclop // Core auth function with multiple method discovery paths
func NewKerberosClientWithConfig(version string, krb5ConfigSource string, krbUsername string,
	verifyCert bool, authConfig AuthConfig) (*KerberosClient, error) {

	cfg, err := LoadKrb5Config(krb5ConfigSource)
	if err != nil {
		return nil, fmt.Errorf("failed to load krb5 config: %w", err)
	}

	// ═══════════════════════════════════════════════════════════════
	// EXPLICIT METHOD SELECTION (--use-* flags)
	// ═══════════════════════════════════════════════════════════════

	if authConfig.ForcePassword {
		username := os.Getenv("KRB5_USERNAME")
		password := os.Getenv("KRB5_PASSWORD")
		if krbUsername != "" {
			// Warn if --user differs from KRB5_USERNAME
			if username != "" && username != krbUsername && !strings.EqualFold(NormalizePrincipal(username), NormalizePrincipal(krbUsername)) {
				if !authConfig.Quiet {
					fmt.Fprintf(os.Stderr, "Warning: --user (%s) differs from KRB5_USERNAME (%s), using --user\n", krbUsername, username)
				}
			}
			username = krbUsername
		}
		if username == "" || password == "" {
			return nil, fmt.Errorf("--use-password requires KRB5_USERNAME and KRB5_PASSWORD environment variables")
		}
		cl, err := tryPasswordAuth(cfg, username, password)
		if err != nil {
			return nil, err
		}
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, NormalizePrincipal(username))
	}

	if authConfig.ForceKeytab {
		ktPath := authConfig.KeytabPath
		if ktPath == "" {
			envPath, set, envErr := keytabPathFromEnv()
			if set {
				if envErr != nil {
					return nil, envErr
				}
				ktPath = envPath
			} else {
				ktPath = findDefaultKeytabPath()
			}
		}
		if ktPath == "" {
			return nil, fmt.Errorf("--use-keytab specified but no keytab found (use --keytab, KRB5_KTNAME, or ~/.keytab)")
		}
		cl, principal, err := tryKeytabAuth(cfg, ktPath, krbUsername, authConfig.Quiet)
		if err != nil {
			return nil, err
		}
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
	}

	if authConfig.ForceCCache {
		if krbUsername != "" {
			if cl, principal, err := tryUserCacheAuth(cfg, krbUsername); err == nil {
				return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
			}
		}
		if cl, principal, err := tryDefaultCacheAuth(cfg); err == nil {
			return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
		}
		return nil, fmt.Errorf("--use-ccache specified but no valid credential cache found")
	}

	// ═══════════════════════════════════════════════════════════════
	// AUTOMATIC MODE (no --use-* flags)
	// ═══════════════════════════════════════════════════════════════

	username := os.Getenv("KRB5_USERNAME")
	password := os.Getenv("KRB5_PASSWORD")
	if krbUsername != "" {
		// Warn if --user differs from KRB5_USERNAME when both are set
		if username != "" && password != "" {
			if !strings.EqualFold(NormalizePrincipal(username), NormalizePrincipal(krbUsername)) {
				if !authConfig.Quiet {
					fmt.Fprintf(os.Stderr, "Warning: --user (%s) differs from KRB5_USERNAME (%s), using --user for authentication\n", krbUsername, username)
				}
				// Do not use the environment password if the user differs
				password = ""
			}
		}
		username = krbUsername
	}

	// Priority 1: Password (if credentials are set)
	if username != "" && password != "" {
		cl, err := tryPasswordAuth(cfg, username, password)
		if err != nil {
			return nil, err
		}
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, NormalizePrincipal(username))
	}

	// Priority 2: Keytab via KRB5_KTNAME
	if path, set, envErr := keytabPathFromEnv(); set {
		if envErr != nil {
			return nil, envErr
		}
		cl, principal, err := tryKeytabAuth(cfg, path, username, authConfig.Quiet)
		if err != nil {
			return nil, fmt.Errorf("authentication failed with KRB5_KTNAME=%s: %w", os.Getenv("KRB5_KTNAME"), err)
		}
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
	}

	// Priority 3: Credential cache
	if krbUsername != "" {
		if cl, principal, err := tryUserCacheAuth(cfg, krbUsername); err == nil {
			return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
		}
	}
	if cl, principal, err := tryDefaultCacheAuth(cfg); err == nil {
		return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
	}

	// Priority 4: Default keytab locations
	if userKeytab := findDefaultKeytabPath(); userKeytab != "" {
		cl, principal, err := tryKeytabAuth(cfg, userKeytab, username, authConfig.Quiet)
		if err == nil {
			return newKerberosClientFromKrbClientWithUser(cl, version, verifyCert, principal)
		} else if !authConfig.Quiet {
			fmt.Fprintf(os.Stderr, "Warning: found keytab at %s but authentication failed: %v\n", userKeytab, err)
		}
	}

	// No method available
	if IsMacOSAPICCache() {
		return nil, fmt.Errorf("no authentication method available. Options:\n" +
			"  1. kinit --keychain your-username@CERN.CH (one-time keychain setup)\n" +
			"  2. --keytab ~/.keytab (use a keytab file)\n" +
			"  3. export KRB5_KTNAME=~/.keytab (keytab via environment)\n" +
			"  4. export KRB5_USERNAME=... KRB5_PASSWORD=... (credentials)")
	}
	return nil, fmt.Errorf("no authentication method available (no credentials, keytab, or ccache)")
}
