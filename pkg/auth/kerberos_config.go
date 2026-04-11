package auth

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
)

const defaultKrb5Conf = `[libdefaults]
    default_realm = CERN.CH
    dns_lookup_realm = false
    dns_lookup_kdc = true
    rdns = false
    ticket_lifetime = 24h
    forwardable = true
    udp_preference_limit = 0
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
    CERN.CH = {
        kdc = cerndc.cern.ch
        default_domain = cern.ch
    }

[domain_realm]
    .cern.ch = CERN.CH
    cern.ch = CERN.CH
`

// Krb5ConfigSource constants for config source options.
const (
	Krb5ConfigEmbedded = "embedded"
	Krb5ConfigSystem   = "system"
)

// AuthConfig holds authentication method configuration.
type AuthConfig struct {
	KeytabPath    string // Explicit keytab path from --keytab flag
	ForcePassword bool   // --use-password flag
	ForceKeytab   bool   // --use-keytab flag (or implied by --keytab)
	ForceCCache   bool   // --use-ccache flag
	Quiet         bool   // --quiet flag (suppress non-error output)
}

// tryKeytabAuth attempts keytab-based Kerberos authentication.
// If username is empty, uses the first principal from the keytab.
func tryKeytabAuth(cfg *config.Config, keytabPath, username string, quiet bool) (*client.Client, string, error) {
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load keytab from %s: %w", keytabPath, err)
	}

	principal := username
	if principal == "" {
		entries := kt.Entries
		if len(entries) == 0 {
			return nil, "", fmt.Errorf("keytab contains no entries")
		}
		// Use first principal from keytab
		// Principal has Components ([]string) and Realm fields
		components := entries[0].Principal.Components
		realm := entries[0].Principal.Realm
		if len(components) > 0 {
			principal = strings.Join(components, "/")
			if realm != "" {
				principal = principal + "@" + realm
			}
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "Using principal %s from keytab %s\n", principal, keytabPath)
		}
	}

	if principal == "" {
		return nil, "", fmt.Errorf("could not determine principal from keytab")
	}

	// Strip @REALM suffix for the client
	shortUsername := principal
	if idx := strings.Index(principal, "@"); idx != -1 {
		shortUsername = principal[:idx]
	}

	cl := client.NewWithKeytab(shortUsername, "CERN.CH", kt, cfg, client.DisablePAFXFAST(true))
	if err := cl.Login(); err != nil {
		return nil, "", fmt.Errorf("keytab login failed for %s: %w", principal, err)
	}

	return cl, NormalizePrincipal(principal), nil
}

// findDefaultKeytabPath returns the keytab path from default locations.
func findDefaultKeytabPath() string {
	// Check user home directory
	if usr, err := user.Current(); err == nil {
		userKeytab := filepath.Join(usr.HomeDir, ".keytab")
		if _, err := os.Stat(userKeytab); err == nil {
			return userKeytab
		}
	}

	// Check system default
	if _, err := os.Stat("/etc/krb5.keytab"); err == nil {
		return "/etc/krb5.keytab"
	}

	return ""
}

func keytabPathFromEnv() (string, bool, error) {
	envPath := os.Getenv("KRB5_KTNAME")
	if envPath == "" {
		return "", false, nil
	}

	path := envPath
	switch {
	case strings.HasPrefix(envPath, "FILE:"):
		path = strings.TrimPrefix(envPath, "FILE:")
	case strings.HasPrefix(envPath, "WRFILE:"):
		path = strings.TrimPrefix(envPath, "WRFILE:")
	case strings.Contains(envPath, ":"):
		return "", true, fmt.Errorf("KRB5_KTNAME=%q uses an unsupported keytab type", envPath)
	}

	if _, err := os.Stat(path); err != nil { // #nosec G703 -- KRB5_KTNAME is an explicit user-provided keytab path
		return "", true, fmt.Errorf("KRB5_KTNAME keytab not found at %s: %w", path, err)
	}

	return path, true, nil
}

// LoadKrb5Config loads Kerberos configuration from the specified source.
// source can be:
//   - "" or "embedded": use the built-in CERN.CH configuration
//   - "system": use system krb5.conf (KRB5_CONFIG env var or /etc/krb5.conf)
//   - "/path/to/file": use a custom configuration file
//
//nolint:cyclop // Handles multiple config sources with platform-specific paths
func LoadKrb5Config(source string) (*config.Config, error) {
	switch source {
	case "", Krb5ConfigEmbedded:
		return config.NewFromString(defaultKrb5Conf)

	case Krb5ConfigSystem:
		// Check KRB5_CONFIG environment variable first
		configPath := os.Getenv("KRB5_CONFIG")
		if configPath == "" {
			// Fall back to default system path
			if runtime.GOOS == "darwin" {
				// macOS: check common locations
				paths := []string{"/etc/krb5.conf", "/Library/Preferences/edu.mit.Kerberos"}
				for _, p := range paths {
					if _, err := os.Stat(p); err == nil {
						configPath = p
						break
					}
				}
			} else {
				configPath = "/etc/krb5.conf"
			}
		}
		if configPath == "" {
			return nil, fmt.Errorf("no system krb5.conf found")
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load system krb5.conf from %s: %w", configPath, err)
		}
		return cfg, nil

	default:
		// Treat as a file path
		if _, err := os.Stat(source); err != nil {
			return nil, fmt.Errorf("krb5.conf not found at %s: %w", source, err)
		}
		cfg, err := config.Load(source)
		if err != nil {
			return nil, fmt.Errorf("failed to load krb5.conf from %s: %w", source, err)
		}
		return cfg, nil
	}
}
