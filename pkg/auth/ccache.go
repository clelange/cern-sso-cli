package auth

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

// FindCCachePath locates the Kerberos credential cache file.
// Returns empty string if no usable file-based cache is found.
func FindCCachePath() string {
	// Check KRB5CCNAME environment variable first
	ccachePath := os.Getenv("KRB5CCNAME")
	if ccachePath != "" {
		// Handle FILE: prefix
		if strings.HasPrefix(ccachePath, "FILE:") {
			return strings.TrimPrefix(ccachePath, "FILE:")
		}
		// API: prefix (macOS) - not usable from pure Go
		if strings.HasPrefix(ccachePath, "API:") {
			return ""
		}
		// If it's a plain path, check if it exists
		if _, err := os.Stat(ccachePath); err == nil {
			return ccachePath
		}
	}

	// Try default paths based on platform
	uid := getUID()
	if uid == "" {
		return ""
	}

	defaultPaths := []string{
		"/tmp/krb5cc_" + uid,
	}

	// On macOS, also check for file caches in common locations
	if runtime.GOOS == "darwin" {
		home := os.Getenv("HOME")
		if home != "" {
			defaultPaths = append(defaultPaths,
				home+"/.krb5cc",
				home+"/Library/Caches/krb5cc",
			)
		}
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// getUID returns the current user's UID as a string.
func getUID() string {
	// Try UID environment variable first (might not be set)
	uid := os.Getenv("UID")
	if uid != "" {
		return uid
	}

	// Use os.Getuid() which works on Unix-like systems
	return strconv.Itoa(os.Getuid())
}

// NewClientFromCCache attempts to create a Kerberos client from the credential cache.
// Returns nil and an error if the cache is not found, invalid, or the TGT is expired.
func NewClientFromCCache(cfg *config.Config) (*client.Client, error) {
	ccachePath := FindCCachePath()
	if ccachePath == "" {
		return nil, fmt.Errorf("no file-based credential cache found")
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load credential cache from %s: %w", ccachePath, err)
	}

	cl, err := client.NewFromCCache(ccache, cfg, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, fmt.Errorf("failed to create client from credential cache: %w", err)
	}

	return cl, nil
}

// IsMacOSAPICCache returns true if we're on macOS and the credential cache
// is using the API: scheme (which is not accessible from pure Go).
func IsMacOSAPICCache() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	ccachePath := os.Getenv("KRB5CCNAME")
	// If not set, macOS defaults to API cache
	return ccachePath == "" || strings.HasPrefix(ccachePath, "API:")
}
