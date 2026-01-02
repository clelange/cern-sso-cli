package auth

import (
	"fmt"
	"os"
	"os/exec"
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

// GetPrincipalFromKlist parses the principal from klist output.
// Returns empty string if no principal found.
func GetPrincipalFromKlist() (string, error) {
	cmd := exec.Command("klist")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("klist failed: %w", err)
	}

	// Parse output looking for "Principal: user@REALM"
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Principal:") {
			principal := strings.TrimSpace(strings.TrimPrefix(line, "Principal:"))
			if principal != "" {
				return principal, nil
			}
		}
	}

	return "", fmt.Errorf("no principal found in klist output")
}

// ConvertAPICacheToFile attempts to convert macOS API credential cache to a file-based cache.
// Uses kinit --keychain to get tickets from keychain-stored password.
// Returns the path to the created file cache, or error if conversion fails.
func ConvertAPICacheToFile() (string, error) {
	if !IsMacOSAPICCache() {
		return "", fmt.Errorf("not using macOS API cache")
	}

	// Get the principal from current cache
	principal, err := GetPrincipalFromKlist()
	if err != nil {
		return "", fmt.Errorf("cannot get principal: %w", err)
	}

	// Create cache file path
	cacheFile := fmt.Sprintf("/tmp/krb5cc_sso_cli_%d", os.Getuid())

	// Try keychain first (if user set it up with kinit --keychain --save)
	// Close stdin to prevent password prompts from blocking
	cmd := exec.Command("kinit", "-c", cacheFile, "--keychain", principal)
	cmd.Stdin = nil
	if err := cmd.Run(); err == nil {
		return cacheFile, nil
	}

	return "", fmt.Errorf("could not convert API cache to file cache for %s (try: kinit --keychain --save %s)", principal, principal)
}
