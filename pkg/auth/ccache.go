package auth

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

// NormalizePrincipal ensures the username has @CERN.CH suffix with correct case.
// Examples:
//   - "clange" -> "clange@CERN.CH"
//   - "clange@cern.ch" -> "clange@CERN.CH"
//   - "clange@CERN.CH" -> "clange@CERN.CH" (unchanged)
//   - "" -> "" (empty string returns empty)
func NormalizePrincipal(username string) string {
	if username == "" {
		return ""
	}
	if !strings.Contains(username, "@") {
		username = username + "@CERN.CH"
	}
	suffix := "@cern.ch"
	lower := strings.ToLower(username)
	if strings.HasSuffix(lower, suffix) {
		username = username[:len(username)-len(suffix)] + "@CERN.CH"
	}
	return username
}

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

// ConvertSpecificCacheToFile converts a specific macOS API cache to a file-based cache.
// Uses kgetcred to export the TGT from the specified cache to a file.
// This allows using a non-default principal without modifying the system default.
func ConvertSpecificCacheToFile(cacheInfo *CacheInfo) (string, error) {
	if runtime.GOOS != "darwin" {
		return "", fmt.Errorf("specific cache conversion only supported on macOS")
	}

	// Create cache file path unique to this principal
	// Use a hash of principal to avoid issues with special characters
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home dir: %w", err)
	}
	cacheDir := filepath.Join(homeDir, ".cache", "cern-sso-cli")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create cache dir: %w", err)
	}

	cacheFile := filepath.Join(cacheDir, fmt.Sprintf("krb5cc_%d_%s", os.Getuid(), strings.Replace(cacheInfo.Principal, "@", "_", -1)))

	// Use kgetcred to export the TGT from the specific API cache to a file
	// This extracts only the TGT (krbtgt/CERN.CH@CERN.CH) which is sufficient for SPNEGO
	cmd := exec.Command("kgetcred", "-c", cacheInfo.CacheName, "--out-cache="+cacheFile, "krbtgt/CERN.CH@CERN.CH")
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("kgetcred failed for %s: %w (output: %s)", cacheInfo.Principal, err, string(output))
	}

	return cacheFile, nil
}

// CacheInfo contains information about a Kerberos credential cache.
type CacheInfo struct {
	Principal string    // e.g., "clange@CERN.CH"
	CacheName string    // e.g., "API:EE3D6722-361C-4ACD-912F-DE88264999E2"
	Expires   time.Time // Expiry time of the TGT
	IsDefault bool      // True if this is the active cache (marked with *)
}

// ListCERNCaches returns all CERN.CH credential caches available on the system.
// This parses the output of `klist -l` and filters to only CERN.CH realm caches.
func ListCERNCaches() ([]CacheInfo, error) {
	cmd := exec.Command("klist", "-l")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("klist -l failed: %w", err)
	}

	var caches []CacheInfo
	lines := strings.Split(string(output), "\n")

	// Skip header line(s) - format is:
	//     Name               Cache name                                 Expires
	//   clemens@FNAL.GOV   API:AD93A96B-...   Jan  3 21:59:21 2026
	// * clange@CERN.CH     API:EE3D6722-...   Jan  3 21:59:20 2026
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Name") {
			continue
		}

		// Check for default marker
		isDefault := false
		if strings.HasPrefix(line, "*") {
			isDefault = true
			line = strings.TrimSpace(line[1:])
		}

		// Parse fields: Principal, CacheName, Expires (month day time year)
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		principal := fields[0]
		cacheName := fields[1]

		// Only include CERN.CH caches
		if !strings.HasSuffix(principal, "@CERN.CH") {
			continue
		}

		// Parse expiry time: "Jan  3 21:59:21 2026" -> fields[2:6]
		// Handle both single and double-digit days
		expiryStr := strings.Join(fields[2:], " ")
		expires, _ := parseKlistExpiry(expiryStr)

		caches = append(caches, CacheInfo{
			Principal: principal,
			CacheName: cacheName,
			Expires:   expires,
			IsDefault: isDefault,
		})
	}

	return caches, nil
}

// parseKlistExpiry parses the expiry time from klist output.
// Format: "Jan  3 21:59:21 2026" or "Jan 13 21:59:21 2026"
func parseKlistExpiry(s string) (time.Time, error) {
	// Normalize multiple spaces to single space
	s = strings.Join(strings.Fields(s), " ")
	// Try parsing with Go's time format
	return time.Parse("Jan 2 15:04:05 2006", s)
}

// FindCacheByUsername finds a CERN.CH cache by username.
// The username can be provided with or without the @CERN.CH suffix.
// Returns error if no matching cache is found.
func FindCacheByUsername(username string) (*CacheInfo, error) {
	// Normalize username to include @CERN.CH with correct case
	username = NormalizePrincipal(username)

	caches, err := ListCERNCaches()
	if err != nil {
		return nil, err
	}

	for i := range caches {
		if caches[i].Principal == username {
			return &caches[i], nil
		}
	}

	// Build helpful error message
	if len(caches) == 0 {
		return nil, fmt.Errorf("no Kerberos cache found for user '%s': no CERN.CH caches available", username)
	}

	var available []string
	for _, c := range caches {
		expiry := c.Expires.Format("Jan 2 15:04:05")
		available = append(available, fmt.Sprintf("  %s (expires %s)", c.Principal, expiry))
	}
	return nil, fmt.Errorf("no Kerberos cache found for user '%s'\nAvailable CERN.CH caches:\n%s",
		username, strings.Join(available, "\n"))
}
