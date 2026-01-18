// Package update provides self-update functionality for cern-sso-cli.
package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

const (
	// GitHubRepo is the repository path for releases.
	GitHubRepo = "clelange/cern-sso-cli"
	// GitHubAPIURL is the base URL for GitHub API.
	GitHubAPIURL = "https://api.github.com"
)

// ReleaseAsset represents a downloadable asset from a GitHub release.
type ReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// ReleaseInfo contains information about a GitHub release.
type ReleaseInfo struct {
	TagName string         `json:"tag_name"`
	Assets  []ReleaseAsset `json:"assets"`
}

// CheckForUpdate queries GitHub for the latest release.
func CheckForUpdate() (*ReleaseInfo, error) {
	url := fmt.Sprintf("%s/repos/%s/releases/latest", GitHubAPIURL, GitHubRepo)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "cern-sso-cli")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch release info: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release ReleaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse release info: %w", err)
	}

	return &release, nil
}

// CompareVersions compares two version strings.
// Returns: -1 if current < latest, 0 if equal, 1 if current > latest.
// Handles "dev" as always older than any release version.
//
//nolint:cyclop // Version parsing with multiple format handling
func CompareVersions(current, latest string) int {
	// Normalise versions by removing 'v' prefix
	current = strings.TrimPrefix(current, "v")
	latest = strings.TrimPrefix(latest, "v")

	// Handle dev builds - always considered older
	if current == "dev" || strings.HasPrefix(current, "dev") {
		return -1
	}
	if latest == "dev" || strings.HasPrefix(latest, "dev") {
		return 1
	}

	// Split into parts
	currentParts := strings.Split(current, ".")
	latestParts := strings.Split(latest, ".")

	// Compare each part
	maxLen := len(currentParts)
	if len(latestParts) > maxLen {
		maxLen = len(latestParts)
	}

	for i := 0; i < maxLen; i++ {
		var currentNum, latestNum int

		if i < len(currentParts) {
			// Handle pre-release suffixes like "1.0.0-rc1"
			part := strings.Split(currentParts[i], "-")[0]
			_, _ = fmt.Sscanf(part, "%d", &currentNum)
		}
		if i < len(latestParts) {
			part := strings.Split(latestParts[i], "-")[0]
			_, _ = fmt.Sscanf(part, "%d", &latestNum)
		}

		if currentNum < latestNum {
			return -1
		}
		if currentNum > latestNum {
			return 1
		}
	}

	return 0
}

// GetAssetForCurrentPlatform returns the download URL for the appropriate binary.
func GetAssetForCurrentPlatform(release *ReleaseInfo) (binaryURL, checksumURL string, err error) {
	osName := runtime.GOOS
	archName := runtime.GOARCH

	// Determine if current binary has WebAuthn support
	hasWebAuthn := auth.IsWebAuthnAvailable()

	// Build expected asset name
	var assetName string
	if hasWebAuthn {
		assetName = fmt.Sprintf("cern-sso-cli-%s-%s-webauthn", osName, archName)
	} else {
		assetName = fmt.Sprintf("cern-sso-cli-%s-%s", osName, archName)
	}

	// Find matching asset
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			binaryURL = asset.BrowserDownloadURL
		}
		if asset.Name == "checksums.txt" {
			checksumURL = asset.BrowserDownloadURL
		}
	}

	if binaryURL == "" {
		// Try without webauthn suffix as fallback
		if hasWebAuthn {
			fallbackName := fmt.Sprintf("cern-sso-cli-%s-%s", osName, archName)
			for _, asset := range release.Assets {
				if asset.Name == fallbackName {
					binaryURL = asset.BrowserDownloadURL
					break
				}
			}
		}
		if binaryURL == "" {
			return "", "", fmt.Errorf("no binary found for %s/%s (webauthn=%v)", osName, archName, hasWebAuthn)
		}
	}

	return binaryURL, checksumURL, nil
}

// DownloadBinary downloads the binary from the given URL.
//
//nolint:cyclop // Download with progress tracking and chunked reading
func DownloadBinary(url string, progress func(downloaded, total int64)) ([]byte, error) {
	resp, err := http.Get(url) // #nosec G107
	if err != nil {
		return nil, fmt.Errorf("failed to download binary: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	var data []byte
	if progress != nil && resp.ContentLength > 0 {
		data = make([]byte, 0, resp.ContentLength)
		buf := make([]byte, 32*1024)
		var downloaded int64
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				data = append(data, buf[:n]...)
				downloaded += int64(n)
				progress(downloaded, resp.ContentLength)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to read response: %w", err)
			}
		}
	} else {
		data, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read binary: %w", err)
		}
	}

	return data, nil
}

// FetchChecksums downloads and parses the checksums file.
func FetchChecksums(url string) (map[string]string, error) {
	resp, err := http.Get(url) // #nosec G107
	if err != nil {
		return nil, fmt.Errorf("failed to download checksums: %w", err)
	}
	defer func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums download failed with status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read checksums: %w", err)
	}

	checksums := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			checksums[parts[1]] = parts[0]
		}
	}

	return checksums, nil
}

// VerifyChecksum verifies the SHA256 checksum of the binary.
func VerifyChecksum(data []byte, expectedChecksum string) error {
	hash := sha256.Sum256(data)
	actual := hex.EncodeToString(hash[:])

	if actual != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actual)
	}

	return nil
}

// ReplaceBinary atomically replaces the current executable with new binary data.
func ReplaceBinary(newBinary []byte) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Resolve symlinks to get actual binary path
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Get file info to preserve permissions
	info, err := os.Stat(execPath)
	if err != nil {
		return fmt.Errorf("failed to stat executable: %w", err)
	}

	// Write to temporary file in the same directory (for atomic rename)
	dir := filepath.Dir(execPath)
	tmpFile, err := os.CreateTemp(dir, "cern-sso-cli-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	// Write new binary
	if _, err := tmpFile.Write(newBinary); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write new binary: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Set permissions
	if err := os.Chmod(tmpPath, info.Mode()); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, execPath); err != nil {
		return fmt.Errorf("failed to replace binary: %w", err)
	}

	// Clear tmpPath so defer doesn't try to remove it
	tmpPath = ""

	return nil
}

// IsHomebrewInstall checks if the binary appears to be installed via Homebrew.
func IsHomebrewInstall() bool {
	execPath, err := os.Executable()
	if err != nil {
		return false
	}

	// Resolve symlinks
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return false
	}

	// Check common Homebrew paths
	homebrewPaths := []string{
		"/opt/homebrew/",     // Apple Silicon
		"/usr/local/Cellar/", // Intel Mac
		"/home/linuxbrew/",   // Linux Homebrew
		"/.linuxbrew/",       // User-local Linux Homebrew
	}

	for _, prefix := range homebrewPaths {
		if strings.Contains(execPath, prefix) {
			return true
		}
	}

	return false
}

// GetExecutablePath returns the resolved path to the current executable.
func GetExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(execPath)
}
