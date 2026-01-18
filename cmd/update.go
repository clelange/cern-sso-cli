// Package cmd provides CLI commands for the CERN SSO tool.
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/clelange/cern-sso-cli/pkg/update"
)

var checkOnly bool

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for and install updates",
	Long: `Check for available updates and optionally install them.

By default, this command will download and install the latest version.
Use --check to only check for updates without installing.

If the binary was installed via Homebrew, the command will suggest using
'brew upgrade' instead of performing a self-update.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runUpdate()
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().BoolVar(&checkOnly, "check", false, "Only check for updates, don't install")
}

//nolint:cyclop // Update flow with multiple checks and user feedback
func runUpdate() error {
	currentVersion := version

	logInfo("Current version: %s\n", currentVersion)
	logInfo("Checking for updates...\n")

	// Fetch latest release info
	release, err := update.CheckForUpdate()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestVersion := release.TagName
	cmp := update.CompareVersions(currentVersion, latestVersion)

	if cmp >= 0 {
		logInfo("You are running the latest version (%s)\n", currentVersion)
		return nil
	}

	logInfo("New version available: %s\n", latestVersion)

	// If check-only mode, stop here
	if checkOnly {
		logInfo("\nRun 'cern-sso-cli update' to install the update.\n")
		return nil
	}

	// Check if installed via Homebrew
	if update.IsHomebrewInstall() {
		logInfo("\nThis binary appears to be installed via Homebrew.\n")
		logInfo("Please update using: brew upgrade cern-sso-cli\n")
		return nil
	}

	// Get the download URL for current platform
	binaryURL, checksumURL, err := update.GetAssetForCurrentPlatform(release)
	if err != nil {
		return fmt.Errorf("failed to find binary for your platform: %w", err)
	}

	// Extract asset name from URL for checksum lookup
	urlParts := strings.Split(binaryURL, "/")
	assetName := urlParts[len(urlParts)-1]

	logInfo("Downloading %s...\n", assetName)

	// Download binary with progress
	binary, err := update.DownloadBinary(binaryURL, func(downloaded, total int64) {
		if !quiet {
			percent := float64(downloaded) / float64(total) * 100
			fmt.Fprintf(os.Stderr, "\rDownloading... %.1f%%", percent)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to download update: %w", err)
	}
	if !quiet {
		fmt.Fprintln(os.Stderr) // New line after progress
	}

	// Verify checksum if available
	if checksumURL != "" {
		logInfo("Verifying checksum...\n")
		checksums, err := update.FetchChecksums(checksumURL)
		if err != nil {
			logInfo("Warning: Could not fetch checksums: %v\n", err)
		} else if expectedChecksum, ok := checksums[assetName]; ok {
			if err := update.VerifyChecksum(binary, expectedChecksum); err != nil {
				return fmt.Errorf("checksum verification failed: %w", err)
			}
			logInfo("Checksum verified.\n")
		} else {
			logInfo("Warning: No checksum found for %s\n", assetName)
		}
	}

	// Replace binary
	logInfo("Installing update...\n")
	if err := update.ReplaceBinary(binary); err != nil {
		return fmt.Errorf("failed to install update: %w", err)
	}

	logInfo("Successfully updated to %s\n", latestVersion)
	return nil
}
