//go:build !nowebauthn
// +build !nowebauthn

// Package cmd provides CLI commands for the CERN SSO tool.
package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

// webauthnCmd represents the webauthn command group.
var webauthnCmd = &cobra.Command{
	Use:   "webauthn",
	Short: "WebAuthn/FIDO2 device management",
	Long:  `Commands for managing and listing WebAuthn/FIDO2 security devices.`,
}

// webauthnListCmd lists available FIDO2 devices.
var webauthnListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available FIDO2 devices",
	Long: `List all available FIDO2/WebAuthn devices connected to the system.

Each device is shown with its index, which can be used with --webauthn-device-index
to select a specific device for authentication.

Note: This tool uses libfido2, which only supports USB/NFC security keys.
macOS Touch ID and iCloud Keychain passkeys are not detected by this tool.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		devices, err := auth.ListFIDO2Devices()
		if err != nil {
			return fmt.Errorf("failed to list devices: %w", err)
		}

		if len(devices) == 0 {
			fmt.Fprintln(os.Stderr, "No FIDO2 devices found.")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Note: This tool only supports USB/NFC security keys (e.g., YubiKey).")
			fmt.Fprintln(os.Stderr, "macOS Touch ID and iCloud Keychain passkeys are not supported by libfido2.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "INDEX\tPRODUCT\tPATH")
		for _, d := range devices {
			fmt.Fprintf(w, "%d\t%s\t%s\n", d.Index, d.Product, d.Path)
		}
		w.Flush()

		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Use --webauthn-device-index <INDEX> to select a specific device.")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(webauthnCmd)
	webauthnCmd.AddCommand(webauthnListCmd)
}
