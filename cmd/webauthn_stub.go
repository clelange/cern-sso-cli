//go:build nowebauthn
// +build nowebauthn

// Package cmd provides CLI commands for the CERN SSO tool.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
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
	Long:  `List all available FIDO2/WebAuthn devices connected to the system.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fmt.Errorf("WebAuthn support is disabled in this build.\n" +
			"Use a WebAuthn-enabled binary to list FIDO2 devices.")
	},
}

func init() {
	rootCmd.AddCommand(webauthnCmd)
	webauthnCmd.AddCommand(webauthnListCmd)
}
