// Package main provides the entry point for the CERN SSO CLI.
package main

import "github.com/clelange/cern-sso-cli/cmd"

// version is set at build time via ldflags
var version = "dev"

func main() {
	cmd.SetVersion(version)
	cmd.Execute()
}
