package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for cern-sso-cli.

To load completions:

Bash:
  $ source <(cern-sso-cli completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ cern-sso-cli completion bash > /etc/bash_completion.d/cern-sso-cli
  # macOS:
  $ cern-sso-cli completion bash > $(brew --prefix)/etc/bash_completion.d/cern-sso-cli

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it.  You can execute the following once:
  $ echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ cern-sso-cli completion zsh > "${fpath[1]}/_cern-sso-cli"

  # You will need to start a new shell for this setup to take effect.

Fish:
  $ cern-sso-cli completion fish | source

  # To load completions for each session, execute once:
  $ cern-sso-cli completion fish > ~/.config/fish/completions/cern-sso-cli.fish

PowerShell:
  PS> cern-sso-cli completion powershell | Out-String | Invoke-Expression

  # To load completions for every new session, run:
  PS> cern-sso-cli completion powershell > cern-sso-cli.ps1
  # and source this file from your PowerShell profile.
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			_ = cmd.Root().GenBashCompletion(os.Stdout)
		case "zsh":
			_ = cmd.Root().GenZshCompletion(os.Stdout)
		case "fish":
			_ = cmd.Root().GenFishCompletion(os.Stdout, true)
		case "powershell":
			_ = cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
