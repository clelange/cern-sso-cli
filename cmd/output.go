package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

func writeCommandOutput(jsonEnabled bool, jsonValue any, textLines ...string) error {
	if quiet {
		return nil
	}

	if jsonEnabled {
		return json.NewEncoder(os.Stdout).Encode(jsonValue)
	}

	for _, line := range textLines {
		if _, err := fmt.Fprintln(os.Stdout, line); err != nil {
			return err
		}
	}

	return nil
}
