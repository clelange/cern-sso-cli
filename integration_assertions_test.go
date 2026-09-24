package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Keep response bodies and redirect URLs out of diagnostics: they may contain tokens.
func validateOpenShiftTokenPage(resp *http.Response, body, oauthHost string) error {
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected HTTP 200, got %d", resp.StatusCode)
	}
	if resp.Request.URL.Host != oauthHost {
		return errors.New("redirected away from the OpenShift OAuth host")
	}
	if strings.Contains(body, "Sign in to CERN") {
		return errors.New("received CERN SSO login page")
	}
	if !strings.Contains(body, "Display Token") && !strings.Contains(body, "sha256~") && !strings.Contains(body, "oc login") {
		return errors.New("response is not an OpenShift token page")
	}
	return nil
}

func TestValidateOpenShiftTokenPage(t *testing.T) {
	const oauthHost = "oauth-openshift.example.com"
	tests := []struct {
		name   string
		status int
		url    string
		body   string
		valid  bool
	}{
		{"display form", 200, "https://" + oauthHost, "<button>Display Token</button>", true},
		{"token", 200, "https://" + oauthHost, "<code>sha256~synthetic-secret</code>", true},
		{"command", 200, "https://" + oauthHost, "<pre>oc login --token=synthetic-secret</pre>", true},
		{"http error", 403, "https://" + oauthHost, "synthetic-secret Display Token", false},
		{"redirected login", 200, "https://auth.example.com/?code=synthetic-secret", "Display Token", false},
		{"login page", 200, "https://" + oauthHost, "Sign in to CERN Display Token synthetic-secret", false},
		{"unexpected page", 200, "https://" + oauthHost, "<html>synthetic-secret</html>", false},
		{"empty page", 200, "https://" + oauthHost, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = validateOpenShiftTokenPage(&http.Response{StatusCode: tt.status, Request: req}, tt.body, oauthHost)
			if (err == nil) != tt.valid {
				t.Fatalf("valid = %v, got error %v", tt.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-secret") {
				t.Fatal("validation diagnostic leaked response or redirect data")
			}
		})
	}
}
