package openshift

import (
	"errors"
	"testing"
)

func TestLookupClusterConfig(t *testing.T) {
	oldLookupTXT := lookupTXT
	defer func() { lookupTXT = oldLookupTXT }()

	tests := []struct {
		name    string
		records []string
		err     bool
	}{
		{
			name: "valid config with extra records",
			records: []string{
				"api_url=https://api.paas.okd.cern.ch",
				"token_exchange_url=https://token-exchange.paas.cern.ch",
				"audience_id=paas_id",
				"login_application_id=okd4-sso-login-application",
				"auth_url=https://auth.cern.ch/auth/realms/cern",
				"ignored_key=ignored",
			},
		},
		{
			name: "missing required field",
			records: []string{
				"api_url=https://api.paas.okd.cern.ch",
				"token_exchange_url=https://token-exchange.paas.cern.ch",
				"login_application_id=okd4-sso-login-application",
				"auth_url=https://auth.cern.ch/auth/realms/cern",
			},
			err: true,
		},
		{
			name: "malformed auth url",
			records: []string{
				"api_url=https://api.paas.okd.cern.ch",
				"token_exchange_url=https://token-exchange.paas.cern.ch",
				"audience_id=paas_id",
				"login_application_id=okd4-sso-login-application",
				"auth_url=https://auth.cern.ch/not-a-realm",
			},
			err: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookupTXT = func(name string) ([]string, error) {
				if name != "_config.paas.okd.cern.ch" {
					t.Fatalf("unexpected lookup name %q", name)
				}
				return tt.records, nil
			}

			cfg, err := LookupClusterConfig("paas")
			if tt.err {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("LookupClusterConfig failed: %v", err)
			}
			if cfg.Name != "paas" {
				t.Fatalf("expected cluster name %q, got %q", "paas", cfg.Name)
			}
			if cfg.APIURL != "https://api.paas.okd.cern.ch" {
				t.Fatalf("expected API URL %q, got %q", "https://api.paas.okd.cern.ch", cfg.APIURL)
			}
		})
	}
}

func TestLookupClusterConfigPropagatesLookupError(t *testing.T) {
	oldLookupTXT := lookupTXT
	defer func() { lookupTXT = oldLookupTXT }()

	lookupTXT = func(string) ([]string, error) {
		return nil, errors.New("lookup failed")
	}

	if _, err := LookupClusterConfig("paas"); err == nil {
		t.Fatal("expected lookup error")
	}
}

func TestClusterNameFromURL(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		want    string
		wantErr bool
	}{
		{name: "console url", rawURL: "https://paas.cern.ch", want: "paas"},
		{name: "api url", rawURL: "https://api.paas.okd.cern.ch:6443", want: "paas"},
		{name: "oauth url", rawURL: "https://oauth-openshift.paas.cern.ch/oauth/token/request", want: "paas"},
		{name: "host without scheme", rawURL: "paas.cern.ch", want: "paas"},
		{name: "invalid host", rawURL: "localhost", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ClusterNameFromURL(tt.rawURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ClusterNameFromURL failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("expected cluster name %q, got %q", tt.want, got)
			}
		})
	}
}
