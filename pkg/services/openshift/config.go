package openshift

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

const openShiftConfigDomainSuffix = ".okd.cern.ch"

var lookupTXT = net.LookupTXT

// ClusterConfig describes the DNS-published configuration for an OpenShift cluster.
type ClusterConfig struct {
	Name               string
	APIURL             string
	TokenExchangeURL   string
	AudienceID         string
	LoginApplicationID string
	AuthURL            string
}

// LookupClusterConfig fetches the OpenShift cluster configuration from DNS TXT records.
func LookupClusterConfig(clusterName string) (*ClusterConfig, error) {
	clusterName = strings.TrimSpace(clusterName)
	if clusterName == "" {
		return nil, fmt.Errorf("cluster name is required")
	}

	records, err := lookupTXT("_config." + clusterName + openShiftConfigDomainSuffix)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup cluster config for %q: %w", clusterName, err)
	}

	cfg := &ClusterConfig{Name: clusterName}
	for _, record := range records {
		applyClusterConfigRecord(cfg, record)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Validate verifies that the required cluster settings are present and plausible.
func (c *ClusterConfig) Validate() error {
	required := map[string]string{
		"api_url":              c.APIURL,
		"token_exchange_url":   c.TokenExchangeURL,
		"audience_id":          c.AudienceID,
		"login_application_id": c.LoginApplicationID,
		"auth_url":             c.AuthURL,
	}

	for field, value := range required {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("cluster config missing required field %q", field)
		}
	}

	for field, value := range map[string]string{
		"api_url":            c.APIURL,
		"token_exchange_url": c.TokenExchangeURL,
		"auth_url":           c.AuthURL,
	} {
		if err := validateHTTPSURL(field, value); err != nil {
			return err
		}
	}

	if _, err := oidcConfigFromAuthURL(c.AuthURL, c.LoginApplicationID, true); err != nil {
		return err
	}

	return nil
}

// ClusterNameFromURL extracts the OpenShift cluster name from a console, API, or OAuth URL.
func ClusterNameFromURL(rawURL string) (string, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "", fmt.Errorf("cluster URL is required")
	}

	host, err := parseClusterHost(rawURL)
	if err != nil {
		return "", err
	}

	host = normalizeClusterHost(host)
	if host == "" || !strings.Contains(host, ".") {
		return "", fmt.Errorf("invalid cluster host %q", rawURL)
	}

	clusterName, _, ok := strings.Cut(host, ".")
	if !ok || clusterName == "" {
		return "", fmt.Errorf("could not determine cluster name from %q", rawURL)
	}

	return clusterName, nil
}

func oidcConfigFromAuthURL(authURL string, clientID string, verifyCerts bool) (auth.OIDCConfig, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return auth.OIDCConfig{}, fmt.Errorf("invalid auth_url: %w", err)
	}

	if u.Host == "" {
		return auth.OIDCConfig{}, fmt.Errorf("invalid auth_url %q: missing host", authURL)
	}

	pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(pathParts) < 3 || pathParts[0] != "auth" || pathParts[1] != "realms" || pathParts[2] == "" {
		return auth.OIDCConfig{}, fmt.Errorf("invalid auth_url %q: expected /auth/realms/<realm>", authURL)
	}

	return auth.OIDCConfig{
		AuthHostname: u.Host,
		AuthRealm:    pathParts[2],
		ClientID:     clientID,
		VerifyCert:   verifyCerts,
	}, nil
}

func validateHTTPSURL(field string, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, rawURL, err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("invalid %s %q: must be an https URL", field, rawURL)
	}
	return nil
}

func applyClusterConfigRecord(cfg *ClusterConfig, record string) {
	key, value, ok := strings.Cut(strings.TrimSpace(record), "=")
	if !ok {
		return
	}

	switch key {
	case "api_url":
		cfg.APIURL = strings.TrimRight(value, "/")
	case "token_exchange_url":
		cfg.TokenExchangeURL = strings.TrimRight(value, "/")
	case "audience_id":
		cfg.AudienceID = value
	case "login_application_id":
		cfg.LoginApplicationID = value
	case "auth_url":
		cfg.AuthURL = strings.TrimRight(value, "/")
	}
}

func parseClusterHost(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid cluster URL: %w", err)
	}

	if parsed.Hostname() != "" || strings.Contains(rawURL, "://") {
		return parsed.Hostname(), nil
	}

	parsed, err = url.Parse("https://" + rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid cluster URL: %w", err)
	}

	return parsed.Hostname(), nil
}

func normalizeClusterHost(host string) string {
	switch {
	case strings.HasPrefix(host, "api."):
		return strings.TrimPrefix(host, "api.")
	case strings.HasPrefix(host, "oauth-openshift."):
		return strings.TrimPrefix(host, "oauth-openshift.")
	default:
		return host
	}
}
