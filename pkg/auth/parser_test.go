package auth

import (
	"strings"
	"testing"
)

func TestParseKerberosLink(t *testing.T) {
	html := `
	<html>
		<body>
			<a id="social-kerberos" href="/auth/realms/cern/broker/kerberos/login?client_id=account-app">Kerberos</a>
		</body>
	</html>`

	authHost := "auth.cern.ch"
	link, err := ParseKerberosLink(strings.NewReader(html), authHost)
	if err != nil {
		t.Fatalf("ParseKerberosLink failed: %v", err)
	}

	expected := "https://auth.cern.ch/auth/realms/cern/broker/kerberos/login?client_id=account-app"
	if link != expected {
		t.Errorf("Expected %q, got %q", expected, link)
	}
}

func TestParseKerberosLink_Error(t *testing.T) {
	html := `
	<html>
		<body>
			<div id="kc-error-message">
				<p>Invalid username or password.</p>
			</div>
		</body>
	</html>`

	_, err := ParseKerberosLink(strings.NewReader(html), "auth.cern.ch")
	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "Invalid username or password") {
		t.Errorf("Expected error message to contain 'Invalid username or password', got %q", err.Error())
	}
}

func TestParseSAMLForm(t *testing.T) {
	html := `
	<html>
		<body>
			<form action="https://target.cern.ch/saml" method="post">
				<input type="hidden" name="SAMLResponse" value="base64data" />
				<input type="hidden" name="RelayState" value="state123" />
			</form>
		</body>
	</html>`

	action, data, err := ParseSAMLForm(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseSAMLForm failed: %v", err)
	}

	if action != "https://target.cern.ch/saml" {
		t.Errorf("Expected action %q, got %q", "https://target.cern.ch/saml", action)
	}

	if data.Get("SAMLResponse") != "base64data" {
		t.Errorf("Expected SAMLResponse %q, got %q", "base64data", data.Get("SAMLResponse"))
	}

	if data.Get("RelayState") != "state123" {
		t.Errorf("Expected RelayState %q, got %q", "state123", data.Get("RelayState"))
	}
}

func TestParseGitLabOIDCForm(t *testing.T) {
	html := `
	<html>
		<head>
			<meta name="csrf-token" content="secret-token" />
		</head>
		<body>
			<form action="/users/auth/openid_connect" method="post">
				<input name="other_field" value="other_value" />
			</form>
		</body>
	</html>`

	action, data, err := ParseGitLabOIDCForm(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseGitLabOIDCForm failed: %v", err)
	}

	if action != "/users/auth/openid_connect" {
		t.Errorf("Expected action %q, got %q", "/users/auth/openid_connect", action)
	}

	if data.Get("authenticity_token") != "secret-token" {
		t.Errorf("Expected authenticity_token %q, got %q", "secret-token", data.Get("authenticity_token"))
	}

	if data.Get("other_field") != "other_value" {
		t.Errorf("Expected other_field %q, got %q", "other_value", data.Get("other_field"))
	}
}
