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

func TestParseOTPForm(t *testing.T) {
	html := `
		<html>
			<body>
				<form id="kc-otp-login-form" 
				      action="https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test" 
				      method="post">
					<input id="otp" name="otp" type="text" autocomplete="one-time-code" />
					<input name="login" id="kc-login" type="submit" value="Sign In" />
				</form>
			</body>
		</html>`

	form, err := ParseOTPForm(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseOTPForm failed: %v", err)
	}

	expectedAction := "https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test"
	if form.Action != expectedAction {
		t.Errorf("Expected action %q, got %q", expectedAction, form.Action)
	}

	if form.OTPField != "otp" {
		t.Errorf("Expected OTP field 'otp', got %q", form.OTPField)
	}

	if form.SubmitName != "login" {
		t.Errorf("Expected submit name 'login', got %q", form.SubmitName)
	}

	if form.SubmitValue != "Sign In" {
		t.Errorf("Expected submit value 'Sign In', got %q", form.SubmitValue)
	}

	if len(form.HiddenFields) != 0 {
		t.Errorf("Expected no hidden fields, got %d", len(form.HiddenFields))
	}
}

func TestParseOTPForm_MissingForm(t *testing.T) {
	html := `
		<html>
			<body>
				<form id="other-form">
					<input name="otp" type="text" />
				</form>
			</body>
		</html>`

	_, err := ParseOTPForm(strings.NewReader(html))
	if err == nil {
		t.Fatal("Expected error for missing OTP form, got nil")
	}

	if err.Error() != "OTP form not found" {
		t.Errorf("Expected error 'OTP form not found', got %q", err.Error())
	}
}

func TestParseOTPForm_WithHiddenFields(t *testing.T) {
	html := `
		<html>
			<body>
				<form id="kc-otp-login-form" action="/submit" method="post">
					<input type="hidden" name="csrf_token" value="secret123" />
					<input type="hidden" name="session_id" value="abc456" />
					<input name="otp" type="text" />
					<input type="submit" value="Submit" />
				</form>
			</body>
		</html>`

	form, err := ParseOTPForm(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseOTPForm failed: %v", err)
	}

	if form.HiddenFields["csrf_token"] != "secret123" {
		t.Errorf("Expected csrf_token 'secret123', got %q", form.HiddenFields["csrf_token"])
	}

	if form.HiddenFields["session_id"] != "abc456" {
		t.Errorf("Expected session_id 'abc456', got %q", form.HiddenFields["session_id"])
	}

	if len(form.HiddenFields) != 2 {
		t.Errorf("Expected 2 hidden fields, got %d", len(form.HiddenFields))
	}
}
