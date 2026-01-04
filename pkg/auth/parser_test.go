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

func TestHasTryAnotherWay(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected bool
	}{
		{
			name:     "OTP page with Try Another Way",
			html:     `<form id="kc-select-try-another-way-form" action="/switch"><input type="hidden" name="tryAnotherWay" value="on"/></form>`,
			expected: true,
		},
		{
			name:     "Page without Try Another Way",
			html:     `<form id="kc-otp-login-form"><input name="otp" type="text" /></form>`,
			expected: false,
		},
		{
			name:     "Empty page",
			html:     `<html><body></body></html>`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HasTryAnotherWay(tt.html)
			if result != tt.expected {
				t.Errorf("HasTryAnotherWay() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestParseTryAnotherWayForm(t *testing.T) {
	html := `
		<html>
			<body>
				<form id="kc-otp-login-form" action="/otp">
					<input name="otp" type="text" />
				</form>
				<form id="kc-select-try-another-way-form" action="https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test123" method="post">
					<input type="hidden" name="tryAnotherWay" value="on"/>
					<a href="#" id="try-another-way">Try Another Way</a>
				</form>
			</body>
		</html>`

	form, err := ParseTryAnotherWayForm(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseTryAnotherWayForm failed: %v", err)
	}

	expectedAction := "https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test123"
	if form.Action != expectedAction {
		t.Errorf("Expected action %q, got %q", expectedAction, form.Action)
	}
}

func TestParseTryAnotherWayForm_NotFound(t *testing.T) {
	html := `<html><body><form id="other-form"></form></body></html>`

	_, err := ParseTryAnotherWayForm(strings.NewReader(html))
	if err == nil {
		t.Fatal("Expected error for missing form, got nil")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' in error, got %q", err.Error())
	}
}

func TestParseMethodSelectionPage(t *testing.T) {
	// HTML structure based on TryAnotherWay.html
	html := `
		<html>
			<body>
				<form id="kc-select-credential-form" action="https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test" method="post">
					<div class="pf-l-stack select-auth-container">
						<button class="pf-l-stack__item select-auth-box-parent pf-l-split" type="submit" name="authenticationExecution" value="133f73d5-6454-4197-b529-b109a5d9432c">
							<div class="pf-l-split__item select-auth-box-icon">
								<i class="fa fa-mobile list-view-pf-icon-lg fa-2x select-auth-box-icon-properties"></i>
							</div>
							<div class="pf-l-split__item pf-l-stack">
								<div class="pf-l-stack__item select-auth-box-headline pf-c-title">
									Authenticator Application
								</div>
								<div class="pf-l-stack__item select-auth-box-desc">
									Enter a verification code from authenticator application.
								</div>
							</div>
						</button>
						<button class="pf-l-stack__item select-auth-box-parent pf-l-split" type="submit" name="authenticationExecution" value="4b3b18ac-dab0-4946-8d47-f7d8827cfedc">
							<div class="pf-l-split__item select-auth-box-icon">
								<i class="fa fa-key list-view-pf-icon-lg fa-2x select-auth-box-icon-properties"></i>
							</div>
							<div class="pf-l-split__item pf-l-stack">
								<div class="pf-l-stack__item select-auth-box-headline pf-c-title">
									Security Key
								</div>
								<div class="pf-l-stack__item select-auth-box-desc">
									Use your Security Key to sign in.
								</div>
							</div>
						</button>
					</div>
				</form>
			</body>
		</html>`

	page, err := ParseMethodSelectionPage(strings.NewReader(html))
	if err != nil {
		t.Fatalf("ParseMethodSelectionPage failed: %v", err)
	}

	expectedAction := "https://auth.cern.ch/auth/realms/cern/login-actions/authenticate?session_code=test"
	if page.Action != expectedAction {
		t.Errorf("Expected action %q, got %q", expectedAction, page.Action)
	}

	if len(page.Methods) != 2 {
		t.Fatalf("Expected 2 methods, got %d", len(page.Methods))
	}

	// Check OTP method
	otpMethod := page.FindMethod(MethodOTP)
	if otpMethod == nil {
		t.Fatal("Expected to find OTP method")
	}
	if otpMethod.ExecutionID != "133f73d5-6454-4197-b529-b109a5d9432c" {
		t.Errorf("Expected OTP execution ID '133f73d5-6454-4197-b529-b109a5d9432c', got %q", otpMethod.ExecutionID)
	}
	if otpMethod.Label != "Authenticator Application" {
		t.Errorf("Expected OTP label 'Authenticator Application', got %q", otpMethod.Label)
	}

	// Check WebAuthn method
	webauthnMethod := page.FindMethod(MethodWebAuthn)
	if webauthnMethod == nil {
		t.Fatal("Expected to find WebAuthn method")
	}
	if webauthnMethod.ExecutionID != "4b3b18ac-dab0-4946-8d47-f7d8827cfedc" {
		t.Errorf("Expected WebAuthn execution ID '4b3b18ac-dab0-4946-8d47-f7d8827cfedc', got %q", webauthnMethod.ExecutionID)
	}
	if webauthnMethod.Label != "Security Key" {
		t.Errorf("Expected WebAuthn label 'Security Key', got %q", webauthnMethod.Label)
	}
}

func TestParseMethodSelectionPage_NotFound(t *testing.T) {
	html := `<html><body><form id="other-form"></form></body></html>`

	_, err := ParseMethodSelectionPage(strings.NewReader(html))
	if err == nil {
		t.Fatal("Expected error for missing form, got nil")
	}
}

func TestMethodSelectionPage_FindMethod_NotFound(t *testing.T) {
	page := &MethodSelectionPage{
		Action: "/test",
		Methods: []AuthMethod{
			{ExecutionID: "123", Type: MethodOTP, Label: "OTP"},
		},
	}

	// OTP should be found
	if page.FindMethod(MethodOTP) == nil {
		t.Error("Expected to find OTP method")
	}

	// WebAuthn should not be found
	if page.FindMethod(MethodWebAuthn) != nil {
		t.Error("Expected WebAuthn method to be nil")
	}
}

func TestGetCurrentMethod(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected string
	}{
		{
			name:     "OTP page",
			html:     `<form id="kc-otp-login-form"><input name="otp" /></form>`,
			expected: MethodOTP,
		},
		{
			name:     "WebAuthn page",
			html:     `<div id="kc-form-webauthn"><form id="webauth"></form></div>`,
			expected: MethodWebAuthn,
		},
		{
			name:     "Neither",
			html:     `<html><body>Regular page</body></html>`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetCurrentMethod(tt.html)
			if result != tt.expected {
				t.Errorf("GetCurrentMethod() = %q, expected %q", result, tt.expected)
			}
		})
	}
}
