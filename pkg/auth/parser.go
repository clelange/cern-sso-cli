// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// ErrLoginFailed represents a login failure.
var ErrLoginFailed = errors.New("login failed")

// LoginError wraps a login error with a message.
type LoginError struct {
	Message string
}

func (e *LoginError) Error() string {
	return fmt.Sprintf("login failed: %s", e.Message)
}

// ParseKerberosLink extracts the Kerberos login link from the SSO page.
func ParseKerberosLink(r io.Reader, authHostname string) (string, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", err
	}

	kerbButton := doc.Find("#social-kerberos")
	if kerbButton.Length() == 0 {
		// Check for error message
		errMsg := GetErrorMessage(doc)
		if errMsg != "" {
			return "", &LoginError{Message: errMsg}
		}
		return "", &LoginError{Message: "landing page not recognized as CERN SSO login page"}
	}

	href, exists := kerbButton.Attr("href")
	if !exists {
		return "", &LoginError{Message: "kerberos button has no href"}
	}

	return fmt.Sprintf("https://%s%s", authHostname, href), nil
}

// GetErrorMessage extracts the Keycloak error message from the page.
func GetErrorMessage(doc *goquery.Document) string {
	errDiv := doc.Find("#kc-error-message")
	if errDiv.Length() == 0 {
		return ""
	}
	return strings.TrimSpace(errDiv.Find("p").Text())
}

// GetErrorMessageFromHTML parses HTML and extracts error message.
func GetErrorMessageFromHTML(r io.Reader) (string, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", err
	}
	return GetErrorMessage(doc), nil
}

// Check2FARequired checks if the response requires 2FA.
func Check2FARequired(body string) bool {
	return IsWebAuthnRequired(body) || IsOTPRequired(body)
}

// IsWebAuthnRequired checks if the response requires WebAuthn/FIDO2 authentication.
func IsWebAuthnRequired(body string) bool {
	return strings.Contains(body, `id="kc-form-webauthn"`)
}

// IsOTPRequired checks if the response requires OTP authentication.
func IsOTPRequired(body string) bool {
	return strings.Contains(body, `id="kc-otp-login-form"`)
}

// CheckConsentRequired checks if consent is required.
func CheckConsentRequired(body string) bool {
	return strings.Contains(body, "login-actions/consent")
}

// ParseSAMLForm extracts the SAML action URL and form data from a response.
func ParseSAMLForm(r io.Reader) (action string, data url.Values, err error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", nil, err
	}

	form := doc.Find("form")
	if form.Length() == 0 {
		return "", nil, errors.New("no form found in response")
	}

	action, _ = form.Attr("action")
	data = make(url.Values)
	isSAML := false

	form.Find("input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" {
			data.Set(name, value)
			if name == "SAMLResponse" || name == "SAMLRequest" {
				isSAML = true
			}
		}
	})

	if !isSAML {
		return "", nil, errors.New("not a SAML form")
	}

	return action, data, nil
}

// PostSAML performs the SAML POST request.
func PostSAML(client *http.Client, action string, data url.Values) (*http.Response, error) {
	return client.PostForm(action, data)
}

// ParseGitLabOIDCForm extracts the OIDC form data from a GitLab auto-submit page.
// GitLab puts the CSRF token in a meta tag, not in the input field.
func ParseGitLabOIDCForm(r io.Reader) (action string, data url.Values, err error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", nil, err
	}

	form := doc.Find("form")
	if form.Length() == 0 {
		return "", nil, errors.New("no form found in response")
	}

	action, _ = form.Attr("action")
	data = make(url.Values)

	// Get CSRF token from meta tag
	csrfToken, exists := doc.Find("meta[name=csrf-token]").Attr("content")
	if exists {
		data.Set("authenticity_token", csrfToken)
	}

	// Also get any other inputs
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" && name != "authenticity_token" && value != "" {
			data.Set(name, value)
		}
	})

	return action, data, nil
}

// ParseForm extracts the action URL and form data from the first form in a response.
func ParseForm(r io.Reader) (action string, data url.Values, err error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return "", nil, err
	}

	form := doc.Find("form")
	if form.Length() == 0 {
		return "", nil, errors.New("no form found in response")
	}

	action, _ = form.Attr("action")
	data = make(url.Values)

	form.Find("input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" {
			data.Set(name, value)
		}
	})

	return action, data, nil
}

// OTPForm represents the structure of an OTP login form.
type OTPForm struct {
	Action       string            // Form action URL
	HiddenFields map[string]string // Hidden input fields (CSRF tokens, etc.)
	OTPField     string            // Name of the OTP input field
	SubmitName   string            // Submit button name
	SubmitValue  string            // Submit button value
}

// ParseOTPForm extracts the OTP form details from the CERN 2FA page.
func ParseOTPForm(r io.Reader) (*OTPForm, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, err
	}

	form := doc.Find("#kc-otp-login-form")
	if form.Length() == 0 {
		return nil, errors.New("OTP form not found")
	}

	action, exists := form.Attr("action")
	if !exists {
		return nil, errors.New("OTP form has no action")
	}

	otpForm := &OTPForm{
		Action:       action,
		HiddenFields: make(map[string]string),
	}

	// Find all hidden input fields
	form.Find("input[type='hidden']").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" {
			otpForm.HiddenFields[name] = value
		}
	})

	// Find OTP input field (exact match for name="otp")
	otpFieldFound := false
	form.Find("input[name='otp']").Each(func(i int, s *goquery.Selection) {
		if !otpFieldFound {
			otpForm.OTPField = "otp"
			otpFieldFound = true
		}
	})

	if !otpFieldFound {
		return nil, errors.New("OTP input field not found")
	}

	// Find submit button
	form.Find("input[type='submit']").Each(func(i int, s *goquery.Selection) {
		if otpForm.SubmitName == "" {
			otpForm.SubmitName, _ = s.Attr("name")
			otpForm.SubmitValue, _ = s.Attr("value")
		}
	})

	return otpForm, nil
}

// WebAuthnForm represents the structure of a Keycloak WebAuthn form.
type WebAuthnForm struct {
	Action        string            // Form action URL
	Challenge     string            // Base64URL-encoded challenge
	RPID          string            // Relying Party ID
	CredentialIDs []string          // Allowed credential IDs (base64url encoded)
	UserHandle    string            // User handle (base64url encoded)
	HiddenFields  map[string]string // Other hidden input fields
}

// ParseWebAuthnForm extracts the WebAuthn form details from the CERN 2FA page.
// Keycloak's WebAuthn page structure:
// - <div id="kc-form-webauthn"> is a wrapper div
// - <form id="webauth" action="..."> is the actual form inside
// - Challenge and rpId are in JavaScript, not form fields
func ParseWebAuthnForm(r io.Reader) (*WebAuthnForm, error) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, err
	}

	// Find the WebAuthn wrapper div
	wrapper := doc.Find("#kc-form-webauthn")
	if wrapper.Length() == 0 {
		return nil, errors.New("WebAuthn form wrapper not found")
	}

	// Find the actual form inside the wrapper (id="webauth")
	form := wrapper.Find("form#webauth")
	if form.Length() == 0 {
		// Fallback: try finding any form inside the wrapper
		form = wrapper.Find("form")
	}
	if form.Length() == 0 {
		return nil, errors.New("WebAuthn form not found inside wrapper")
	}

	action, exists := form.Attr("action")
	if !exists || action == "" {
		return nil, errors.New("WebAuthn form has no action")
	}

	webauthnForm := &WebAuthnForm{
		Action:        action,
		HiddenFields:  make(map[string]string),
		CredentialIDs: make([]string, 0),
	}

	// Find all hidden input fields in the form
	form.Find("input[type='hidden']").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" {
			webauthnForm.HiddenFields[name] = value
		}
	})

	// Also check for credential IDs in the authn_select form
	doc.Find("form#authn_select input[name='authn_use_chk']").Each(func(i int, s *goquery.Selection) {
		if credID, exists := s.Attr("value"); exists && credID != "" {
			webauthnForm.CredentialIDs = append(webauthnForm.CredentialIDs, credID)
		}
	})

	// Keycloak embeds WebAuthn data in script tags
	// Look for the authenticateByWebAuthn call with input object
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptContent := s.Text()

		// Look for challenge in the input object: challenge : 'xxx'
		if strings.Contains(scriptContent, "challenge") {
			// Pattern: challenge : 'value' or challenge: 'value'
			challengePattern := regexp.MustCompile(`challenge\s*:\s*'([^']+)'`)
			if matches := challengePattern.FindStringSubmatch(scriptContent); len(matches) > 1 {
				webauthnForm.Challenge = matches[1]
			}
		}

		// Look for rpId: rpId : 'xxx'
		if strings.Contains(scriptContent, "rpId") {
			rpIdPattern := regexp.MustCompile(`rpId\s*:\s*'([^']+)'`)
			if matches := rpIdPattern.FindStringSubmatch(scriptContent); len(matches) > 1 {
				webauthnForm.RPID = matches[1]
			}
		}
	})

	// Also check for data attributes on elements as fallback
	doc.Find("[data-challenge]").Each(func(i int, s *goquery.Selection) {
		if challenge, exists := s.Attr("data-challenge"); exists {
			webauthnForm.Challenge = challenge
		}
	})

	doc.Find("[data-rpid]").Each(func(i int, s *goquery.Selection) {
		if rpid, exists := s.Attr("data-rpid"); exists {
			webauthnForm.RPID = rpid
		}
	})

	return webauthnForm, nil
}
