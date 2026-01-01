// Package auth provides authentication utilities for CERN SSO.
package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	return strings.Contains(body, `id="kc-form-webauthn"`) ||
		strings.Contains(body, `id="kc-otp-login-form"`)
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
