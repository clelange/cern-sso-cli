package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// switchTo2FAMethod switches from the current 2FA method to the preferred one.
// It submits the "Try Another Way" form, parses the method selection page,
// and selects the preferred method.
//
//nolint:cyclop // Multi-step form submission with redirect handling
func (k *KerberosClient) switchTo2FAMethod(currentResp *http.Response, currentBody []byte, preferredMethod string) ([]byte, *http.Response, error) {
	// Parse the "Try Another Way" form
	tryAnotherWayForm, err := ParseTryAnotherWayForm(bytes.NewReader(currentBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse Try Another Way form: %w", err)
	}

	// Make the action URL absolute
	actionURL := tryAnotherWayForm.Action
	if !strings.HasPrefix(actionURL, "http") {
		baseURL := currentResp.Request.URL
		resolvedURL, err := baseURL.Parse(actionURL)
		if err == nil {
			actionURL = resolvedURL.String()
		}
	}

	// Submit the "Try Another Way" form
	formData := url.Values{}
	formData.Set("tryAnotherWay", "on")

	selectionResp, err := k.httpClient.PostForm(actionURL, formData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to submit Try Another Way form: %w", err)
	}

	// Follow any redirects
	for selectionResp.StatusCode == http.StatusFound || selectionResp.StatusCode == http.StatusSeeOther {
		location := selectionResp.Header.Get("Location")
		if location == "" {
			break
		}
		locURL, err := url.Parse(location)
		if err == nil && !locURL.IsAbs() {
			locURL = selectionResp.Request.URL.ResolveReference(locURL)
			location = locURL.String()
		}
		closeResponseBody(selectionResp)
		selectionResp, err = k.httpClient.Get(location) // #nosec G704
		if err != nil {
			return nil, nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
	}

	selectionBody, err := io.ReadAll(selectionResp.Body)
	if err != nil {
		closeResponseBody(selectionResp)
		return nil, nil, fmt.Errorf("failed to read selection page: %w", err)
	}
	closeResponseBody(selectionResp)

	// Parse the method selection page
	selectionPage, err := ParseMethodSelectionPage(bytes.NewReader(selectionBody))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse method selection page: %w", err)
	}

	// Find the preferred method
	method := selectionPage.FindMethod(preferredMethod)
	if method == nil {
		return nil, nil, fmt.Errorf("preferred method %q not available", preferredMethod)
	}

	// Make the selection form action URL absolute
	selectionActionURL := selectionPage.Action
	if !strings.HasPrefix(selectionActionURL, "http") {
		baseURL := selectionResp.Request.URL
		resolvedURL, err := baseURL.Parse(selectionActionURL)
		if err == nil {
			selectionActionURL = resolvedURL.String()
		}
	}

	// Submit the method selection
	selectionFormData := url.Values{}
	selectionFormData.Set("authenticationExecution", method.ExecutionID)

	methodResp, err := k.httpClient.PostForm(selectionActionURL, selectionFormData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to submit method selection: %w", err)
	}

	// Follow any redirects
	for methodResp.StatusCode == http.StatusFound || methodResp.StatusCode == http.StatusSeeOther {
		location := methodResp.Header.Get("Location")
		if location == "" {
			break
		}
		locURL, err := url.Parse(location)
		if err == nil && !locURL.IsAbs() {
			locURL = methodResp.Request.URL.ResolveReference(locURL)
			location = locURL.String()
		}
		closeResponseBody(methodResp)
		methodResp, err = k.httpClient.Get(location) // #nosec G704
		if err != nil {
			return nil, nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
	}

	methodBody, err := io.ReadAll(methodResp.Body)
	if err != nil {
		closeResponseBody(methodResp)
		return nil, nil, fmt.Errorf("failed to read method page: %w", err)
	}

	closeResponseBody(methodResp)
	return methodBody, withResponseBody(methodResp, methodBody), nil
}

// getOTP retrieves an OTP code using the configured provider or interactive prompt.
func (k *KerberosClient) getOTP() (string, string, error) {
	if k.otpProvider != nil {
		return k.otpProvider.GetOTP(k.username)
	}
	// Fallback to interactive prompt if no provider configured
	otp, err := promptForOTPInteractive(k.username)
	if err != nil {
		return "", "", err
	}
	return otp, OTPSourcePrompt, nil
}

// getMaxOTPRetries returns the configured maximum OTP submission attempts.
func (k *KerberosClient) getMaxOTPRetries() int {
	if k.otpProvider != nil {
		return k.otpProvider.GetMaxRetries()
	}
	return defaultMaxOTPAttempts
}

// refreshOTP gets a fresh OTP for retry attempts.
func (k *KerberosClient) refreshOTP(source string, attempt, maxRetries int) (string, error) {
	if k.otpProvider != nil {
		return k.otpProvider.RefreshOTP(k.username, source, attempt, maxRetries)
	}
	// Fallback to interactive re-prompt
	_, _ = fmt.Fprintf(os.Stderr, "Invalid OTP. Try again (%d/%d): ", attempt, maxRetries)
	var code string
	_, err := fmt.Scanln(&code)
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}
	return validateOTP(code)
}
