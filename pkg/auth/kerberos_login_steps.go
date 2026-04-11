package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/clelange/cern-sso-cli/pkg/browser"
)

var (
	isChromeAvailableFunc      = browser.IsChromeAvailable
	authenticateWithChromeFunc = browser.AuthenticateWithChrome
)

type kerberosLoginPage struct {
	body []byte
}

type kerberosLoginFlow struct {
	client       *KerberosClient
	loginPage    string
	authHostname string
	redirectURI  string
}

func newKerberosLoginFlow(client *KerberosClient, loginPage string, authHostname string) *kerberosLoginFlow {
	return &kerberosLoginFlow{
		client:       client,
		loginPage:    loginPage,
		authHostname: authHostname,
	}
}

func (k *KerberosClient) tryBrowserLogin(loginPage string, authHostname string) (*LoginResult, bool, error) {
	if k.webauthnProvider == nil || !k.webauthnProvider.UseBrowser {
		return nil, false, nil
	}

	if !isChromeAvailableFunc() {
		return nil, true, &LoginError{Message: "--browser requires Chrome or Chromium to be installed"}
	}

	result, err := k.authenticateWithBrowser(loginPage, authHostname, k.browserLoginTimeout(), k.browserLoginEnv())
	return result, true, err
}

func (k *KerberosClient) browserLoginTimeout() time.Duration {
	timeout := k.webauthnProvider.GetTimeout()
	if timeout < 3*time.Minute {
		timeout = 3 * time.Minute
	}
	return timeout
}

func (k *KerberosClient) browserLoginEnv() map[string]string {
	env := make(map[string]string)

	if k.username == "" || runtime.GOOS != "darwin" {
		return env
	}

	originalKrb5CCName := os.Getenv("KRB5CCNAME")
	_ = os.Unsetenv("KRB5CCNAME")

	cacheInfo, err := FindCacheByUsername(k.username)

	if originalKrb5CCName != "" {
		_ = os.Setenv("KRB5CCNAME", originalKrb5CCName)
	}

	if err != nil {
		if !k.authConfig.Quiet {
			_, _ = fmt.Fprintf(os.Stderr, "Warning: ticket for %s not found in system klist, using default\n", k.username)
		}
		return env
	}

	if cacheInfo.IsDefault {
		return env
	}

	switch {
	case strings.HasPrefix(cacheInfo.CacheName, "FILE:"):
		env["KRB5CCNAME"] = strings.TrimPrefix(cacheInfo.CacheName, "FILE:")
	case cacheInfo.CacheName != "":
		env["KRB5CCNAME"] = cacheInfo.CacheName
	}

	return env
}

func (k *KerberosClient) authenticateWithBrowser(
	loginPage string,
	authHostname string,
	timeout time.Duration,
	env map[string]string,
) (*LoginResult, error) {
	browserResult, err := authenticateWithChromeFunc(loginPage, authHostname, timeout, env)
	if err != nil {
		return nil, &LoginError{Message: fmt.Sprintf("browser authentication failed: %v", err)}
	}

	return &LoginResult{
		Cookies:     browserResult.Cookies,
		RedirectURI: browserResult.FinalURL,
		Username:    browserResult.Username,
	}, nil
}

func (k *KerberosClient) fetchKerberosLoginPage(loginPage string) (*kerberosLoginPage, error) {
	resp, err := k.httpClient.Get(loginPage)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch login page: %w", err)
	}

	for resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusMovedPermanently {
		location := resp.Header.Get("Location")
		closeResponseBody(resp)

		resp, err = k.httpClient.Get(location)
		if err != nil {
			return nil, fmt.Errorf("failed to follow redirect: %w", err)
		}
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		closeResponseBody(resp)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	requestURL := resp.Request.URL
	closeResponseBody(resp)

	if strings.Contains(requestURL.Host, "login.cern.ch") {
		return nil, &LoginError{Message: "old SSO (login.cern.ch) is not supported"}
	}

	if strings.Contains(string(bodyBytes), "/users/auth/openid_connect") {
		oidcPage, handled, err := k.followInitialGitLabOIDC(requestURL, bodyBytes)
		if err != nil {
			return nil, err
		}
		if handled {
			return oidcPage, nil
		}
	}

	return &kerberosLoginPage{body: bodyBytes}, nil
}

func (k *KerberosClient) followInitialGitLabOIDC(
	baseURL *url.URL,
	bodyBytes []byte,
) (*kerberosLoginPage, bool, error) {
	action, data, err := ParseGitLabOIDCForm(bytes.NewReader(bodyBytes))
	if err != nil || action == "" {
		return nil, false, nil
	}

	oidcResp, err := k.httpClient.PostForm(resolveActionURL(baseURL, action), data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to submit OIDC form: %w", err)
	}

	for oidcResp.StatusCode == http.StatusFound || oidcResp.StatusCode == http.StatusSeeOther {
		location := oidcResp.Header.Get("Location")
		nextURL := resolveActionURL(baseURL, location)

		closeResponseBody(oidcResp)
		oidcResp, err = k.httpClient.Get(nextURL) // #nosec G704
		if err != nil {
			return nil, false, fmt.Errorf("failed to follow OIDC redirect: %w", err)
		}
		baseURL = oidcResp.Request.URL
	}

	oidcBody, err := io.ReadAll(oidcResp.Body)
	if err != nil {
		closeResponseBody(oidcResp)
		return nil, false, fmt.Errorf("failed to read OIDC response: %w", err)
	}

	closeResponseBody(oidcResp)
	return &kerberosLoginPage{body: oidcBody}, true, nil
}

func (k *KerberosClient) parseKerberosAuthURL(loginPage string, authHostname string, bodyBytes []byte) (string, error) {
	kerbURL, err := ParseKerberosLink(bytes.NewReader(bodyBytes), authHostname)
	if err == nil {
		return kerbURL, nil
	}

	spaInfo, spaErr := DetectSPA(k.httpClient, loginPage, bodyBytes)
	if spaErr == nil && spaInfo != nil {
		_, loginBody, navErr := GetSPALoginPage(k.httpClient, spaInfo, authHostname)
		if navErr == nil {
			kerbURL, err = ParseKerberosLink(bytes.NewReader(loginBody), authHostname)
		}
	}

	if err != nil {
		return "", err
	}

	return kerbURL, nil
}

func (k *KerberosClient) resolveKerberosAuthURL(kerbURL string) (string, error) {
	kerbAuthURL := kerbURL

	for {
		req, err := http.NewRequest(http.MethodGet, kerbAuthURL, nil) // #nosec G704
		if err != nil {
			return "", fmt.Errorf("failed to create redirect request: %w", err)
		}

		resp, err := k.httpClient.Do(req) // #nosec G704
		if err != nil {
			return "", fmt.Errorf("failed to follow redirect: %w", err)
		}
		closeResponseBody(resp)

		if !isRedirectStatus(resp.StatusCode) {
			return kerbAuthURL, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return kerbAuthURL, nil
		}

		baseURL, err := url.Parse(kerbAuthURL)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect base URL: %w", err)
		}

		resolvedLocation, _, err := resolveRedirectLocation(baseURL, location)
		if err != nil {
			return "", fmt.Errorf("failed to parse redirect location: %w", err)
		}
		kerbAuthURL = resolvedLocation
	}
}

func (f *kerberosLoginFlow) run(authResp *http.Response) (*LoginResult, error) {
	currentResp := authResp

	for {
		nextResp, handled, err := f.handleRedirect(currentResp)
		if err != nil {
			closeResponseBody(currentResp)
			return nil, err
		}
		if handled {
			closeResponseBody(currentResp)
			currentResp = nextResp
			continue
		}

		result, nextResp, err := f.handleResponse(currentResp)
		closeResponseBody(currentResp)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}

		currentResp = nextResp
	}
}

func (f *kerberosLoginFlow) handleRedirect(resp *http.Response) (*http.Response, bool, error) {
	if !isRedirectStatus(resp.StatusCode) {
		return nil, false, nil
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, false, nil
	}

	resolvedLocation, resolvedURL, err := resolveRedirectLocation(resp.Request.URL, location)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse redirect location: %w", err)
	}

	if resolvedURL.IsAbs() && resolvedURL.Host != f.authHostname && f.redirectURI == "" {
		f.redirectURI = resolvedLocation
	}

	nextResp, err := f.client.httpClient.Get(resolvedLocation) // #nosec G704
	if err != nil {
		return nil, false, fmt.Errorf("redirect failed: %w", err)
	}

	return nextResp, true, nil
}

func (f *kerberosLoginFlow) handleResponse(resp *http.Response) (*LoginResult, *http.Response, error) {
	authBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read authentication response: %w", err)
	}

	authBodyStr := string(authBody)

	if Check2FARequired(authBodyStr) {
		return f.handle2FA(resp, authBody, authBodyStr)
	}

	if CheckConsentRequired(authBodyStr) {
		return nil, nil, &LoginError{Message: "application requires consent, please accept manually first"}
	}

	if nextResp, handled, err := f.handleAutoSubmit(resp, authBody, authBodyStr); handled || err != nil {
		return nil, nextResp, err
	}

	if nextResp, handled, err := f.handleSAML(resp, authBody); handled || err != nil {
		return nil, nextResp, err
	}

	if resp.Request.URL.Host != f.authHostname {
		return f.successResult(resp), nil, nil
	}

	errMsg, _ := GetErrorMessageFromHTML(bytes.NewReader(authBody))
	if errMsg != "" {
		return nil, nil, &LoginError{Message: errMsg}
	}

	return nil, nil, &LoginError{Message: "unexpected response from authentication server"}
}

func (f *kerberosLoginFlow) handle2FA(
	resp *http.Response,
	authBody []byte,
	authBodyStr string,
) (*LoginResult, *http.Response, error) {
	resp, authBody, authBodyStr, err := f.maybeSwitch2FAMethod(resp, authBody, authBodyStr)
	if err != nil {
		return nil, nil, err
	}

	webauthnAvailable := IsWebAuthnRequired(authBodyStr) &&
		f.client.webauthnProvider != nil &&
		IsWebAuthnAvailable()
	otpAvailable := IsOTPRequired(authBodyStr)

	if webauthnAvailable && (f.client.preferredMethod == "webauthn" || !otpAvailable) {
		if f.client.webauthnProvider.UseBrowser {
			result, err := f.client.authenticateWithBrowser(
				f.loginPage,
				f.authHostname,
				f.client.webauthnProvider.GetTimeout(),
				nil,
			)
			return result, nil, err
		}

		nextResp, err := f.handleWebAuthn(resp, authBody)
		return nil, nextResp, err
	}

	if !otpAvailable {
		return nil, nil, &LoginError{Message: "2FA required but no supported method available"}
	}

	nextResp, err := f.handleOTP(authBody)
	return nil, nextResp, err
}

func (f *kerberosLoginFlow) maybeSwitch2FAMethod(
	resp *http.Response,
	authBody []byte,
	authBodyStr string,
) (*http.Response, []byte, string, error) {
	currentMethod := GetCurrentMethod(authBodyStr)
	if f.client.preferredMethod == "" || currentMethod == "" || currentMethod == f.client.preferredMethod {
		return resp, authBody, authBodyStr, nil
	}
	if !HasTryAnotherWay(authBodyStr) {
		return resp, authBody, authBodyStr, nil
	}

	switchedBody, switchedResp, err := f.client.switchTo2FAMethod(resp, authBody, f.client.preferredMethod)
	if err != nil {
		return nil, nil, "", &LoginError{Message: fmt.Sprintf("failed to switch 2FA method: %v", err)}
	}

	return switchedResp, switchedBody, string(switchedBody), nil
}

func (f *kerberosLoginFlow) handleWebAuthn(resp *http.Response, authBody []byte) (*http.Response, error) {
	webauthnForm, err := ParseWebAuthnForm(bytes.NewReader(authBody))
	if err != nil {
		return nil, &LoginError{Message: fmt.Sprintf("failed to parse WebAuthn form: %v", err)}
	}

	result, err := f.client.webauthnProvider.Authenticate(webauthnForm)
	if err != nil {
		return nil, &LoginError{Message: fmt.Sprintf("WebAuthn authentication failed: %v", err)}
	}

	formData := url.Values{}
	for key, val := range webauthnForm.HiddenFields {
		formData.Set(key, val)
	}
	formData.Set("clientDataJSON", result.ClientDataJSON)
	formData.Set("authenticatorData", result.AuthenticatorData)
	formData.Set("signature", result.Signature)
	formData.Set("credentialId", result.CredentialID)
	if result.UserHandle != "" {
		formData.Set("userHandle", result.UserHandle)
	}

	actionURL := resolveActionURL(resp.Request.URL, webauthnForm.Action)
	nextResp, err := f.client.httpClient.PostForm(actionURL, formData)
	if err != nil {
		return nil, &LoginError{Message: fmt.Sprintf("failed to submit WebAuthn response: %v", err)}
	}

	return nextResp, nil
}

func (f *kerberosLoginFlow) handleOTP(authBody []byte) (*http.Response, error) {
	otpForm, otpCode, source, maxRetries, err := f.prepareOTPChallenge(authBody)
	if err != nil {
		return nil, err
	}

	for attempt := 1; attempt <= maxRetries; attempt++ {
		otpResp, otpBody, err := f.submitOTPAttempt(otpForm, otpCode)
		if err != nil {
			return nil, err
		}

		if !Check2FARequired(string(otpBody)) {
			return f.handleAcceptedOTP(otpResp, otpBody)
		}

		closeResponseBody(otpResp)
		if attempt >= maxRetries {
			break
		}

		otpCode, err = f.refreshOTPForRetry(source, attempt, maxRetries)
		if err != nil {
			return nil, err
		}
	}

	return nil, &LoginError{Message: fmt.Sprintf("OTP verification failed after %d attempts", maxRetries)}
}

func (f *kerberosLoginFlow) prepareOTPChallenge(authBody []byte) (*OTPForm, string, string, int, error) {
	otpForm, err := ParseOTPForm(bytes.NewReader(authBody))
	if err != nil {
		return nil, "", "", 0, &LoginError{Message: fmt.Sprintf("failed to parse OTP form: %v", err)}
	}

	otpCode, source, err := f.client.getOTP()
	if err != nil {
		return nil, "", "", 0, &LoginError{Message: fmt.Sprintf("failed to read OTP: %v", err)}
	}

	maxRetries := maxOTPAttemptsForSource(source, f.client.getMaxOTPRetries())
	return otpForm, otpCode, source, maxRetries, nil
}

func (f *kerberosLoginFlow) submitOTPAttempt(otpForm *OTPForm, otpCode string) (*http.Response, []byte, error) {
	formData := url.Values{}
	for key, val := range otpForm.HiddenFields {
		formData.Set(key, val)
	}
	formData.Set(otpForm.OTPField, otpCode)
	if otpForm.SubmitName != "" {
		formData.Set(otpForm.SubmitName, otpForm.SubmitValue)
	}

	otpResp, err := f.client.httpClient.PostForm(otpForm.Action, formData)
	if err != nil {
		return nil, nil, &LoginError{Message: fmt.Sprintf("failed to submit OTP: %v", err)}
	}

	otpBody, readErr := io.ReadAll(otpResp.Body)
	if readErr != nil {
		closeResponseBody(otpResp)
		return nil, nil, &LoginError{Message: fmt.Sprintf("failed to read OTP response: %v", readErr)}
	}

	return otpResp, otpBody, nil
}

func (f *kerberosLoginFlow) handleAcceptedOTP(otpResp *http.Response, otpBody []byte) (*http.Response, error) {
	if errMsg, _ := GetErrorMessageFromHTML(bytes.NewReader(otpBody)); errMsg != "" {
		closeResponseBody(otpResp)
		return nil, &LoginError{Message: errMsg}
	}

	closeResponseBody(otpResp)
	return withResponseBody(otpResp, otpBody), nil
}

func (f *kerberosLoginFlow) refreshOTPForRetry(source string, attempt int, maxRetries int) (string, error) {
	if !IsRefreshable(source) {
		return "", &LoginError{Message: "Invalid OTP code. Cannot retry with static OTP value."}
	}

	if isAutoGeneratedTOTPSource(source) {
		wait := timeUntilNextTOTPWindow(timeNow())
		if !f.client.authConfig.Quiet {
			if wait >= time.Second {
				_, _ = fmt.Fprintf(os.Stderr, "OTP may have expired. Waiting %s for a fresh code...\n", wait.Round(time.Second))
			} else {
				_, _ = fmt.Fprintln(os.Stderr, "OTP may have expired. Retrying with a fresh code...")
			}
		}
		waitForNextTOTPWindow()
	}

	otpCode, err := f.client.refreshOTP(source, attempt+1, maxRetries)
	if err != nil {
		return "", &LoginError{Message: fmt.Sprintf("failed to refresh OTP: %v", err)}
	}

	return otpCode, nil
}

func (f *kerberosLoginFlow) handleAutoSubmit(
	resp *http.Response,
	authBody []byte,
	authBodyStr string,
) (*http.Response, bool, error) {
	if !strings.Contains(authBodyStr, "document.forms[0].submit()") &&
		!strings.Contains(authBodyStr, "document.querySelector('form').submit()") {
		return nil, false, nil
	}

	var (
		action string
		data   url.Values
		err    error
	)

	if strings.Contains(authBodyStr, "csrf-token") {
		action, data, err = ParseGitLabOIDCForm(bytes.NewReader(authBody))
	} else {
		action, data, err = ParseForm(bytes.NewReader(authBody))
	}

	if err != nil || action == "" {
		return nil, false, nil
	}

	nextResp, err := f.client.httpClient.PostForm(resolveActionURL(resp.Request.URL, action), data)
	if err != nil {
		return nil, true, fmt.Errorf("form auto-submit failed: %w", err)
	}

	return nextResp, true, nil
}

func (f *kerberosLoginFlow) handleSAML(resp *http.Response, authBody []byte) (*http.Response, bool, error) {
	action, data, err := ParseSAMLForm(bytes.NewReader(authBody))
	if err != nil || action == "" {
		return nil, false, nil
	}

	nextResp, err := f.client.httpClient.PostForm(resolveActionURL(resp.Request.URL, action), data)
	if err != nil {
		return nil, true, fmt.Errorf("SAML POST failed: %w", err)
	}

	return nextResp, true, nil
}

func (f *kerberosLoginFlow) successResult(resp *http.Response) *LoginResult {
	finalURI := resp.Request.URL.String()
	if f.redirectURI == "" {
		f.redirectURI = finalURI
	}

	return &LoginResult{
		Cookies:     f.client.GetCookies(resp.Request.URL),
		RedirectURI: f.redirectURI,
		Username:    f.client.username,
	}
}

func closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

func isRedirectStatus(statusCode int) bool {
	return statusCode == http.StatusFound ||
		statusCode == http.StatusMovedPermanently ||
		statusCode == http.StatusSeeOther
}

func resolveRedirectLocation(baseURL *url.URL, location string) (string, *url.URL, error) {
	locURL, err := url.Parse(location)
	if err != nil {
		return "", nil, err
	}
	if !locURL.IsAbs() {
		locURL = baseURL.ResolveReference(locURL)
	}

	return locURL.String(), locURL, nil
}

func resolveActionURL(baseURL *url.URL, action string) string {
	actionURL, err := url.Parse(action)
	if err != nil {
		return action
	}
	if actionURL.IsAbs() {
		return actionURL.String()
	}

	return baseURL.ResolveReference(actionURL).String()
}

func withResponseBody(resp *http.Response, body []byte) *http.Response {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp
}
