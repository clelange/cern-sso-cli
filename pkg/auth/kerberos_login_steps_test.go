package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/client"
)

func TestFetchKerberosLoginPageFollowsInitialGitLabOIDC(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			_, _ = io.WriteString(w, `
				<html>
					<head><meta name="csrf-token" content="csrf-123"></head>
					<body>
						<form action="/users/auth/openid_connect" method="post">
							<input type="hidden" name="provider" value="openid_connect">
						</form>
					</body>
				</html>
			`)
		case "/users/auth/openid_connect":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse form: %v", err)
			}
			if got := r.Form.Get("authenticity_token"); got != "csrf-123" {
				t.Fatalf("expected authenticity token %q, got %q", "csrf-123", got)
			}
			if got := r.Form.Get("provider"); got != "openid_connect" {
				t.Fatalf("expected provider %q, got %q", "openid_connect", got)
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
		case "/login":
			_, _ = io.WriteString(w, `<html><body><a id="social-kerberos" href="/auth/kerberos">Sign in with Kerberos</a></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	page, err := kc.fetchKerberosLoginPage(server.URL + "/start")
	if err != nil {
		t.Fatalf("fetchKerberosLoginPage failed: %v", err)
	}

	if !strings.Contains(string(page.body), `id="social-kerberos"`) {
		t.Fatalf("expected Kerberos login page body, got %q", string(page.body))
	}
}

func TestResolveKerberosAuthURLFollowsRedirectChain(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kerberos":
			http.Redirect(w, r, "/step-one", http.StatusFound)
		case "/step-one":
			http.Redirect(w, r, "/spnego", http.StatusSeeOther)
		case "/spnego":
			w.WriteHeader(http.StatusUnauthorized)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	kerbAuthURL, err := kc.resolveKerberosAuthURL(server.URL + "/kerberos")
	if err != nil {
		t.Fatalf("resolveKerberosAuthURL failed: %v", err)
	}

	if kerbAuthURL != server.URL+"/spnego" {
		t.Fatalf("expected SPNEGO URL %q, got %q", server.URL+"/spnego", kerbAuthURL)
	}
}

func TestKerberosLoginFlowRunCapturesRedirectURI(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	kc.username = "alice@CERN.CH"

	callbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer callbackServer.Close()

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, callbackServer.URL+"/callback?code=abc123", http.StatusFound)
	}))
	defer authServer.Close()

	authResp, err := kc.httpClient.Get(authServer.URL)
	if err != nil {
		t.Fatalf("failed to fetch auth response: %v", err)
	}

	authURL, err := url.Parse(authServer.URL)
	if err != nil {
		t.Fatalf("failed to parse auth server URL: %v", err)
	}

	flow := newKerberosLoginFlow(kc, "https://target.example", authURL.Host)
	result, err := flow.run(authResp)
	if err != nil {
		t.Fatalf("run failed: %v", err)
	}

	wantRedirectURI := callbackServer.URL + "/callback?code=abc123"
	if result.RedirectURI != wantRedirectURI {
		t.Fatalf("expected redirect URI %q, got %q", wantRedirectURI, result.RedirectURI)
	}
	if result.Username != "alice@CERN.CH" {
		t.Fatalf("expected username %q, got %q", "alice@CERN.CH", result.Username)
	}
}

func TestMaybeSwitch2FAMethodUsesPreferredMethod(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	kc.preferredMethod = MethodWebAuthn

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/try-another":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse try-another form: %v", err)
			}
			if got := r.Form.Get("tryAnotherWay"); got != "on" {
				t.Fatalf("expected tryAnotherWay=%q, got %q", "on", got)
			}
			_, _ = io.WriteString(w, `
				<form id="kc-select-credential-form" action="/select" method="post">
					<button name="authenticationExecution" value="otp">
						<span class="select-auth-box-headline">Authenticator Application</span>
					</button>
					<button name="authenticationExecution" value="webauthn">
						<span class="fa-key"></span>
						<span class="select-auth-box-headline">Security Key</span>
					</button>
				</form>
			`)
		case "/select":
			if err := r.ParseForm(); err != nil {
				t.Fatalf("failed to parse selection form: %v", err)
			}
			if got := r.Form.Get("authenticationExecution"); got != "webauthn" {
				t.Fatalf("expected authenticationExecution=%q, got %q", "webauthn", got)
			}
			_, _ = io.WriteString(w, `<form id="kc-form-webauthn" action="/webauthn"></form>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	req, err := http.NewRequest(http.MethodGet, server.URL+"/otp", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	currentResp := &http.Response{
		StatusCode: http.StatusOK,
		Request:    req,
		Body:       io.NopCloser(strings.NewReader("")),
	}
	currentBody := []byte(`
		<form id="kc-otp-login-form" action="/otp">
			<input name="otp">
		</form>
		<form id="kc-select-try-another-way-form" action="/try-another"></form>
	`)

	flow := newKerberosLoginFlow(kc, "https://target.example", "auth.example")
	switchedResp, switchedBody, switchedBodyStr, err := flow.maybeSwitch2FAMethod(currentResp, currentBody, string(currentBody))
	if err != nil {
		t.Fatalf("maybeSwitch2FAMethod failed: %v", err)
	}

	if GetCurrentMethod(switchedBodyStr) != MethodWebAuthn {
		t.Fatalf("expected switched method %q, got %q", MethodWebAuthn, GetCurrentMethod(switchedBodyStr))
	}
	if !strings.Contains(string(switchedBody), `id="kc-form-webauthn"`) {
		t.Fatalf("expected WebAuthn body, got %q", string(switchedBody))
	}
	if switchedResp.Request.URL.Path != "/select" {
		t.Fatalf("expected final request path %q, got %q", "/select", switchedResp.Request.URL.Path)
	}
}

func TestHandleOTPStaticCodeCannotRetry(t *testing.T) {
	kc := newLoginStepsTestClient(t)
	defer kc.Close()
	kc.otpProvider = &OTPProvider{
		OTP:        "123456",
		MaxRetries: 3,
	}

	serverURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("failed to parse OTP form submission: %v", err)
		}
		if got := r.Form.Get("otp"); got != "123456" {
			t.Fatalf("expected OTP %q, got %q", "123456", got)
		}
		_, _ = io.WriteString(w, `
			<form id="kc-otp-login-form" action="`+serverURL+`" method="post">
				<input name="otp">
			</form>
		`)
	}))
	defer server.Close()
	serverURL = server.URL

	flow := newKerberosLoginFlow(kc, "https://target.example", "auth.example")
	otpBody := []byte(`
		<form id="kc-otp-login-form" action="` + server.URL + `" method="post">
			<input name="otp">
			<input type="submit" name="login" value="Sign In">
		</form>
	`)
	_, err := flow.handleOTP(otpBody)
	if err == nil {
		t.Fatal("expected OTP retry error")
	}
	if !strings.Contains(err.Error(), "Cannot retry with static OTP value") {
		t.Fatalf("expected static OTP retry error, got %v", err)
	}
}

func newLoginStepsTestClient(t *testing.T) *KerberosClient {
	t.Helper()

	cfg, err := loadTestKrb5Config()
	if err != nil {
		t.Fatalf("failed to load test config: %v", err)
	}

	cl := client.NewWithPassword("test", "CERN.CH", "test", cfg, client.DisablePAFXFAST(true))
	kc, err := newTestKerberosClient(cl, true)
	if err != nil {
		t.Fatalf("failed to create test Kerberos client: %v", err)
	}

	return kc
}
