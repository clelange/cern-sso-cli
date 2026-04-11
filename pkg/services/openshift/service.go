package openshift

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
)

const httpTimeout = 30 * time.Second

// LogFunc receives informational messages generated during the flow.
type LogFunc func(format string, args ...any)

// LoginCommandResult contains the extracted `oc login` command details.
type LoginCommandResult struct {
	Command string
	Token   string
	Server  string
}

// FetchLoginCommand fetches the OpenShift token page and extracts the login command.
//
//nolint:cyclop // OpenShift token flow requires multiple steps and parsing branches
func FetchLoginCommand(
	oauthBaseURL string,
	clusterURL string,
	authHost string,
	cookies []*http.Cookie,
	verifyCerts bool,
	logf LogFunc,
) (*LoginCommandResult, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cookie jar: %w", err)
	}

	transport := &http.Transport{}
	if !verifyCerts {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402
	}

	client := &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   httpTimeout,
	}

	oauthURL, err := url.Parse(oauthBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid OAuth base URL: %w", err)
	}
	jar.SetCookies(oauthURL, cookies)

	authURL, err := url.Parse("https://" + authHost)
	if err != nil {
		return nil, fmt.Errorf("invalid auth host: %w", err)
	}
	jar.SetCookies(authURL, cookies)

	tokenRequestURL := oauthBaseURL + "/oauth/token/request"
	resp, err := client.Get(tokenRequestURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch token request page: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch token request page (status %d): %s", resp.StatusCode, string(body))
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML: %w", err)
	}

	result := parseTokenFromPage(doc, clusterURL)
	if result.Command != "" {
		return result, nil
	}

	form := doc.Find("form")
	if form.Length() == 0 {
		return nil, fmt.Errorf("could not find Display Token form on page")
	}

	action := form.AttrOr("action", resp.Request.URL.Path)
	formURL := oauthBaseURL + action
	if strings.HasPrefix(action, "http") {
		formURL = action
	}

	method := strings.ToUpper(form.AttrOr("method", http.MethodPost))

	formData := url.Values{}
	form.Find("input").Each(func(_ int, selection *goquery.Selection) {
		name, _ := selection.Attr("name")
		value := selection.AttrOr("value", "")
		if name != "" {
			formData.Set(name, value)
		}
	})

	if logf != nil {
		logf("Submitting Display Token form...\n")
	}

	var formResp *http.Response
	if method == http.MethodGet {
		formResp, err = client.Get(formURL + "?" + formData.Encode()) // #nosec G704
	} else {
		formResp, err = client.PostForm(formURL, formData)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to submit form: %w", err)
	}
	defer func() {
		if formResp != nil && formResp.Body != nil {
			_ = formResp.Body.Close()
		}
	}()

	if formResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(formResp.Body)
		return nil, fmt.Errorf("form submission failed (status %d): %s", formResp.StatusCode, string(body))
	}

	doc, err = goquery.NewDocumentFromReader(formResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token page: %w", err)
	}

	result = parseTokenFromPage(doc, clusterURL)
	if result.Command == "" {
		return nil, fmt.Errorf("could not find oc login command in response")
	}

	return result, nil
}

//nolint:cyclop // Multiple parsing strategies for different page layouts
func parseTokenFromPage(doc *goquery.Document, clusterURL string) *LoginCommandResult {
	result := &LoginCommandResult{}

	doc.Find("pre").Each(func(_ int, selection *goquery.Selection) {
		text := strings.TrimSpace(selection.Text())
		if strings.Contains(text, "oc login") && strings.Contains(text, "--token=") {
			result.Command = text
		}
	})

	doc.Find("code").Each(func(_ int, selection *goquery.Selection) {
		text := strings.TrimSpace(selection.Text())
		if strings.HasPrefix(text, "sha256~") && !strings.Contains(text, " ") {
			result.Token = strings.Trim(text, "\"'")
		}
	})

	if result.Command != "" {
		for _, part := range strings.Fields(result.Command) {
			if strings.HasPrefix(part, "--token=") {
				result.Token = strings.Trim(strings.TrimPrefix(part, "--token="), "\"'")
			}
			if strings.HasPrefix(part, "--server=") {
				result.Server = strings.Trim(strings.TrimPrefix(part, "--server="), "\"'")
			}
		}
		return result
	}

	if result.Token == "" {
		return result
	}

	doc.Find("pre").Each(func(_ int, selection *goquery.Selection) {
		text := strings.TrimSpace(selection.Text())
		if !strings.Contains(text, "--server=") {
			return
		}
		for _, part := range strings.Fields(text) {
			if strings.HasPrefix(part, "--server=") {
				result.Server = strings.Trim(strings.TrimPrefix(part, "--server="), "\"'")
				break
			}
		}
	})

	if result.Server == "" {
		parsedURL, _ := url.Parse(clusterURL)
		result.Server = parsedURL.Scheme + "://api." + parsedURL.Host + ":6443"
	}

	result.Command = fmt.Sprintf("oc login --token=%s --server=%s", result.Token, result.Server)
	return result
}
