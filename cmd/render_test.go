package cmd

import (
	"encoding/json"
	"testing"

	"github.com/clelange/cern-sso-cli/pkg/auth"
)

func TestWriteCommandOutputQuietSuppressesOutput(t *testing.T) {
	oldQuiet := quiet
	quiet = true
	defer func() { quiet = oldQuiet }()

	stdout, stderr := captureStdoutStderr(t, func() {
		if err := writeCommandOutput(true, map[string]string{"result": "ok"}, "visible"); err != nil {
			t.Fatalf("writeCommandOutput failed: %v", err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("expected no stderr output, got %q", stderr)
	}
}

func TestRenderTokenOutputJSON(t *testing.T) {
	oldQuiet := quiet
	oldTokenJSON := tokenJSON
	quiet = false
	tokenJSON = true
	defer func() {
		quiet = oldQuiet
		tokenJSON = oldTokenJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := renderTokenOutput("token-123"); err != nil {
			t.Fatalf("renderTokenOutput failed: %v", err)
		}
	})

	var output TokenOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", stdout, err)
	}

	if output.AccessToken != "token-123" {
		t.Fatalf("expected access token %q, got %q", "token-123", output.AccessToken)
	}
	if output.TokenType != "Bearer" {
		t.Fatalf("expected token type %q, got %q", "Bearer", output.TokenType)
	}
}

func TestRenderTokenOutputQuiet(t *testing.T) {
	oldQuiet := quiet
	oldTokenJSON := tokenJSON
	quiet = true
	tokenJSON = false
	defer func() {
		quiet = oldQuiet
		tokenJSON = oldTokenJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := renderTokenOutput("token-123"); err != nil {
			t.Fatalf("renderTokenOutput failed: %v", err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
}

func TestRenderDeviceOutputText(t *testing.T) {
	oldQuiet := quiet
	oldDeviceJSON := deviceJSON
	quiet = false
	deviceJSON = false
	defer func() {
		quiet = oldQuiet
		deviceJSON = oldDeviceJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := renderDeviceOutput(&auth.TokenResponse{
			AccessToken:  "access-123",
			RefreshToken: "refresh-456",
		}); err != nil {
			t.Fatalf("renderDeviceOutput failed: %v", err)
		}
	})

	expected := "Access Token:\naccess-123\n\nRefresh Token:\nrefresh-456\n"
	if stdout != expected {
		t.Fatalf("expected stdout %q, got %q", expected, stdout)
	}
}

func TestRenderHarborOutputQuiet(t *testing.T) {
	oldQuiet := quiet
	oldHarborJSON := harborJSON
	quiet = true
	harborJSON = false
	defer func() {
		quiet = oldQuiet
		harborJSON = oldHarborJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := renderHarborOutput("alice", "secret-123"); err != nil {
			t.Fatalf("renderHarborOutput failed: %v", err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
}

func TestRenderOpenShiftOutputLoginCommand(t *testing.T) {
	oldQuiet := quiet
	oldOpenShiftJSON := openshiftJSON
	oldOpenShiftLoginCmd := openshiftLoginCmd
	quiet = false
	openshiftJSON = false
	openshiftLoginCmd = true
	defer func() {
		quiet = oldQuiet
		openshiftJSON = oldOpenShiftJSON
		openshiftLoginCmd = oldOpenShiftLoginCmd
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := renderOpenShiftOutput(
			"oc login --token=sha256~token --server=https://api.example:6443",
			"sha256~token",
			"https://api.example:6443",
		); err != nil {
			t.Fatalf("renderOpenShiftOutput failed: %v", err)
		}
	})

	expected := "oc login --token=sha256~token --server=https://api.example:6443\n"
	if stdout != expected {
		t.Fatalf("expected stdout %q, got %q", expected, stdout)
	}
}

func TestPrintCookieOutputJSON(t *testing.T) {
	oldQuiet := quiet
	oldCookieJSON := cookieJSON
	quiet = false
	cookieJSON = true
	defer func() {
		quiet = oldQuiet
		cookieJSON = oldCookieJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := printCookieOutput(&CookieOutput{
			File:  "cookies.txt",
			Count: 2,
			User:  "alice@CERN.CH",
		}); err != nil {
			t.Fatalf("printCookieOutput failed: %v", err)
		}
	})

	var output CookieOutput
	if err := json.Unmarshal([]byte(stdout), &output); err != nil {
		t.Fatalf("expected JSON output, got %q: %v", stdout, err)
	}

	if output.File != "cookies.txt" {
		t.Fatalf("expected file %q, got %q", "cookies.txt", output.File)
	}
	if output.Count != 2 {
		t.Fatalf("expected count %d, got %d", 2, output.Count)
	}
	if output.User != "alice@CERN.CH" {
		t.Fatalf("expected user %q, got %q", "alice@CERN.CH", output.User)
	}
}

func TestPrintCookieOutputDefaultModeIsSilent(t *testing.T) {
	oldQuiet := quiet
	oldCookieJSON := cookieJSON
	quiet = false
	cookieJSON = false
	defer func() {
		quiet = oldQuiet
		cookieJSON = oldCookieJSON
	}()

	stdout, _ := captureStdoutStderr(t, func() {
		if err := printCookieOutput(&CookieOutput{
			File:  "cookies.txt",
			Count: 2,
		}); err != nil {
			t.Fatalf("printCookieOutput failed: %v", err)
		}
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
}
