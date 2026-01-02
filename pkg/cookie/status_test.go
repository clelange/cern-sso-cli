package cookie

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPrintStatusTable_ValidCookie(t *testing.T) {
	now := time.Now()
	validCookie := &http.Cookie{
		Name:    "test_cookie",
		Value:   "test_value",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(24 * time.Hour),
		Secure:  true,
	}

	cookies := []*http.Cookie{validCookie}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()
	if !strings.Contains(output, "test_cookie") {
		t.Error("Output should contain cookie name")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Output should contain domain")
	}
	if !strings.Contains(output, "✓") {
		t.Error("Output should show valid cookie with checkmark")
	}
	if !strings.Contains(output, "[S]") {
		t.Error("Output should show Secure flag")
	}
}

func TestPrintStatusTable_ExpiredCookie(t *testing.T) {
	expiredCookie := &http.Cookie{
		Name:    "expired_cookie",
		Value:   "test_value",
		Domain:  "example.com",
		Path:    "/",
		Expires: time.Now().Add(-1 * time.Hour),
		Secure:  false,
	}

	cookies := []*http.Cookie{expiredCookie}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()
	if !strings.Contains(output, "expired_cookie") {
		t.Error("Output should contain cookie name")
	}
	if !strings.Contains(output, "✗ Expired") {
		t.Error("Output should show expired cookie with X mark")
	}
	if !strings.Contains(output, "example.com") {
		t.Error("Output should contain domain")
	}
}

func TestPrintStatusTable_SessionCookie(t *testing.T) {
	sessionCookie := &http.Cookie{
		Name:     "session_cookie",
		Value:    "test_value",
		Domain:   "example.com",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	}

	cookies := []*http.Cookie{sessionCookie}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()
	if !strings.Contains(output, "session_cookie") {
		t.Error("Output should contain cookie name")
	}
	if !strings.Contains(output, "Session") {
		t.Error("Output should show session cookie")
	}
	if !strings.Contains(output, "[H]") {
		t.Error("Output should show HttpOnly flag")
	}
}

func TestPrintStatusTable_MultipleCookies(t *testing.T) {
	now := time.Now()

	cookies := []*http.Cookie{
		{
			Name:    "valid_1",
			Value:   "val1",
			Domain:  "example.com",
			Path:    "/",
			Expires: now.Add(1 * time.Hour),
			Secure:  true,
		},
		{
			Name:    "expired_1",
			Value:   "val2",
			Domain:  "example.com",
			Path:    "/",
			Expires: now.Add(-1 * time.Hour),
		},
		{
			Name:     "valid_2",
			Value:    "val3",
			Domain:   "sub.example.com",
			Path:     "/api",
			Expires:  now.Add(2 * time.Hour),
			HttpOnly: true,
		},
	}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()
	validCount := strings.Count(output, "✓")
	expiredCount := strings.Count(output, "✗ Expired")

	if validCount != 2 {
		t.Errorf("Expected 2 valid cookies, got %d", validCount)
	}
	if expiredCount != 1 {
		t.Errorf("Expected 1 expired cookie, got %d", expiredCount)
	}

	if !strings.Contains(output, "sub.example.com") {
		t.Error("Output should contain subdomain")
	}
	if !strings.Contains(output, "/api") {
		t.Error("Output should contain path")
	}
}

func TestPrintStatusTable_NoCookies(t *testing.T) {
	cookies := []*http.Cookie{}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()
	if !strings.Contains(output, "No cookies found") {
		t.Error("Output should show no cookies message")
	}
}

func TestPrintStatusTable_LongCookieName(t *testing.T) {
	now := time.Now()

	shortNameCookie := &http.Cookie{
		Name:    "short",
		Value:   "val1",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(1 * time.Hour),
	}

	longNameCookie := &http.Cookie{
		Name:    "this_is_a_very_long_cookie_name_that_exceeds_32_characters",
		Value:   "val2",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(1 * time.Hour),
	}

	exactly32Cookie := &http.Cookie{
		Name:    "exactly_32_characters_long_name!",
		Value:   "val3",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(1 * time.Hour),
	}

	cookies := []*http.Cookie{shortNameCookie, longNameCookie, exactly32Cookie}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()

	if !strings.Contains(output, "short") {
		t.Error("Output should contain short cookie name unchanged")
	}

	truncatedName := "this_is_a_very_long_cookie_na..."
	if !strings.Contains(output, truncatedName) {
		t.Errorf("Output should contain truncated long cookie name: %s", truncatedName)
	}

	if !strings.Contains(output, "exactly_32_characters_long_name!") {
		t.Error("Output should contain 32-character name unchanged")
	}

	if strings.Contains(output, "this_is_a_very_long_cookie_name_that_exceeds_32_characters") {
		t.Error("Output should NOT contain the full long cookie name")
	}
}

func TestPrintStatusTable_LongPath(t *testing.T) {
	now := time.Now()

	shortPathCookie := &http.Cookie{
		Name:    "cookie1",
		Value:   "val1",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(1 * time.Hour),
	}

	longPathCookie := &http.Cookie{
		Name:    "cookie2",
		Value:   "val2",
		Domain:  "example.com",
		Path:    "/very/long/path/that/exceeds/22/characters",
		Expires: now.Add(1 * time.Hour),
	}

	exactly22PathCookie := &http.Cookie{
		Name:    "cookie3",
		Value:   "val3",
		Domain:  "example.com",
		Path:    "/exactly/22/chars/path",
		Expires: now.Add(1 * time.Hour),
	}

	cookies := []*http.Cookie{shortPathCookie, longPathCookie, exactly22PathCookie}

	var buf bytes.Buffer
	printStatusTable(cookies, &buf)

	output := buf.String()

	if !strings.Contains(output, "/") {
		t.Error("Output should contain short path unchanged")
	}

	truncatedPath := "/very/long/path/tha..."
	if !strings.Contains(output, truncatedPath) {
		t.Errorf("Output should contain truncated long path: %s", truncatedPath)
	}

	if !strings.Contains(output, "/exactly/22/chars/path") {
		t.Error("Output should contain 22-character path unchanged")
	}

	if strings.Contains(output, "/very/long/path/that/exceeds/22/characters") {
		t.Error("Output should NOT contain the full long path")
	}
}

func TestPrintStatusJSON_ValidCookie(t *testing.T) {
	now := time.Now()
	validCookie := &http.Cookie{
		Name:    "test_cookie",
		Value:   "test_value",
		Domain:  "example.com",
		Path:    "/",
		Expires: now.Add(24 * time.Hour),
		Secure:  true,
	}

	cookies := []*http.Cookie{validCookie}

	var buf bytes.Buffer
	printStatusJSON(cookies, &buf)

	output := buf.String()

	if !strings.Contains(output, `"name": "test_cookie"`) {
		t.Error("JSON should contain cookie name")
	}
	if !strings.Contains(output, `"domain": "example.com"`) {
		t.Error("JSON should contain domain")
	}
	if !strings.Contains(output, `"secure": true`) {
		t.Error("JSON should show secure as true")
	}
	if !strings.Contains(output, `"http_only": false`) {
		t.Error("JSON should show http_only as false")
	}
	if !strings.Contains(output, `"status": "valid"`) {
		t.Error("JSON should show status as valid")
	}
}

func TestPrintStatusJSON_SessionCookie(t *testing.T) {
	sessionCookie := &http.Cookie{
		Name:    "session_cookie",
		Value:   "test_value",
		Domain:  "example.com",
		Path:    "/",
		Expires: time.Unix(0, 0),
	}

	cookies := []*http.Cookie{sessionCookie}

	var buf bytes.Buffer
	printStatusJSON(cookies, &buf)

	output := buf.String()

	if !strings.Contains(output, `"expires": null`) {
		t.Error("JSON should show expires as null for session cookies")
	}
	if !strings.Contains(output, `"status": "session"`) {
		t.Error("JSON should show status as session")
	}
	if !strings.Contains(output, `"remaining_seconds": 0`) {
		t.Error("JSON should show remaining_seconds as 0 for session cookies")
	}
}

func TestPrintStatusJSON_ExpiredCookie(t *testing.T) {
	expiredCookie := &http.Cookie{
		Name:    "expired_cookie",
		Value:   "test_value",
		Domain:  "example.com",
		Path:    "/",
		Expires: time.Now().Add(-1 * time.Hour),
	}

	cookies := []*http.Cookie{expiredCookie}

	var buf bytes.Buffer
	printStatusJSON(cookies, &buf)

	output := buf.String()

	if !strings.Contains(output, `"status": "expired"`) {
		t.Error("JSON should show status as expired")
	}
	if !strings.Contains(output, `"remaining_seconds": 0`) {
		t.Error("JSON should show remaining_seconds as 0 for expired cookies")
	}
}

func TestPrintStatusJSON_EmptyCookies(t *testing.T) {
	cookies := []*http.Cookie{}

	var buf bytes.Buffer
	printStatusJSON(cookies, &buf)

	output := buf.String()

	if output != "[\n]\n" {
		t.Errorf("Expected empty JSON array with newlines, got: %q", output)
	}
}
