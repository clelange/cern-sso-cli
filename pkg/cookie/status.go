package cookie

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// truncateString shortens a string to maxLen characters, adding "..." if truncated.
func truncateString(s string, maxLen int) string {
	if utf8.RuneCountInString(s) <= maxLen {
		return s
	}

	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}

	return string(runes[:maxLen-3]) + "..."
}

// PrintStatus displays cookie information in either table or JSON format.
// If asJSON is true, output is in JSON format. Otherwise, a formatted table is shown.
func PrintStatus(cookies []*http.Cookie, asJSON bool, w io.Writer) {
	if asJSON {
		printStatusJSON(cookies, w)
	} else {
		printStatusTable(cookies, w)
	}
}

// printStatusTable displays cookies in a formatted table.
func printStatusTable(cookies []*http.Cookie, w io.Writer) {
	if len(cookies) == 0 {
		fmt.Fprintln(w, "No cookies found.")
		return
	}

	sort.Slice(cookies, func(i, j int) bool {
		domainI := cookies[i].Domain
		domainJ := cookies[j].Domain
		if domainI == "" {
			domainI = "<no domain>"
		}
		if domainJ == "" {
			domainJ = "<no domain>"
		}
		return domainI < domainJ
	})

	fmt.Fprintln(w, "Cookie Status:")
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "%-32s %-20s %-22s %-20s %-10s\n", "Name", "Domain", "Path", "Expires", "Status")
	fmt.Fprintln(w, strings.Repeat("-", 104))

	now := time.Now()
	for _, c := range cookies {
		var expiresStr, status string

		if c.Expires.IsZero() || c.Expires.Unix() <= 0 {
			expiresStr = "Session"
			status = "Session"
		} else if c.Expires.Before(now) {
			expiresStr = c.Expires.Format("2006-01-02 15:04:05")
			status = "✗ Expired"
		} else {
			expiresStr = c.Expires.Format("2006-01-02 15:04:05")
			remaining := c.Expires.Sub(now)
			if remaining < time.Minute {
				status = fmt.Sprintf("✓ %ds", int(remaining.Seconds()))
			} else if remaining < time.Hour {
				status = fmt.Sprintf("✓ %dm", int(remaining.Minutes()))
			} else if remaining < 24*time.Hour {
				status = fmt.Sprintf("✓ %dh", int(remaining.Hours()))
			} else {
				status = fmt.Sprintf("✓ %dd", int(remaining.Hours()/24))
			}
		}

		flags := []string{}
		if c.Secure {
			flags = append(flags, "S")
		}
		if c.HttpOnly {
			flags = append(flags, "H")
		}
		flagStr := ""
		if len(flags) > 0 {
			flagStr = fmt.Sprintf("[%s]", strings.Join(flags, ","))
		}

		domain := c.Domain
		if domain == "" {
			domain = "<no domain>"
		}

		fmt.Fprintf(w, "%-32s %-20s %-22s %-20s %-10s\n",
			truncateString(c.Name, 32), domain, truncateString(c.Path, 22), expiresStr, status+" "+flagStr)
	}
}

// CookieStatusJSON represents cookie data for JSON output.
type CookieStatusJSON struct {
	Name             string  `json:"name"`
	Domain           string  `json:"domain"`
	Path             string  `json:"path"`
	Secure           bool    `json:"secure"`
	HttpOnly         bool    `json:"http_only"`
	Expires          *string `json:"expires"`
	Status           string  `json:"status"`
	RemainingSeconds float64 `json:"remaining_seconds"`
}

// printStatusJSON displays cookies in JSON format.
func printStatusJSON(cookies []*http.Cookie, w io.Writer) {
	now := time.Now()
	result := make([]CookieStatusJSON, len(cookies))

	for i, c := range cookies {
		var status string
		var remainingSeconds float64
		var expires *string

		if c.Expires.IsZero() || c.Expires.Unix() <= 0 {
			status = "session"
			remainingSeconds = 0
			expires = nil
		} else if c.Expires.Before(now) {
			status = "expired"
			remainingSeconds = 0
			expiresStr := c.Expires.Format(time.RFC3339)
			expires = &expiresStr
		} else {
			status = "valid"
			remainingSeconds = c.Expires.Sub(now).Seconds()
			expiresStr := c.Expires.Format(time.RFC3339)
			expires = &expiresStr
		}

		result[i] = CookieStatusJSON{
			Name:             c.Name,
			Domain:           c.Domain,
			Path:             c.Path,
			Secure:           c.Secure,
			HttpOnly:         c.HttpOnly,
			Expires:          expires,
			Status:           status,
			RemainingSeconds: remainingSeconds,
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}
