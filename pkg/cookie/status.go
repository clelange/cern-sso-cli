package cookie

import (
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

// printStatusJSON displays cookies in JSON format.
func printStatusJSON(cookies []*http.Cookie, w io.Writer) {
	fmt.Fprintln(w, "[")
	now := time.Now()
	for i, c := range cookies {
		var status string
		var remainingSeconds float64

		if c.Expires.IsZero() || c.Expires.Unix() <= 0 {
			status = "session"
			remainingSeconds = 0
		} else if c.Expires.Before(now) {
			status = "expired"
			remainingSeconds = 0
		} else {
			status = "valid"
			remainingSeconds = c.Expires.Sub(now).Seconds()
		}

		fmt.Fprintf(w, "  {\n")
		fmt.Fprintf(w, "    \"name\": %q,\n", c.Name)
		fmt.Fprintf(w, "    \"domain\": %q,\n", c.Domain)
		fmt.Fprintf(w, "    \"path\": %q,\n", c.Path)
		fmt.Fprintf(w, "    \"secure\": %v,\n", c.Secure)
		fmt.Fprintf(w, "    \"http_only\": %v,\n", c.HttpOnly)

		if c.Expires.IsZero() || c.Expires.Unix() <= 0 {
			fmt.Fprintf(w, "    \"expires\": null,\n")
		} else {
			fmt.Fprintf(w, "    \"expires\": %q,\n", c.Expires.Format(time.RFC3339))
		}

		fmt.Fprintf(w, "    \"status\": %q,\n", status)
		fmt.Fprintf(w, "    \"remaining_seconds\": %.0f\n", remainingSeconds)
		fmt.Fprintf(w, "  }")

		if i < len(cookies)-1 {
			fmt.Fprintf(w, ",")
		}
		fmt.Fprintln(w, "")
	}
	fmt.Fprintln(w, "]")
}
