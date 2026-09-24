#!/usr/bin/env python3
"""Verify a saved cookie file against GitLab without printing credentials or profiles."""

import json
import subprocess
import sys


def verify_cookies(cookie_file, url="https://gitlab.cern.ch/api/v4/user"):
    # curl handles Netscape session cookies (expiry 0) and enforces cookie scope.
    # Do not follow redirects: a login page is an authentication failure.
    result = subprocess.run(
        [
            "curl", "--disable", "--silent", "--show-error", "--max-time", "30",
            "--cookie", str(cookie_file), "--write-out", "\n%{http_code}",
            "--url", url,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise ValueError("GitLab cookie verification request failed")

    body, _, status = result.stdout.rpartition("\n")
    if status != "200":
        raise ValueError("GitLab cookie verification did not return HTTP 200")
    try:
        profile = json.loads(body)
    except ValueError:
        raise ValueError("GitLab cookie verification did not return JSON") from None
    if (
        not isinstance(profile, dict)
        or type(profile.get("id")) is not int
        or profile["id"] <= 0
        or not isinstance(profile.get("username"), str)
        or not profile["username"].strip()
    ):
        raise ValueError("GitLab cookie verification did not return an authenticated user")


def main():
    if len(sys.argv) != 2:
        print("Usage: verify_gitlab_cookies.py COOKIE_FILE", file=sys.stderr)
        return 2
    try:
        verify_cookies(sys.argv[1])
    except (ValueError, OSError) as error:
        # Only our structural diagnostics are safe to print, never curl output.
        message = str(error) if isinstance(error, ValueError) else "Could not run curl"
        print(message, file=sys.stderr)
        return 1
    print("Saved cookies successfully authenticated to GitLab")
    return 0


if __name__ == "__main__":
    sys.exit(main())
