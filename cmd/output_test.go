package cmd

import (
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdoutStderr(t *testing.T, fn func()) (string, string) {
	t.Helper()

	oldStdout := os.Stdout
	oldStderr := os.Stderr

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}

	os.Stdout = stdoutW
	os.Stderr = stderrW
	defer func() {
		os.Stdout = oldStdout
		os.Stderr = oldStderr
	}()

	fn()

	_ = stdoutW.Close()
	_ = stderrW.Close()

	stdoutBytes, err := io.ReadAll(stdoutR)
	if err != nil {
		t.Fatalf("failed to read stdout: %v", err)
	}
	stderrBytes, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatalf("failed to read stderr: %v", err)
	}

	_ = stdoutR.Close()
	_ = stderrR.Close()

	return string(stdoutBytes), string(stderrBytes)
}

func TestLogInfoWritesToStderr(t *testing.T) {
	oldQuiet := quiet
	quiet = false
	defer func() { quiet = oldQuiet }()

	stdout, stderr := captureStdoutStderr(t, func() {
		logInfo("hello %s", "world")
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	if stderr != "hello world" {
		t.Fatalf("expected stderr output %q, got %q", "hello world", stderr)
	}
}

func TestLogPrintlnWritesToStderr(t *testing.T) {
	oldQuiet := quiet
	quiet = false
	defer func() { quiet = oldQuiet }()

	stdout, stderr := captureStdoutStderr(t, func() {
		logPrintln("line", 2)
	})

	if stdout != "" {
		t.Fatalf("expected no stdout output, got %q", stdout)
	}
	if strings.TrimSpace(stderr) != "line 2" {
		t.Fatalf("expected stderr output %q, got %q", "line 2", stderr)
	}
}
