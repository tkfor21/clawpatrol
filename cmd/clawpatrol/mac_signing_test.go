package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// xcconfigValue returns the last `key = value` assignment in an
// xcconfig file, the same lookup macos/signing-value.sh does.
func xcconfigValue(t *testing.T, path, key string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var v string
	for line := range strings.Lines(string(b)) {
		k, val, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == key {
			v = strings.TrimSpace(val)
		}
	}
	if v == "" {
		t.Fatalf("%s: no %s assignment", path, key)
	}
	return v
}

// The doctor looks for the system extension by bundle ID. Its default
// has to match the one Clawpatrol.app is built with, or `clawpatrol
// doctor` reports a working extension as missing.
func TestMacBundleIDPrefixMatchesSigningXcconfig(t *testing.T) {
	want := xcconfigValue(t, filepath.Join("..", "..", "macos", "Signing.xcconfig"), "CLAWPATROL_BUNDLE_ID_PREFIX")
	if macBundleIDPrefix != want {
		t.Fatalf("macBundleIDPrefix = %q, macos/Signing.xcconfig has %q", macBundleIDPrefix, want)
	}
}

// Signing.xcconfig derives the extension ID as <prefix>.app.extension.
func TestMacExtensionBundleIDDerivesFromPrefix(t *testing.T) {
	old := macBundleIDPrefix
	t.Cleanup(func() { macBundleIDPrefix = old })

	macBundleIDPrefix = "dev.clawpatrol.fork"
	if got, want := macExtensionBundleID(), "dev.clawpatrol.fork.app.extension"; got != want {
		t.Fatalf("macExtensionBundleID() = %q, want %q", got, want)
	}
}
