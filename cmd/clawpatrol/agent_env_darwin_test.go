//go:build darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Review I-4 (N-32, R4-05 on darwin): applyEnvPushdown, the darwin and
// tsnet launchers' pushdown, composes through envPushdownVars, so the
// local CA vars are added and a gateway-pushed CA var is dropped: the
// MITM CA wins over both the pushed value and the operator's (I5).
func TestApplyEnvPushdownComposesCAVars(t *testing.T) {
	caDir := t.TempDir()
	caPath := filepath.Join(caDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAWPATROL_NO_ENV", "")
	t.Setenv("SSL_CERT_FILE", "/operator.pem")
	t.Setenv("NODE_EXTRA_CA_CERTS", "/operator.pem")
	t.Setenv("ANTHROPIC_API_KEY", "")
	for name := range clawpatrolCAVarNames {
		if name != "SSL_CERT_FILE" && name != "NODE_EXTRA_CA_CERTS" {
			t.Setenv(name, "")
		}
	}
	prevD, prevG := envPushdownDaemonFetcher, envPushdownGatewayFetcher
	t.Cleanup(func() { envPushdownDaemonFetcher, envPushdownGatewayFetcher = prevD, prevG })
	envPushdownDaemonFetcher = nil
	envPushdownGatewayFetcher = func(string) ([]pushdownEnvVar, error) {
		return []pushdownEnvVar{
			{Name: "SSL_CERT_FILE", Value: "/evil.pem"},
			{Name: "NODE_EXTRA_CA_CERTS", Value: "/evil.pem"},
			{Name: "ANTHROPIC_API_KEY", Value: "sk-ant-clawpatrol-placeholder"},
		}, nil
	}
	applyEnvPushdown(caDir)
	// ca.crt holds no usable CA, so ensureCABundle falls back to ca.crt
	// itself for the replace-style vars.
	if got := os.Getenv("SSL_CERT_FILE"); got != caPath {
		t.Errorf("SSL_CERT_FILE = %q, want the local CA %q", got, caPath)
	}
	if got := os.Getenv("NODE_EXTRA_CA_CERTS"); got != caPath {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want the local CA %q", got, caPath)
	}
	if got := os.Getenv("ANTHROPIC_API_KEY"); got != "sk-ant-clawpatrol-placeholder" {
		t.Errorf("ANTHROPIC_API_KEY = %q, want the pushed placeholder", got)
	}
}
