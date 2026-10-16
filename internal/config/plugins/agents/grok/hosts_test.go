package grok

import (
	"slices"
	"testing"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// TestGrokHostDecisions pins the hosts the gateway injects grok's real
// session token into. Live runs also saw api.x.ai (/v1/tokenize-text, a
// token-count telemetry call that carries the session bearer), grok.com
// (/_data/v1/events, product telemetry keyed by a build-time events key),
// x.ai (/cli/*, the unauthenticated self-updater) and the
// code.grok.com/ws/code-agent relay (session bearer, headless and leader
// mode only). None is declared: declaring a host sends the real session
// token there and scrubs its responses, which only a host that needs the
// bearer for a feature operators need earns (see grok.go).
//
// Every API host must also be a destination the models-cache check
// accepts (trustedXAIURL), or a cache grok fetched from its own API host
// would refuse the launch.
func TestGrokHostDecisions(t *testing.T) {
	p := agentprovider.ByID("grok")
	if p == nil {
		t.Fatal("grok provider not registered")
	}
	if want := []string{"cli-chat-proxy.grok.com"}; !slices.Equal(p.APIHosts, want) {
		t.Fatalf("APIHosts = %v, want %v: a new API host gets the real session token; record its decision here and in site/doc", p.APIHosts, want)
	}
	for _, h := range []string{"api.x.ai", "grok.com", "x.ai", "code.grok.com"} {
		if got := agentprovider.ByHost(h); got != nil && got.ID == "grok" && slices.Contains(got.APIHosts, h) {
			t.Errorf("%s is a grok API host; it was decided against", h)
		}
	}
	for _, h := range p.APIHosts {
		if !trustedXAIURL("https://" + h + "/v1") {
			t.Errorf("API host %s is not a trusted models-cache destination", h)
		}
	}
}
