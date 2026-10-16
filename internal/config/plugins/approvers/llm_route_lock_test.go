package approvers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// captureJudge records the judge call's URL and headers, then answers 503.
type captureJudge struct {
	url    *string
	header *http.Header
}

func (c captureJudge) RoundTrip(r *http.Request) (*http.Response, error) {
	*c.url = r.URL.String()
	*c.header = r.Header.Clone()
	return &http.Response{StatusCode: 503, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

// TestLockApproverRouting pins model family → judge URL and headers, for
// both Approve and Summarize (the HITL classifier).
func TestLockApproverRouting(t *testing.T) {
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge":     {Body: nopHTTPCredential{}},
		"grokjudge": {Body: nopHTTPCredential{}, Plugin: &config.Plugin{Type: "grok_oauth"}},
		// D-R4-8 (A): a type the backend's own provider owns.
		"claudejudge": {Body: nopHTTPCredential{}, Plugin: &config.Plugin{Type: "anthropic_oauth_subscription"}},
	}}
	saved := llmJudgeClient
	defer func() { llmJudgeClient = saved }()
	cases := []struct {
		model, cred string
		wantURL     string            // "" = denied as unknown family, no call
		wantHeader  map[string]string // headers the judge call must carry
		wantDeny    string            // set: denied for its credential type, no call
	}{
		{model: "claude-sonnet-4", cred: "judge", wantURL: "https://api.anthropic.com/v1/messages",
			wantHeader: map[string]string{"anthropic-version": "2023-06-01", "Content-Type": "application/json"}},
		{model: "gpt-5", cred: "judge", wantURL: "https://api.openai.com/v1/responses", wantHeader: map[string]string{"Content-Type": "application/json"}},
		{model: "o1", cred: "judge", wantURL: "https://api.openai.com/v1/responses", wantHeader: map[string]string{"Content-Type": "application/json"}},
		{model: "o3-mini", cred: "judge", wantURL: "https://api.openai.com/v1/responses", wantHeader: map[string]string{"Content-Type": "application/json"}},
		{model: "o4-mini", cred: "judge", wantURL: "https://api.openai.com/v1/responses", wantHeader: map[string]string{"Content-Type": "application/json"}},
		{model: "omni-x", cred: "judge"},
		{model: "grok-4", cred: "grokjudge", wantURL: "https://cli-chat-proxy.grok.com/v1/responses",
			wantHeader: map[string]string{"X-XAI-Token-Auth": "xai-grok-cli"}},
		{model: "grok-4", cred: "judge", wantDeny: "cannot back this judge"},
		// D-R4-8 (A): with CredentialTypes empty, another provider's
		// credential type is denied; the backend's own provider's is not.
		{model: "claude-sonnet-4", cred: "grokjudge", wantDeny: "cannot back this judge"},
		{model: "gpt-5", cred: "grokjudge", wantDeny: "cannot back this judge"},
		{model: "claude-sonnet-4", cred: "claudejudge", wantURL: "https://api.anthropic.com/v1/messages",
			wantHeader: map[string]string{"anthropic-version": "2023-06-01", "Content-Type": "application/json"}},
		{model: "llama-3", cred: "judge"},
	}
	for _, tc := range cases {
		var gotURL string
		var gotHeader http.Header
		llmJudgeClient = &http.Client{Transport: captureJudge{&gotURL, &gotHeader}}
		a := &LLMApprover{Model: tc.model, Credential: tc.cred}
		req := runtime.ApproveRequest{Policy: policy, Secrets: okSecrets{}}
		v, err := a.Approve(context.Background(), req)
		if err != nil {
			t.Fatalf("%s: Approve: %v", tc.model, err)
		}
		approveURL, approveHeader := gotURL, gotHeader
		gotURL, gotHeader = "", nil
		_, serr := a.Summarize(context.Background(), req)
		if tc.wantDeny != "" {
			if v.Decision != "deny" || !strings.Contains(v.Reason, tc.wantDeny) || approveURL != "" {
				t.Errorf("%s/%s: Approve verdict %+v url %q, want a deny containing %q with no call", tc.model, tc.cred, v, approveURL, tc.wantDeny)
			}
			if serr == nil || !strings.Contains(serr.Error(), tc.wantDeny) || gotURL != "" {
				t.Errorf("%s/%s: Summarize err %v url %q, want an error containing %q with no call", tc.model, tc.cred, serr, gotURL, tc.wantDeny)
			}
			continue
		}
		if tc.wantURL == "" {
			if v.Decision != "deny" || !strings.Contains(v.Reason, "unknown model family") || approveURL != "" {
				t.Errorf("%s: Approve verdict %+v url %q, want unknown-family deny with no call", tc.model, v, approveURL)
			}
			if serr == nil || !strings.Contains(serr.Error(), "unknown model family") || gotURL != "" {
				t.Errorf("%s: Summarize err %v url %q, want unknown-family error with no call", tc.model, serr, gotURL)
			}
			continue
		}
		if approveURL != tc.wantURL || gotURL != tc.wantURL {
			t.Errorf("%s: judge URL Approve=%q Summarize=%q, want %q", tc.model, approveURL, gotURL, tc.wantURL)
		}
		if tc.wantURL != "" && len(tc.wantHeader) == 0 {
			t.Errorf("%s: row has no wantHeader; every routed row must pin its headers", tc.model)
		}
		for k, want := range tc.wantHeader {
			if approveHeader.Get(k) != want || gotHeader.Get(k) != want {
				t.Errorf("%s: header %s Approve=%q Summarize=%q, want %q", tc.model, k, approveHeader.Get(k), gotHeader.Get(k), want)
			}
		}
	}
}
