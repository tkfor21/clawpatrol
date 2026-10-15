package approvers

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Fake values only. formsInjector sends the raw secret in x-api-key, a
// Basic header (base64 of user:secret), and a Bearer header carrying a
// derived token, and reports one more value.
const (
	formsSecret   = "FORMSSECRET0123456789ABCDEFGH"
	formsExtra    = "FORMSEXTRA9876543210QRSTUV"
	formsReported = "FORMSREPORTED55556666WXY"
	formsDerived  = "FORMSDERIVEDBEARER11112222"
)

var formsBasic = base64.StdEncoding.EncodeToString([]byte("formsuser:" + formsSecret))

var judgeValueForms = map[string]string{
	"raw":          formsSecret,
	"extra":        formsExtra,
	"reported":     formsReported,
	"basic-token":  formsBasic,
	"basic-header": "Basic " + formsBasic,
	"bearer-token": formsDerived,
	"bearer-hdr":   "Bearer " + formsDerived,
}

type formsInjector struct{}

func (formsInjector) InjectHTTP(_ context.Context, req *http.Request, sec runtime.Secret) error {
	req.Header.Set("x-api-key", string(sec.Bytes))
	req.Header.Set("Authorization", "Basic "+formsBasic)
	req.Header.Set("X-Upstream-Auth", "Bearer "+formsDerived)
	return nil
}

func (formsInjector) ConsumeHTTPRedactions(*http.Request) []string { return []string{formsReported} }

type formsSecrets struct{}

func (formsSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(formsSecret), Extras: map[string]string{"e": formsExtra}}, nil
}

func formsRequest(body any) runtime.ApproveRequest {
	return runtime.ApproveRequest{
		Policy:  &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: body}}},
		Secrets: formsSecrets{},
	}
}

// formsLeak names the first value form, or 8-byte window of a raw
// value, found in got.
func formsLeak(got string) string {
	for name, v := range judgeValueForms {
		if strings.Contains(got, v) {
			return "full " + name
		}
	}
	for name, v := range map[string]string{"raw": formsSecret, "extra": formsExtra, "reported": formsReported, "basic": formsBasic, "derived": formsDerived} {
		for i := 0; i+8 <= len(v); i++ {
			if strings.Contains(got, v[i:i+8]) {
				return "partial " + name
			}
		}
	}
	return ""
}

// toJudgeServer sends api.anthropic.com requests to a local server.
type toJudgeServer struct{ judge *url.URL }

func (r toJudgeServer) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.anthropic.com" {
		req = req.Clone(req.Context())
		req.URL.Scheme, req.URL.Host = r.judge.Scheme, r.judge.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

// useJudgeServer points the judge client at a local server, keeping the
// production client's redirect policy and timeout.
func useJudgeServer(t *testing.T, h http.HandlerFunc) {
	t.Helper()
	judge := httptest.NewServer(h)
	t.Cleanup(judge.Close)
	ju, _ := url.Parse(judge.URL)
	saved := llmJudgeClient
	t.Cleanup(func() { llmJudgeClient = saved })
	llmJudgeClient = &http.Client{Transport: toJudgeServer{judge: ju}, CheckRedirect: saved.CheckRedirect, Timeout: saved.Timeout}
}

// A judge redirect must not be followed: following it would send the
// judge-call headers to another host (Go strips only Authorization
// across hosts) and take the verdict from that host. The 3xx is a
// non-outage rejection and denies.
func TestLLMJudgeDoesNotFollowRedirects(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	var gotKey, gotUp string
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		gotKey, gotUp = r.Header.Get("x-api-key"), r.Header.Get("X-Upstream-Auth")
		mu.Unlock()
		_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"allow\nok"}]}`)
	}))
	defer second.Close()
	secondURL, _ := url.Parse(second.URL)
	secondURL.Host = strings.Replace(secondURL.Host, "127.0.0.1", "localhost", 1)

	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		useJudgeServer(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			http.Redirect(w, r, secondURL.String()+"/v1/messages", status)
		})
		a := &LLMApprover{Model: "claude-test", Credential: "judge"}
		v, err := a.Approve(context.Background(), formsRequest(formsInjector{}))
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if v.Decision != "deny" {
			t.Fatalf("status %d: Decision = %q, want deny", status, v.Decision)
		}
		if _, err := a.Summarize(context.Background(), formsRequest(formsInjector{})); err == nil {
			t.Fatalf("status %d: Summarize succeeded through a redirect", status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Fatalf("second host got %d requests (x-api-key forwarded=%v, X-Upstream-Auth forwarded=%v)", hits, gotKey != "", gotUp != "")
	}
}

// A redirect whose Location reflects the key must not put the key in
// the reason or the error.
func TestLLMJudgeRedirectLocationDoesNotLeak(t *testing.T) {
	useJudgeServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Location", "http://127.0.0.1:1/x?k="+url.QueryEscape(r.Header.Get("x-api-key")))
		w.WriteHeader(http.StatusFound)
	})
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	v, err := a.Approve(context.Background(), formsRequest(formsInjector{}))
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if l := formsLeak(v.Reason); l != "" {
		t.Fatalf("Approve reason leaks %s: %q", l, v.Reason)
	}
	_, err = a.Summarize(context.Background(), formsRequest(formsInjector{}))
	if err == nil {
		t.Fatal("Summarize: want an error")
	}
	if l := formsLeak(err.Error()); l != "" {
		t.Fatalf("Summarize error leaks %s: %q", l, err)
	}
}

// keyEchoingTransport fails every call with an error that quotes the
// judge-call headers, standing in for any transport error that names a
// server-chosen URL.
type keyEchoingTransport struct{}

func (keyEchoingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("dial http://judge.example.test/?k=" + req.Header.Get("x-api-key") +
		"&a=" + req.Header.Get("Authorization") + "&u=" + req.Header.Get("X-Upstream-Auth"))
}

// The "llm call:" transport error reaches the verdict reason and the
// classifier error, so it is redacted too.
func TestLLMJudgeTransportErrorIsRedacted(t *testing.T) {
	saved := llmJudgeClient
	t.Cleanup(func() { llmJudgeClient = saved })
	llmJudgeClient = &http.Client{Transport: keyEchoingTransport{}, CheckRedirect: saved.CheckRedirect}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	v, err := a.Approve(context.Background(), formsRequest(formsInjector{}))
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if v.Decision != "" || !strings.HasPrefix(v.Reason, "llm call: ") {
		t.Fatalf("verdict = %+v, want undecided llm call", v)
	}
	if l := formsLeak(v.Reason); l != "" || !strings.Contains(v.Reason, judgeRedactionMarker) {
		t.Fatalf("Approve reason leaks %q or has no marker: %q", l, v.Reason)
	}
	_, err = a.Summarize(context.Background(), formsRequest(formsInjector{}))
	if err == nil {
		t.Fatal("Summarize: want an error")
	}
	if l := formsLeak(err.Error()); l != "" || !strings.Contains(err.Error(), judgeRedactionMarker) {
		t.Fatalf("Summarize error leaks %q or has no marker: %q", l, err)
	}
}

// A successful summary goes to Slack, Signal, and external plugins, so
// every judge-written field is redacted and bounded.
func TestLLMSummarizeSuccessRedactsFields(t *testing.T) {
	for name, v := range judgeValueForms {
		t.Run(name, func(t *testing.T) {
			useJudgeReply(t, 200, anthropicText(t,
				`{"subject":"s `+v+`","label":"l `+v+`","confidence":5,"summary":"key `+v+`"}`))
			a := &LLMApprover{Model: "claude-test", Credential: "judge"}
			s, err := a.Summarize(context.Background(), formsRequest(formsInjector{}))
			if err != nil {
				t.Fatalf("Summarize: %v", err)
			}
			for field, got := range map[string]string{"subject": s.Subject, "label": s.Label, "summary": s.Summary} {
				if l := formsLeak(got); l != "" {
					t.Fatalf("%s leaks %s: %q", field, l, got)
				}
				if !strings.Contains(got, judgeRedactionMarker) {
					t.Fatalf("%s = %q, want the marker", field, got)
				}
			}
			if s.Confidence != 5 {
				t.Fatalf("Confidence = %d, want 5", s.Confidence)
			}
		})
	}
}

func TestLLMSummarizeSuccessBoundsFields(t *testing.T) {
	long := strings.Repeat("w", 2000)
	useJudgeReply(t, 200, anthropicText(t,
		`{"subject":"`+long+`","label":"`+long+`","summary":"`+long+`"}`))
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	s, err := a.Summarize(context.Background(), formsRequest(formsInjector{}))
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if len(s.Subject) > 210 || len(s.Label) > 210 || len(s.Summary) > 520 {
		t.Fatalf("field lengths = %d/%d/%d, want bounded", len(s.Subject), len(s.Label), len(s.Summary))
	}
}

// customHeaderCredential puts a derived token with no auth scheme in a
// custom header, as an OAuth-exchanging injector might. Only the
// header-diff redaction knows that value.
type customHeaderCredential struct{}

const customHeaderToken = "CUSTOMTOKEN0000111122223333"

func (customHeaderCredential) InjectHTTP(_ context.Context, req *http.Request, _ runtime.Secret) error {
	req.Header.Set("X-Api-Token", customHeaderToken)
	return nil
}

func TestLLMJudgeRedactsSchemelessHeaderToken(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{401, `{"error":"bad token ` + customHeaderToken + `"}`},
		{200, ""},
	} {
		body := tc.body
		if tc.status == 200 {
			body = anthropicText(t, "deny\ntoken "+customHeaderToken)
		}
		useJudgeReply(t, tc.status, body)
		v, err := (&LLMApprover{Model: "claude-test", Credential: "judge"}).Approve(context.Background(), formsRequest(customHeaderCredential{}))
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if strings.Contains(v.Reason, customHeaderToken) || !strings.Contains(v.Reason, judgeRedactionMarker) {
			t.Fatalf("status %d: Reason = %q, want the custom-header token redacted", tc.status, v.Reason)
		}
	}
}

type wordSecrets string

func (s wordSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(s)}, nil
}

// The verdict is read from the raw judge text. Redacting a value that
// contains "deny" or "allow" first would change the text the verdict
// is read from, and could turn an ambiguous deny into an allow.
func TestLLMJudgeVerdictIsParsedFromRawText(t *testing.T) {
	cases := []struct {
		secret, text, want string
	}{
		// Raw: has both words, so ambiguous: deny. Redacted, only
		// "allow" would remain.
		{"fake-deny-secret-0001", "Verdict: allow; key fake-deny-secret-0001", "deny"},
		{"fake-allow-secret-0002", "Verdict: deny; key fake-allow-secret-0002", "deny"},
		{"fake-allow-secret-0003", "deny\nkey fake-allow-secret-0003", "deny"},
		{"fake-deny-secret-0004", "allow\nkey fake-deny-secret-0004", "allow"},
	}
	for _, c := range cases {
		useJudgeReply(t, 200, anthropicText(t, c.text))
		req := runtime.ApproveRequest{
			Policy:  &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: nopHTTPCredential{}}}},
			Secrets: wordSecrets(c.secret),
		}
		v, err := (&LLMApprover{Model: "claude-test", Credential: "judge"}).Approve(context.Background(), req)
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
		if v.Decision != c.want {
			t.Fatalf("text %q: Decision = %q, want %q", c.text, v.Decision, c.want)
		}
		if strings.Contains(v.Reason, c.secret) {
			t.Fatalf("text %q: Reason leaks the secret: %q", c.text, v.Reason)
		}
	}
}
