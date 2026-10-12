package approvers

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// D4: a non-200 judge answer's body goes to the gateway log, never into
// the agent-facing verdict reason. cannedStatus answers "judge says no".
func TestLLMApproverWithholdsJudgeBody(t *testing.T) {
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	for _, status := range []int{401, 503} {
		var logged bytes.Buffer
		log.SetOutput(&logged)
		llmJudgeClient = &http.Client{Transport: cannedStatus(status)}
		v, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: okSecrets{}})
		if err != nil {
			t.Fatalf("status %d: Approve: %v", status, err)
		}
		if strings.Contains(v.Reason, "judge says no") {
			t.Errorf("status %d: verdict reason %q carries the judge body", status, v.Reason)
		}
		if !strings.Contains(logged.String(), "judge says no") {
			t.Errorf("status %d: judge body not logged server-side; log = %q", status, logged.String())
		}
	}
	// The logged body is capped at 1 KiB, so a huge judge answer cannot
	// flood the log.
	var logged bytes.Buffer
	log.SetOutput(&logged)
	llmJudgeClient = &http.Client{Transport: cannedBody{status: 401, body: strings.Repeat("x", 4096)}}
	if _, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: okSecrets{}}); err != nil {
		t.Fatalf("oversize: Approve: %v", err)
	}
	if n := strings.Count(logged.String(), "x"); n > 1024+16 {
		t.Errorf("logged %d body bytes, want at most 1024", n)
	}
}

// Round-2 S109: the logged judge body has the judge credential's own
// secret (Bytes and every Extras value) replaced, so moving the body
// from the deny reason to the log does not put the credential in logs.
func TestLLMApproverRedactsSecretInLoggedJudgeBody(t *testing.T) {
	const secret = "judge-secret-0123456789abcdef"
	const extra = "judge-refresh-0123456789abcdef"
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	llmJudgeClient = &http.Client{Transport: cannedBody{status: 401, body: "bad key " + secret + " / " + extra}}
	sec := fixedSecret{Bytes: []byte(secret), Extras: map[string]string{"refresh_token": extra}}
	if _, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: sec}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if strings.Contains(logged.String(), secret) || strings.Contains(logged.String(), extra) {
		t.Fatalf("judge credential reached the gateway log: %q", logged.String())
	}
	if !strings.Contains(logged.String(), "clawpatrol-redacted-secret") {
		t.Fatalf("log = %q, want the redaction marker in place of the secret", logged.String())
	}
}

// cannedBody answers every request with status and body.
type cannedBody struct {
	status int
	body   string
}

func (c cannedBody) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body)), Header: http.Header{}, Request: req}, nil
}

// fixedSecret returns itself for every credential name.
type fixedSecret runtime.Secret

func (f fixedSecret) Get(string) (runtime.Secret, error) { return runtime.Secret(f), nil }

// echoHeaders answers 401 with every request header value in the body,
// like a judge that echoes the credential it rejected.
type echoHeaders struct{}

func (echoHeaders) RoundTrip(r *http.Request) (*http.Response, error) {
	var b strings.Builder
	for k, vs := range r.Header {
		b.WriteString(k + "=" + strings.Join(vs, ",") + "\n")
	}
	return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(b.String())), Request: r}, nil
}

// basicJudgeCred injects HTTP Basic auth, as the built-in basic_auth
// credential does: the wire value is base64(user:secret).
type basicJudgeCred struct{}

func (basicJudgeCred) InjectHTTP(_ context.Context, r *http.Request, s runtime.Secret) error {
	r.SetBasicAuth("judgeuser", string(s.Bytes))
	return nil
}

// derivingJudgeCred injects a value derived from the secret and reports
// it for redaction (HTTPCredentialRedactionProvider), as the extplugin
// adapter does.
type derivingJudgeCred struct{}

func (derivingJudgeCred) InjectHTTP(_ context.Context, r *http.Request, s runtime.Secret) error {
	r.Header.Set("X-Judge-Token", "derived-"+string(s.Bytes)+"-v2")
	return nil
}

func (derivingJudgeCred) ConsumeHTTPRedactions(r *http.Request) []string {
	return []string{r.Header.Get("X-Judge-Token")}
}

// echoBareToken answers 401 echoing only the token after the
// Authorization scheme, as a judge that reports "invalid token <t>" does.
type echoBareToken struct{}

func (echoBareToken) RoundTrip(r *http.Request) (*http.Response, error) {
	_, tok, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	return &http.Response{StatusCode: 401, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("invalid token " + tok)), Request: r}, nil
}

func TestLLMApproverRedactsDerivedJudgeCredential(t *testing.T) {
	const secret = "judge-secret-0123456789abcdef"
	basic := base64.StdEncoding.EncodeToString([]byte("judgeuser:" + secret))
	for _, tc := range []struct {
		name   string
		cred   runtime.HTTPCredentialRuntime
		judge  http.RoundTripper
		leaked string
	}{
		{"basic_auth", basicJudgeCred{}, echoHeaders{}, basic},
		{"redaction provider", derivingJudgeCred{}, echoHeaders{}, "derived-" + secret + "-v2"},
		{"basic_auth bare token", basicJudgeCred{}, echoBareToken{}, basic},
	} {
		policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: tc.cred}}}
		a := &LLMApprover{Model: "claude-test", Credential: "judge"}
		saved, savedOut := llmJudgeClient, log.Writer()
		var logged bytes.Buffer
		log.SetOutput(&logged)
		llmJudgeClient = &http.Client{Transport: tc.judge}
		_, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: fixedSecret{Bytes: []byte(secret)}})
		llmJudgeClient = saved
		log.SetOutput(savedOut)
		if err != nil {
			t.Fatalf("%s: Approve: %v", tc.name, err)
		}
		if strings.Contains(logged.String(), tc.leaked) || strings.Contains(logged.String(), secret) {
			t.Errorf("%s: derived judge credential reached the gateway log: %q", tc.name, logged.String())
		}
		if !strings.Contains(logged.String(), "clawpatrol-redacted-secret") {
			t.Errorf("%s: log = %q, want the redaction marker", tc.name, logged.String())
		}
	}
}

// Fix round 2 (I-1): the log cap never emits an unscanned tail. Sweeps
// secret placement around byte 1024, back-to-back repeats (redaction
// shrinks the buffer) and a body far past the read bound.
func TestLLMApproverNeverLogsSecretPrefixAtLogCap(t *testing.T) {
	gen := func(n int) string {
		const cyc = "0123456789abcdefghijklmnopqrstuvwxyz"
		var b strings.Builder
		b.WriteString("SK-")
		for b.Len() < n {
			b.WriteByte(cyc[b.Len()%len(cyc)])
		}
		return b.String()[:n]
	}
	type tc struct {
		name         string
		secret, body string
		inRange      bool
	}
	var cases []tc
	for _, n := range []int{8, 34, 120} {
		sec := gen(n)
		for off := 960; off <= 1040; off++ {
			cases = append(cases, tc{fmt.Sprintf("len%d@%d", n, off), sec, strings.Repeat("y", off) + sec + strings.Repeat("z", 200), off+26 <= 1024})
		}
		cases = append(cases,
			tc{fmt.Sprintf("len%d repeated", n), sec, strings.Repeat(sec, 40), true},
			tc{fmt.Sprintf("len%d at0 then repeated at 1030", n), sec, sec + strings.Repeat("y", 1030-n) + strings.Repeat(sec, 10), true},
			tc{fmt.Sprintf("len%d >10KiB", n), sec, strings.Repeat(sec, 11000/n+1), true},
		)
	}
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: nopHTTPCredential{}}}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	for _, c := range cases {
		var logged bytes.Buffer
		log.SetOutput(&logged)
		llmJudgeClient = &http.Client{Transport: cannedBody{status: 401, body: c.body}}
		if _, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: fixedSecret{Bytes: []byte(c.secret)}}); err != nil {
			t.Fatalf("%s: Approve: %v", c.name, err)
		}
		for k := 0; k+8 <= len(c.secret); k++ {
			if w := c.secret[k : k+8]; strings.Contains(logged.String(), w) {
				t.Errorf("%s: secret bytes %q reached the log", c.name, w)
				break
			}
		}
		if c.inRange && !strings.Contains(logged.String(), "clawpatrol-redacted-secret") {
			t.Errorf("%s: log lacks the redaction marker", c.name)
		}
	}
}

// Fix round 1 (I-2): Summarize's error never carries the judge body; the
// body is logged once, redacted.
func TestLLMSummarizeWithholdsAndRedactsJudgeBody(t *testing.T) {
	const secret = "judge-secret-0123456789abcdef"
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	llmJudgeClient = &http.Client{Transport: cannedBody{status: 400, body: "bad key " + secret}}
	sec := fixedSecret{Bytes: []byte(secret)}
	_, err := a.Summarize(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: sec})
	if err == nil {
		t.Fatal("Summarize: want error")
	}
	// human.go logs err.Error(); check it and the judge log together.
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "bad key") {
		t.Fatalf("Summarize error carries the judge body: %q", err)
	}
	if strings.Contains(logged.String(), secret) {
		t.Fatalf("secret reached the log: %q", logged.String())
	}
	if !strings.Contains(logged.String(), "clawpatrol-redacted-secret") {
		t.Fatalf("log = %q, want the redaction marker", logged.String())
	}
}

// Fix round 2: Summarize redacts derived values too (basic_auth sends
// base64(user:secret), which holds no raw secret bytes).
func TestLLMSummarizeRedactsDerivedJudgeCredential(t *testing.T) {
	const secret = "judge-secret-0123456789abcdef"
	basic := base64.StdEncoding.EncodeToString([]byte("judgeuser:" + secret))
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: basicJudgeCred{}}}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	llmJudgeClient = &http.Client{Transport: cannedBody{status: 400, body: "bad " + basic}}
	_, err := a.Summarize(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: fixedSecret{Bytes: []byte(secret)}})
	if err == nil {
		t.Fatal("Summarize: want error")
	}
	if strings.Contains(err.Error()+logged.String(), basic) {
		t.Fatalf("derived credential leaked: err=%q log=%q", err, logged.String())
	}
	if !strings.Contains(logged.String(), "clawpatrol-redacted-secret") {
		t.Fatalf("log = %q, want the redaction marker", logged.String())
	}
}

// Fix round 3: several redaction values at once, with the tail of the
// bounded read inside a partly read value. Early copies of the long
// value shrink the redacted buffer (the marker is shorter), so an
// undropped tail would slide back under the 1 KiB cap. Pins that
// unscannedTail takes the longest suffix and looks at every value, not
// just the first.
func TestLLMApproverNeverLogsPartialValueTailWithManyValues(t *testing.T) {
	const marker = "clawpatrol-redacted-secret"
	gen := func(prefix string, n int) string {
		const cyc = "0123456789abcdefghijklmnopqrstuvwxyz"
		s := prefix
		for len(s) < n {
			s += string(cyc[len(s)%len(cyc)])
		}
		return s[:n]
	}
	periodic := strings.Repeat("q", 40) + "-tail-0123456789"
	cases := []struct {
		name string
		a    string // sec.Bytes
		b    string // sec.Extras
	}{
		{"shared prefix 120/34", gen("SK-abc", 120), gen("SK-abd", 34)},
		{"shared prefix 34/120", gen("SK-abc", 34), gen("SK-abd", 120)},
		{"periodic shorter", gen("LONG-", 120), periodic},
		{"periodic longer", periodic + gen("-x", 80), gen("SHORT-", 34)},
		{"marker-prefixed redacted-secret-", gen("redacted-secret-", 120), gen("SK-abd", 34)},
		{"marker-prefixed secret-", gen("secret-", 34), gen("SK-abc", 120)},
		{"marker-prefixed periodic", gen("redacted-secret-", 34), periodic},
	}
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: nopHTTPCredential{}}}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	saved, savedOut := llmJudgeClient, log.Writer()
	defer func() { llmJudgeClient = saved; log.SetOutput(savedOut) }()
	for _, c := range cases {
		long, short := c.a, c.b
		if len(short) > len(long) {
			long, short = short, long
		}
		bound := 1024 + len(long)
		head := long + short + long + short
		for _, tail := range []string{c.a, c.b} {
			for k := 1; k < len(tail); k++ {
				pad := bound - k - len(head)
				if pad < 0 {
					continue
				}
				body := head + strings.Repeat("y", pad) + tail + strings.Repeat("z", 300)
				var logged bytes.Buffer
				log.SetOutput(&logged)
				llmJudgeClient = &http.Client{Transport: cannedBody{status: 401, body: body}}
				sec := fixedSecret{Bytes: []byte(c.a), Extras: map[string]string{"e": c.b}}
				if _, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: sec}); err != nil {
					t.Fatalf("%s: Approve: %v", c.name, err)
				}
				out := logged.String()
				if !strings.Contains(out, marker) {
					t.Errorf("%s k=%d: log lacks the redaction marker", c.name, k)
				}
				for _, v := range []string{c.a, c.b} {
					for w := 0; w+8 <= len(v); w++ {
						win := v[w : w+8]
						if strings.Contains(marker, win) {
							continue
						}
						if strings.Contains(out, win) {
							t.Errorf("%s k=%d: secret bytes %q reached the log", c.name, k, win)
							break
						}
					}
				}
			}
		}
	}
}
