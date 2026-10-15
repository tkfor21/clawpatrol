package approvers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Fake secrets only. Each stands for one kind of value the judge call
// carries: the raw secret, an Extras value, a token the injector put in
// a header that is not the raw secret, and a value the injector
// reported for redaction.
const (
	redactTestSecret   = "fake-judge-secret-a1b2c3d4"
	redactTestExtra    = "fake-extra-value-1234abcd"
	redactTestDerived  = "fake-derived-bearer-e5f6a7b8"
	redactTestReported = "fake-reported-value-c9d0e1f2"
)

var redactTestValues = []string{redactTestSecret, redactTestExtra, redactTestDerived, redactTestReported}

// derivingJudgeCredential sends a header token derived from the secret
// (as basic_auth or an OAuth exchange would) and reports one more value
// for redaction.
type derivingJudgeCredential struct{}

func (derivingJudgeCredential) InjectHTTP(_ context.Context, req *http.Request, _ runtime.Secret) error {
	req.Header.Set("Authorization", "Bearer "+redactTestDerived)
	return nil
}

func (derivingJudgeCredential) ConsumeHTTPRedactions(*http.Request) []string {
	return []string{redactTestReported}
}

type redactTestSecrets struct{}

func (redactTestSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(redactTestSecret), Extras: map[string]string{"extra": redactTestExtra}}, nil
}

func redactTestPolicy() *config.CompiledPolicy {
	return &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: derivingJudgeCredential{}},
	}}
}

// cannedReply answers every request with the given status and body.
type cannedReply struct {
	status int
	body   string
}

func (c cannedReply) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: c.status,
		Body:       io.NopCloser(strings.NewReader(c.body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

func anthropicText(t *testing.T, text string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func useJudgeReply(t *testing.T, status int, body string) {
	t.Helper()
	saved := llmJudgeClient
	t.Cleanup(func() { llmJudgeClient = saved })
	llmJudgeClient = &http.Client{Transport: cannedReply{status: status, body: body}}
}

func assertNoJudgeSecret(t *testing.T, where, got string) {
	t.Helper()
	for _, v := range redactTestValues {
		// A prefix catches a value cut by truncation before redaction.
		if strings.Contains(got, v[:12]) {
			t.Fatalf("%s carries (a prefix of) %q: %q", where, v, got)
		}
	}
}

// captureJudgeLog sends the standard logger to a buffer for the test.
func captureJudgeLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	savedOut, savedFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(savedOut); log.SetFlags(savedFlags) })
	return &logs
}

// judgeWithheld is what a non-200 judge reply leaves in the verdict
// reason or error (D4): the body itself goes only to the gateway log.
const judgeWithheld = "judge response withheld (see the gateway log)"

const leakedValues = redactTestSecret + " " + redactTestExtra + " " + redactTestDerived + " " + redactTestReported

// A judge reply that repeats a value from the judge call must not carry
// it into the verdict Reason, which the gateway writes to the agent's
// 403 body, the server log, and the dashboard event. A non-200 body is
// withheld from the Reason entirely (D4) and logged redacted, so for
// those the redaction checks run against the log line.
func TestLLMJudgeReasonRedactsJudgeCallValues(t *testing.T) {
	errBody := `{"error":"bad key ` + leakedValues + `"}`
	// Boundary cases put a value across the length cap, so the raw
	// text cut at the cap would end in a prefix of it. The marker may
	// itself be cut there, so only the absence of the value is checked.
	cases := []struct {
		name     string
		status   int
		body     string
		decision string
		marker   bool
	}{
		{"deny reason line", 200, anthropicText(t, "deny\nthe key is "+leakedValues), "deny", true},
		{"allow reason line", 200, anthropicText(t, "allow\nthe key is "+leakedValues), "allow", true},
		{"verdict word inside prose", 200, anthropicText(t, "Verdict: deny, it sent "+leakedValues), "deny", true},
		{"ambiguous reply", 200, anthropicText(t, "unsure about "+leakedValues), "deny", true},
		{"secret across the ambiguity cap", 200, anthropicText(t, "unsure "+strings.Repeat("x", 180)+" "+redactTestSecret), "deny", false},
		{"secret across the reason cap", 200, anthropicText(t, "deny\n"+strings.Repeat("y", 495)+" "+redactTestSecret), "deny", false},
		{"4xx body", 401, errBody, "deny", true},
		{"5xx body", 503, errBody, "", true},
		{"secret across the error body cap", 401, strings.Repeat("z", 1010) + redactTestSecret, "deny", false},
		// The error body is read to 1024 plus the longest value (35,
		// "Bearer " plus the derived token), so 1059 bytes. The secret
		// starts at 1045 and only 14 bytes of it are read. Twenty
		// earlier values each shrink by 2 when redacted, which slides
		// that raw prefix back under the 1024 cap unless it is dropped.
		{"secret cut at the read bound after redaction shrinks", 401,
			strings.Repeat(redactTestDerived+" ", 20) + strings.Repeat("z", 465) + redactTestSecret + strings.Repeat("z", 100),
			"deny", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureJudgeLog(t)
			useJudgeReply(t, tc.status, tc.body)
			a := &LLMApprover{Model: "claude-test", Credential: "judge"}
			v, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: redactTestPolicy(), Secrets: redactTestSecrets{}})
			if err != nil {
				t.Fatalf("Approve: %v", err)
			}
			if v.Decision != tc.decision {
				t.Fatalf("Decision = %q, want %q", v.Decision, tc.decision)
			}
			assertNoJudgeSecret(t, "Reason", v.Reason)
			if len(v.Reason) > 1100 {
				t.Fatalf("Reason is %d bytes, want it bounded", len(v.Reason))
			}
			where, got := "Reason", v.Reason
			if tc.status != 200 {
				if !strings.Contains(v.Reason, judgeWithheld) {
					t.Fatalf("Reason = %q, want the judge body withheld", v.Reason)
				}
				where, got = "log", logs.String()
				assertNoJudgeSecret(t, where, got)
			}
			if tc.marker && !strings.Contains(got, judgeRedactionMarker) {
				t.Fatalf("%s = %q, want the redaction marker in place of the value", where, got)
			}
			// At a cap the value is still redacted whole, so at least
			// the start of the marker survives the cut.
			if !strings.Contains(got, judgeRedactionMarker[:8]) {
				t.Fatalf("%s = %q, want (the start of) the redaction marker", where, got)
			}
		})
	}
}

// A clean reason passes through unchanged.
func TestLLMJudgeReasonKeepsCleanText(t *testing.T) {
	useJudgeReply(t, 200, anthropicText(t, "deny\nwrites to a production table"))
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	v, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: redactTestPolicy(), Secrets: redactTestSecrets{}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if v.Decision != "deny" || v.Reason != "writes to a production table" {
		t.Fatalf("verdict = %+v", v)
	}
}

// The classifier's error, which human_approver logs, must not carry
// judge-call values from an unparsable or rejected reply.
func TestLLMSummarizeErrorRedactsJudgeCallValues(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"unparsable 200", 200, ""},
		{"4xx body", 401, `{"error":"bad key ` + leakedValues + `"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			if tc.status == 200 {
				body = anthropicText(t, "not json: "+leakedValues)
			}
			logs := captureJudgeLog(t)
			useJudgeReply(t, tc.status, body)
			a := &LLMApprover{Model: "claude-test", Credential: "judge"}
			s, err := a.Summarize(context.Background(), runtime.ApproveRequest{Policy: redactTestPolicy(), Secrets: redactTestSecrets{}})
			if err == nil {
				t.Fatalf("Summarize = %+v, want an error", s)
			}
			assertNoJudgeSecret(t, "error", err.Error())
			where, got := "error", err.Error()
			if tc.status != 200 {
				if !strings.Contains(got, judgeWithheld) {
					t.Fatalf("error = %q, want the judge body withheld", got)
				}
				where, got = "log", logs.String()
				assertNoJudgeSecret(t, where, got)
			}
			if !strings.Contains(got, judgeRedactionMarker) {
				t.Fatalf("%s = %q, want the redaction marker in place of the value", where, got)
			}
		})
	}
}

// End to end through human_approver: the classifier failure it logs
// carries no raw judge-call value.
func TestHumanApproverClassifierLogRedactsJudgeOutput(t *testing.T) {
	useJudgeReply(t, 200, anthropicText(t, "not json: "+leakedValues))
	var logs bytes.Buffer
	savedOut, savedFlags := log.Writer(), log.Flags()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(savedOut); log.SetFlags(savedFlags) })

	policy := redactTestPolicy()
	policy.Approvers = map[string]*config.Entity{
		"clf": {Body: &LLMApprover{Model: "claude-test", Credential: "judge"}},
	}
	pool := newCaptureHITLPool()
	pool.decision <- runtime.HITLDecision{Allow: false, Reason: "operator said no", By: "test"}
	done := make(chan error, 1)
	go func() {
		_, err := (&HumanApprover{Classifier: "clf", Timeout: 5}).Approve(context.Background(), runtime.ApproveRequest{
			Pool:         pool,
			ApproverName: "ops",
			Policy:       policy,
			Secrets:      redactTestSecrets{},
		})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Approve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("human approver did not return")
	}
	got := logs.String()
	if !strings.Contains(got, "classifier") {
		t.Fatalf("log = %q, want the classifier failure line", got)
	}
	assertNoJudgeSecret(t, "log", got)
	if !strings.Contains(got, judgeRedactionMarker) {
		t.Fatalf("log = %q, want the redaction marker", got)
	}
}

// numericSecrets holds a fake all-digit secret.
type numericSecrets struct{}

const redactTestNumeric = "4111111111111111"

func (numericSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(redactTestNumeric)}, nil
}

// The decode and classifier-parse errors pass encoding/json's error
// through unredacted. That is safe only while those errors name the
// JSON type and path but never quote a literal from the judge body;
// older encoding/json quoted number literals. This pins it.
func TestLLMJudgeDecodeErrorsRedactJudgeCallValues(t *testing.T) {
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	req := runtime.ApproveRequest{Policy: policy, Secrets: numericSecrets{}}

	useJudgeReply(t, 200, `{"content":[{"type":"text","text":`+redactTestNumeric+`}]}`)
	v, err := a.Approve(context.Background(), req)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if v.Decision != "" || strings.Contains(v.Reason, redactTestNumeric) {
		t.Fatalf("Approve decode verdict = %+v, want undecided without the value", v)
	}
	_, err = a.Summarize(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), redactTestNumeric) {
		t.Fatalf("Summarize decode error = %v, want no raw value", err)
	}

	useJudgeReply(t, 200, anthropicText(t, `{"subject":`+redactTestNumeric+`}`))
	_, err = a.Summarize(context.Background(), req)
	if err == nil || strings.Contains(err.Error(), redactTestNumeric) {
		t.Fatalf("Summarize parse error = %v, want no raw value", err)
	}
}
