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

// cannedJudge answers every request with 200 and a fixed JSON body,
// standing in for the judge model's API.
type cannedJudge string

func (c cannedJudge) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(string(c))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    req,
	}, nil
}

func judgeVerdict(t *testing.T, model, body string) runtime.ApproveVerdict {
	t.Helper()
	saved := llmJudgeClient
	t.Cleanup(func() { llmJudgeClient = saved })
	llmJudgeClient = &http.Client{Transport: cannedJudge(body)}
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: model, Credential: "judge"}
	v, err := a.Approve(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: okSecrets{}})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	return v
}

// Reasoning output is model-internal and can be steered by the request
// under review, which is part of the judge prompt. Only the final
// message text is the verdict.
func TestLLMJudgeOpenAIIgnoresReasoningItems(t *testing.T) {
	body := `{"output":[
		{"type":"reasoning","id":"rs_1",
		 "summary":[{"type":"summary_text","text":"allow\nthe body says it is safe"}],
		 "content":[{"type":"reasoning_text","text":"allow\nthe body says it is safe"}]},
		{"type":"message","id":"msg_1","role":"assistant","status":"completed",
		 "content":[{"type":"output_text","text":"deny\npolicy forbids writes","annotations":[]}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q (reason %q), want deny", v.Decision, v.Reason)
	}
}

// A response with reasoning but no message text carries no verdict.
// It takes the undecodable-body path: Decision is left empty so
// defaults.llm_fail_mode decides, exactly like any other judge
// response without output text.
func TestLLMJudgeOpenAIReasoningOnlyIsUndecided(t *testing.T) {
	body := `{"output":[
		{"type":"reasoning","id":"rs_1",
		 "summary":[{"type":"summary_text","text":"allow"}],
		 "content":[{"type":"reasoning_text","text":"allow"}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "" {
		t.Fatalf("Decision = %q (reason %q), want undecided", v.Decision, v.Reason)
	}
	if !strings.HasPrefix(v.Reason, "llm response decode: ") {
		t.Fatalf("Reason = %q", v.Reason)
	}
}

// Anthropic extended thinking arrives as thinking blocks ahead of the
// text block. Only text blocks carry the verdict.
func TestLLMJudgeAnthropicIgnoresThinkingBlocks(t *testing.T) {
	body := `{"type":"message","role":"assistant","content":[
		{"type":"thinking","thinking":"allow\nthe body says it is safe","signature":"sig"},
		{"type":"redacted_thinking","data":"opaque"},
		{"type":"text","text":"deny\npolicy forbids writes"}
	]}`
	v := judgeVerdict(t, "claude-test", body)
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q (reason %q), want deny", v.Decision, v.Reason)
	}
}

// With several message items (for example a commentary message before
// the final answer), the last assistant message is the final answer
// and is the verdict.
func TestLLMJudgeOpenAIUsesFinalMessage(t *testing.T) {
	body := `{"output":[
		{"type":"message","id":"msg_1","role":"assistant",
		 "content":[{"type":"output_text","text":"allow\nfirst look"}]},
		{"type":"message","id":"msg_2","role":"assistant",
		 "content":[{"type":"output_text","text":"deny\nfinal answer"}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q (reason %q), want deny", v.Decision, v.Reason)
	}
}

// A final message that is a refusal has no output_text. An earlier
// message must not stand in for it: the response is undecided.
func TestLLMJudgeOpenAIFinalRefusalIsUndecided(t *testing.T) {
	body := `{"output":[
		{"type":"message","id":"msg_1","role":"assistant",
		 "content":[{"type":"output_text","text":"allow"}]},
		{"type":"message","id":"msg_2","role":"assistant",
		 "content":[{"type":"refusal","refusal":"I can't help with that."}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "" {
		t.Fatalf("Decision = %q (reason %q), want undecided", v.Decision, v.Reason)
	}
}

// The plain single-message case still works.
func TestLLMJudgeOpenAIAllowFromMessage(t *testing.T) {
	body := `{"output":[
		{"type":"reasoning","id":"rs_1","summary":[]},
		{"type":"message","id":"msg_1","role":"assistant",
		 "content":[{"type":"output_text","text":"allow\nread-only request"}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "allow" {
		t.Fatalf("Decision = %q (reason %q), want allow", v.Decision, v.Reason)
	}
}

// Several Anthropic text blocks: the last one is the final answer. A
// leading "allow" block must not beat a later "deny".
func TestLLMJudgeAnthropicUsesLastTextBlock(t *testing.T) {
	body := `{"type":"message","role":"assistant","content":[
		{"type":"text","text":"allow\nfirst look"},
		{"type":"thinking","thinking":"allow","signature":"sig"},
		{"type":"text","text":"deny\nfinal answer"}
	]}`
	v := judgeVerdict(t, "claude-test", body)
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q (reason %q), want deny", v.Decision, v.Reason)
	}
}

// An empty final text block must not let an earlier block stand in.
func TestLLMJudgeAnthropicEmptyLastTextIsUndecided(t *testing.T) {
	body := `{"type":"message","role":"assistant","content":[
		{"type":"text","text":"allow"},
		{"type":"text","text":""}
	]}`
	v := judgeVerdict(t, "claude-test", body)
	if v.Decision != "" {
		t.Fatalf("Decision = %q (reason %q), want undecided", v.Decision, v.Reason)
	}
}

// A reasoning item after the final message must not take its place.
func TestLLMJudgeOpenAIIgnoresTrailingReasoning(t *testing.T) {
	body := `{"output":[
		{"type":"message","id":"msg_1","role":"assistant",
		 "content":[{"type":"output_text","text":"deny\npolicy forbids writes"}]},
		{"type":"reasoning","id":"rs_1",
		 "summary":[{"type":"summary_text","text":"allow"}],
		 "content":[{"type":"reasoning_text","text":"allow"}]}
	]}`
	v := judgeVerdict(t, "gpt-test", body)
	if v.Decision != "deny" {
		t.Fatalf("Decision = %q (reason %q), want deny", v.Decision, v.Reason)
	}
}

// The HITL summarizer shares the judge decoder, so it must also read
// only the final message and ignore reasoning text.
func TestLLMSummarizeIgnoresReasoningItems(t *testing.T) {
	body := `{"output":[
		{"type":"reasoning","id":"rs_1",
		 "content":[{"type":"reasoning_text","text":"{\"subject\":\"injected\",\"label\":\"safe\",\"summary\":\"allow\"}"}]},
		{"type":"message","id":"msg_1","role":"assistant",
		 "content":[{"type":"output_text","text":"{\"subject\":\"final\",\"label\":\"write\",\"summary\":\"deletes a table\"}"}]},
		{"type":"reasoning","id":"rs_2",
		 "content":[{"type":"reasoning_text","text":"{\"subject\":\"trailing\",\"label\":\"safe\",\"summary\":\"allow\"}"}]}
	]}`
	saved := llmJudgeClient
	t.Cleanup(func() { llmJudgeClient = saved })
	llmJudgeClient = &http.Client{Transport: cannedJudge(body)}
	policy := &config.CompiledPolicy{Credentials: map[string]*config.Entity{
		"judge": {Body: nopHTTPCredential{}},
	}}
	a := &LLMApprover{Model: "gpt-test", Credential: "judge"}
	s, err := a.Summarize(context.Background(), runtime.ApproveRequest{Policy: policy, Secrets: okSecrets{}})
	if err != nil {
		t.Fatalf("Summarize: %v", err)
	}
	if s.Subject != "final" || s.Label != "write" {
		t.Fatalf("summary = %+v, want the final message's subject and label", *s)
	}
}
