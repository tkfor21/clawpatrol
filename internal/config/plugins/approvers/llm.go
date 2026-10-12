package approvers

// llm_approver: an LLM proctor that judges a request against the
// operator's policy text. Anthropic (api.anthropic.com) and OpenAI /
// codex (api.openai.com) wire through their bound credential's
// HTTPCredentialRuntime — same auth path the agent dispatcher uses
// for end-user requests, so OAuth refresh / per-profile rotation
// come for free.
//
// Model dispatch is name-prefixed: `claude-…` → Anthropic Messages
// API, `gpt-…` / `o*-…` → OpenAI Responses API.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const llmJudgeSystem = `You are a security gate. Decide whether the operator's policy intends the gateway to ALLOW or DENY this request. The policy text is the source of truth.

Reply with EXACTLY one word on the first line: "allow" or "deny" (lowercase, no punctuation).
Then a brief one-line reason on the second line.

Be conservative — when the policy is ambiguous about whether the request is permitted, deny.`

const llmClassifierSystem = `You are a request classifier. Analyze the request against the policy and return JSON request context.

Reply with JSON only — no markdown fences, no other text:
{"subject":"<short request subject or resource identifier, or empty string>","label":"<short label per policy>","confidence":<0-100>,"summary":"<one sentence>"}

Use generic request details only. Do not assume a domain-specific object type unless the policy says so.`

// judgeRedactionMarker replaces every judge-call value found in judge
// output before that output reaches a verdict reason, an error, or a
// log line.
const judgeRedactionMarker = "clawpatrol-redacted-secret"

// LLMApprover carries the model + the credential used to authenticate
// the call to the model API + the inline policy text the model judges
// against. `policy` is a heredoc-friendly string attribute on the
// approver block itself — no separate `policy "<name>" {}` block.
type LLMApprover struct {
	// Model is the model id used for policy judgment, such as a
	// claude-*, gpt-*, or o*-prefixed model.
	Model string `hcl:"model"`
	// Credential references the HTTP credential used to authenticate
	// the model API call.
	Credential string `hcl:"credential"`
	// Policy is the prose the model judges requests against. Typically
	// a heredoc on the approver block.
	Policy string `hcl:"policy,optional"`
}

// Approve is part of the clawpatrol plugin API.
func (a *LLMApprover) Approve(ctx context.Context, req runtime.ApproveRequest) (runtime.ApproveVerdict, error) {
	if a.Model == "" {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm approver has no model"}, nil
	}
	if a.Credential == "" {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "llm approver has no credential"}, nil
	}
	if req.Policy == nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "no policy on request"}, nil
	}
	if _, ok := req.Policy.Credentials[a.Credential]; !ok {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential " + a.Credential + " not declared"}, nil
	}

	user := buildJudgePrompt(req, a.Policy)

	var (
		hreq   *http.Request
		decode func(io.Reader) (string, error)
	)
	switch {
	case strings.HasPrefix(a.Model, "claude-"):
		hreq, decode = anthropicJudgeRequest(ctx, a.Model, llmJudgeSystem, user)
	case strings.HasPrefix(a.Model, "gpt-"), strings.HasPrefix(a.Model, "o"):
		hreq, decode = openaiJudgeRequest(ctx, a.Model, llmJudgeSystem, user)
	default:
		return runtime.ApproveVerdict{Decision: "deny", Reason: "unknown model family: " + a.Model}, nil
	}

	credEnt := req.Policy.Credentials[a.Credential]
	injector, ok := credEnt.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential " + a.Credential + " does not satisfy HTTPCredentialRuntime"}, nil
	}
	sec, err := req.Secrets.Get(a.Credential)
	if err != nil {
		return runtime.ApproveVerdict{Decision: "deny", Reason: "secret fetch: " + err.Error()}, nil
	}
	before := hreq.Header.Clone()
	if err := injector.InjectHTTP(ctx, hreq, sec); err != nil {
		discardHTTPRedactions(injector, hreq)
		return runtime.ApproveVerdict{Decision: "deny", Reason: "credential inject: " + err.Error()}, nil
	}
	redactions := judgeRedactions(before, hreq.Header, consumeHTTPRedactions(injector, hreq), sec)
	resp, err := llmJudgeClient.Do(hreq)
	if err != nil {
		return llmUndecided("llm call: " + err.Error()), nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body := readJudgeErrorBody(resp.Body, redactions)
		reason := fmt.Sprintf("llm http %d: %s", resp.StatusCode, string(body))
		if llmStatusIsOutage(resp.StatusCode) {
			return llmUndecided(reason), nil
		}
		// 4xx other than 429 is the judge rejecting our request: a
		// revoked key, a bad model name, a malformed body. That is a
		// persistent condition, not an outage, and must not be allowed
		// through by llm_fail_mode = "open".
		return runtime.ApproveVerdict{Decision: "deny", Reason: reason}, nil
	}
	text, err := decode(resp.Body)
	if err != nil {
		return llmUndecided("llm response decode: " + err.Error()), nil
	}
	// The verdict is read from the raw text; only the reason is
	// redacted, so a replaced value cannot change the decision.
	verdict, reason := parseJudgeVerdict(text)
	reason = redactJudgeText(reason, redactions, judgeReasonLimit)
	by := "llm:" + a.Model
	return runtime.ApproveVerdict{Decision: verdict, Reason: reason, By: by}, nil
}

// llmUndecided is the verdict for a model call that could not
// complete because the judge is unavailable: transport error or
// timeout, 429 or 5xx status, or an undecodable body. Decision is
// left empty so the approve chain applies defaults.llm_fail_mode
// ("closed" denies, "open" allows). Everything that points at the
// gateway's own configuration rather than an outage always denies:
// no model, credential not declared, unknown model family, a
// credential whose secret cannot be fetched or injected, and any
// other 4xx (revoked key, unknown model, malformed request).
// llmJudgeClient issues the judge and summarizer requests. A variable
// so tests can swap the transport for a canned judge.
var llmJudgeClient = &http.Client{Timeout: 30 * time.Second}

func llmUndecided(reason string) runtime.ApproveVerdict {
	return runtime.ApproveVerdict{Decision: "", Reason: reason}
}

// llmStatusIsOutage reports whether a non-200 status from the judge
// means the judge is unavailable (retry later) rather than that it
// rejected the request.
func llmStatusIsOutage(status int) bool {
	return status == 429 || status >= 500
}

func discardHTTPRedactions(injector runtime.HTTPCredentialRuntime, req *http.Request) {
	if rp, ok := injector.(runtime.HTTPCredentialRedactionProvider); ok {
		_ = rp.ConsumeHTTPRedactions(req)
	}
}

// consumeHTTPRedactions returns the values an injector reports for
// redaction, or nil. It must run after every successful InjectHTTP.
func consumeHTTPRedactions(injector runtime.HTTPCredentialRuntime, req *http.Request) []string {
	if rp, ok := injector.(runtime.HTTPCredentialRedactionProvider); ok {
		return rp.ConsumeHTTPRedactions(req)
	}
	return nil
}

// judgeReasonLimit bounds the judge's free text in a verdict reason.
// The reason reaches the agent's deny response, the gateway log, and
// the dashboard event.
const judgeReasonLimit = 512

// judgeRedactions lists every value the judge call carried that must
// not come back out of judge output: the credential's secret, its
// Extras values of 8 bytes or more, every value the injector reported,
// and every header value the injector added or changed, plus the token
// after a "Basic " or "Bearer " scheme (basic_auth sends
// base64(user:secret), which contains no raw secret bytes). Longest
// first, so a value that contains another is replaced whole.
//
// The judge prompt is built from the agent's request before the
// gateway injects the agent's real credential, so the judge never sees
// that credential; the judge-call credential is the only gateway secret
// on this call.
func judgeRedactions(before, after http.Header, reported []string, sec runtime.Secret) []string {
	var out []string
	if len(sec.Bytes) > 0 {
		out = append(out, string(sec.Bytes))
	}
	add := func(v string) {
		if len(v) >= 8 {
			out = append(out, v)
		}
	}
	for _, v := range sec.Extras {
		add(v)
	}
	for _, v := range reported {
		add(v)
	}
	for k, vs := range after {
		for _, v := range vs {
			if slices.Contains(before[k], v) {
				continue
			}
			add(v)
			for _, scheme := range []string{"Basic ", "Bearer "} {
				if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) {
					add(v[len(scheme):])
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// redactJudgeValues replaces every value in body with the marker.
func redactJudgeValues(body []byte, values []string) []byte {
	for _, v := range values {
		body = bytes.ReplaceAll(body, []byte(v), []byte(judgeRedactionMarker))
	}
	return body
}

// redactJudgeText redacts the whole of s, then bounds it to limit
// bytes. Redacting first means the cut cannot leave a partial value;
// the cut backs up to a rune boundary.
func redactJudgeText(s string, values []string, limit int) string {
	s = string(redactJudgeValues([]byte(s), values))
	if len(s) <= limit {
		return s
	}
	n := limit
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// readJudgeErrorBody reads a non-200 judge body for a reason or error.
// Redaction runs before the 1 KiB cap: it reads enough extra bytes that
// any value starting inside the cap is whole, replaces them, then
// truncates. When the read filled its bound the body may continue, and
// a value cut off by the bound is still a raw prefix that redacting
// earlier values could slide back under the cap, so the longest suffix
// of the redacted buffer that is a proper prefix of any value is
// dropped before truncating.
func readJudgeErrorBody(r io.Reader, values []string) []byte {
	const limit = 1024
	extra := 0
	for _, v := range values {
		extra = max(extra, len(v))
	}
	bound := limit + extra
	body, _ := io.ReadAll(io.LimitReader(r, int64(bound)))
	filled := len(body) >= bound
	body = redactJudgeValues(body, values)
	if filled {
		body = body[:len(body)-unscannedTail(body, values)]
	}
	if len(body) > limit {
		body = body[:limit]
	}
	return body
}

// unscannedTail is the length of the longest suffix of body that is a
// proper prefix of any value: a possible value cut off by the end of
// the read.
func unscannedTail(body []byte, values []string) int {
	longest := 0
	for _, v := range values {
		for n := min(len(v)-1, len(body)); n > longest; n-- {
			if bytes.HasSuffix(body, []byte(v[:n])) {
				longest = n
				break
			}
		}
	}
	return longest
}

func buildJudgePrompt(req runtime.ApproveRequest, policyText string) string {
	var sb strings.Builder
	sb.WriteString("Policy:\n")
	if policyText != "" {
		sb.WriteString(policyText)
	} else if req.Reason != "" {
		sb.WriteString(req.Reason)
	} else {
		sb.WriteString("(none — fall back to default-deny when uncertain)")
	}
	sb.WriteString("\n\nRequest:\n")
	fmt.Fprintf(&sb, "  method: %s\n  host: %s\n  path: %s\n", req.Method, req.Host, req.Path)
	if req.UA != "" {
		fmt.Fprintf(&sb, "  user-agent: %s\n", req.UA)
	}
	if req.BodySample != "" {
		fmt.Fprintf(&sb, "  body:\n%s\n", indent(truncate(req.BodySample, 4000), "    "))
	}
	return sb.String()
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n")
}

func parseJudgeVerdict(text string) (string, string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "deny", "llm returned empty response"
	}
	lines := strings.SplitN(text, "\n", 2)
	first := strings.ToLower(strings.TrimSpace(lines[0]))
	first = strings.Trim(first, ".,;:!?\"'`")
	reason := ""
	if len(lines) > 1 {
		reason = strings.TrimSpace(lines[1])
	}
	switch first {
	case "allow":
		return "allow", reason
	case "deny":
		return "deny", reason
	default:
		// Best-effort: search for the verdict word anywhere in the
		// response. Models occasionally preface with "Verdict: …".
		lower := strings.ToLower(text)
		if strings.Contains(lower, "deny") && !strings.Contains(lower, "allow") {
			return "deny", text
		}
		if strings.Contains(lower, "allow") && !strings.Contains(lower, "deny") {
			return "allow", text
		}
		// Not truncated here: the caller redacts the whole text first,
		// then bounds it, so a cut cannot leave a partial secret.
		return "deny", "ambiguous llm response: " + text
	}
}

// anthropicJudgeRequest builds a /v1/messages call. The credential
// plugin's InjectHTTP stamps Authorization + the OAuth beta header
// when needed; we just frame the body.
func anthropicJudgeRequest(ctx context.Context, model, system, user string) (*http.Request, func(io.Reader) (string, error)) {
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"max_tokens": 512,
		"system":     system,
		"messages": []map[string]any{
			{"role": "user", "content": user},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.anthropic.com/v1/messages", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	decode := func(r io.Reader) (string, error) {
		var msg struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.NewDecoder(r).Decode(&msg); err != nil {
			return "", err
		}
		// The last text block is the final answer and decides alone.
		// Thinking blocks are ignored: the request under review is
		// part of the prompt and could steer them.
		for i := len(msg.Content) - 1; i >= 0; i-- {
			if c := msg.Content[i]; c.Type == "text" {
				if c.Text != "" {
					return c.Text, nil
				}
				break
			}
		}
		return "", fmt.Errorf("anthropic response had no text content")
	}
	return req, decode
}

// openaiJudgeRequest builds a /v1/responses call (the modern GPT
// API). Authorization is supplied by the credential plugin's
// InjectHTTP.
func openaiJudgeRequest(ctx context.Context, model, system, user string) (*http.Request, func(io.Reader) (string, error)) {
	body, _ := json.Marshal(map[string]any{
		"model": model,
		"input": []map[string]any{
			{"role": "system", "content": []map[string]any{{"type": "input_text", "text": system}}},
			{"role": "user", "content": []map[string]any{{"type": "input_text", "text": user}}},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://api.openai.com/v1/responses", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	decode := func(r io.Reader) (string, error) {
		var msg struct {
			Output []struct {
				Type    string `json:"type"`
				Role    string `json:"role"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"output"`
		}
		if err := json.NewDecoder(r).Decode(&msg); err != nil {
			return "", err
		}
		// The verdict is the final assistant message's output_text.
		// Reasoning items also carry text, and the request under
		// review is part of the prompt, so reading them would let the
		// request steer the verdict.
		for i := len(msg.Output) - 1; i >= 0; i-- {
			o := msg.Output[i]
			if o.Type != "message" || o.Role != "assistant" {
				continue
			}
			var text strings.Builder
			for _, c := range o.Content {
				if c.Type == "output_text" {
					text.WriteString(c.Text)
				}
			}
			// The last assistant message decides alone: if it has no
			// output_text (a refusal), an earlier message must not
			// stand in for it.
			if text.Len() > 0 {
				return text.String(), nil
			}
			break
		}
		return "", fmt.Errorf("openai response had no output text")
	}
	return req, decode
}

// Summarize implements runtime.HITLClassifier. It calls the LLM in
// "summary mode" — sends the classifier system prompt and asks for
// structured JSON request context instead of an allow/deny verdict.
// On parse failure or LLM error, returns nil, err so the caller can
// fall back to the generic card.
func (a *LLMApprover) Summarize(ctx context.Context, req runtime.ApproveRequest) (*runtime.HITLSummary, error) {
	if a.Model == "" {
		return nil, fmt.Errorf("llm classifier has no model")
	}
	if a.Credential == "" {
		return nil, fmt.Errorf("llm classifier has no credential")
	}
	if req.Policy == nil {
		return nil, fmt.Errorf("no policy on request")
	}
	if _, ok := req.Policy.Credentials[a.Credential]; !ok {
		return nil, fmt.Errorf("credential %s not declared", a.Credential)
	}

	user := buildClassifierPrompt(req, a.Policy)

	var (
		hreq   *http.Request
		decode func(io.Reader) (string, error)
	)
	switch {
	case strings.HasPrefix(a.Model, "claude-"):
		hreq, decode = anthropicJudgeRequest(ctx, a.Model, llmClassifierSystem, user)
	case strings.HasPrefix(a.Model, "gpt-"), strings.HasPrefix(a.Model, "o"):
		hreq, decode = openaiJudgeRequest(ctx, a.Model, llmClassifierSystem, user)
	default:
		return nil, fmt.Errorf("unknown model family: %s", a.Model)
	}

	credEnt := req.Policy.Credentials[a.Credential]
	injector, ok := credEnt.Body.(runtime.HTTPCredentialRuntime)
	if !ok {
		return nil, fmt.Errorf("credential %s does not satisfy HTTPCredentialRuntime", a.Credential)
	}
	sec, err := req.Secrets.Get(a.Credential)
	if err != nil {
		return nil, fmt.Errorf("secret fetch: %w", err)
	}
	before := hreq.Header.Clone()
	if err := injector.InjectHTTP(ctx, hreq, sec); err != nil {
		discardHTTPRedactions(injector, hreq)
		return nil, fmt.Errorf("credential inject: %w", err)
	}
	redactions := judgeRedactions(before, hreq.Header, consumeHTTPRedactions(injector, hreq), sec)
	resp, err := llmJudgeClient.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		body := readJudgeErrorBody(resp.Body, redactions)
		return nil, fmt.Errorf("llm http %d: %s", resp.StatusCode, string(body))
	}
	text, err := decode(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("llm response decode: %w", err)
	}
	text = strings.TrimSpace(text)
	var summary runtime.HITLSummary
	if err := json.Unmarshal([]byte(text), &summary); err != nil {
		return nil, fmt.Errorf("classifier json parse: %w (raw: %s)", err, redactJudgeText(text, redactions, 200))
	}
	return &summary, nil
}

func buildClassifierPrompt(req runtime.ApproveRequest, policyText string) string {
	var sb strings.Builder
	sb.WriteString("Policy:\n")
	if policyText != "" {
		sb.WriteString(policyText)
	} else if req.Reason != "" {
		sb.WriteString(req.Reason)
	} else {
		sb.WriteString("(none)")
	}
	sb.WriteString("\n\nRequest:\n")
	fmt.Fprintf(&sb, "  method: %s\n  host: %s\n  path: %s\n", req.Method, req.Host, req.Path)
	if req.UA != "" {
		fmt.Fprintf(&sb, "  user-agent: %s\n", req.UA)
	}
	if req.BodySample != "" {
		fmt.Fprintf(&sb, "  body:\n%s\n", indent(truncate(req.BodySample, 4000), "    "))
	}
	return sb.String()
}

// compile-time assertion that LLMApprover satisfies HITLClassifier.
var _ runtime.HITLClassifier = (*LLMApprover)(nil)

func init() {
	config.Register(&config.Plugin{
		Kind:    config.KindApprover,
		Type:    "llm_approver",
		New:     func() any { return &LLMApprover{} },
		Runtime: (*LLMApprover)(nil),
		Refs: []config.RefSpec{
			{Path: "Credential", Kind: config.KindCredential},
		},
		Build: func(d any, _ string, _ *config.BuildCtx) (any, hcl.Diagnostics) { return d, nil },
		Emit: func(body any, _ string, b *hclwrite.Body) {
			a := body.(*LLMApprover)
			ri := config.EmitRefIndex()
			b.SetAttributeValue("model", cty.StringVal(a.Model))
			config.SetIdent(b, "credential", ri.Ref(config.KindCredential, a.Credential))
			if a.Policy != "" {
				b.SetAttributeValue("policy", cty.StringVal(a.Policy))
			}
		},
	})
}
