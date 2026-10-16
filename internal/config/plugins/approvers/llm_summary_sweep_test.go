package approvers

import (
	"context"
	"strings"
	"testing"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// Fake values only, of three sizes: one that shrinks when redacted
// (125 bytes to the 26-byte marker), one about the marker's size, and
// one of 8 bytes that grows when redacted.
const (
	sweepLong  = "LX" + "Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7Q7" + "END"
	sweepShort = "SHRT1234"
	sweepMid   = "MIDVALUE0123456789abcdefZZ"
)

type sweepSecrets struct{}

func (sweepSecrets) Get(string) (runtime.Secret, error) {
	return runtime.Secret{Bytes: []byte(sweepLong), Extras: map[string]string{"a": sweepShort, "b": sweepMid}}, nil
}

// sweepLeak reports the first 8-byte window of a secret found in s,
// skipping windows that also occur inside the redaction marker.
func sweepLeak(s string) string {
	for _, v := range []string{sweepLong, sweepShort, sweepMid} {
		for i := 0; i+8 <= len(v); i++ {
			w := v[i : i+8]
			if strings.Contains(judgeRedactionMarker, w) {
				continue
			}
			if strings.Contains(s, w) {
				return w
			}
		}
	}
	return ""
}

// The Summarize field cuts must redact before they cut. Each secret is
// placed at every offset across each field's bound, after 0, 2, or 20
// copies of the long secret: those shrink when redacted and pull a
// later value back under the cut, the shape of the Task 7 leak. A
// cut-then-redact field would end in a raw prefix of the secret.
func TestLLMSummarizeFieldsNeverLeakAtAnyOffset(t *testing.T) {
	req := runtime.ApproveRequest{
		Policy:  &config.CompiledPolicy{Credentials: map[string]*config.Entity{"judge": {Body: nopHTTPCredential{}, Plugin: genericJudgeType}}},
		Secrets: sweepSecrets{},
	}
	a := &LLMApprover{Model: "claude-test", Credential: "judge"}
	cases := 0
	for _, target := range []string{sweepLong, sweepShort, sweepMid} {
		// 0, a few, and many shrinking copies; trimmed from the
		// reviewer's 0/1/3/8/20 to stay under 5 s with -race.
		for _, reps := range []int{0, 2, 20} {
			prefix := strings.Repeat(sweepLong, reps)
			for off := 0; off <= judgeReasonLimit+len(target)+130; off++ {
				val := prefix + strings.Repeat("a", off) + target + strings.Repeat("b", 40)
				body := `{"subject":"` + val + `","label":"` + val + `","confidence":1,"summary":"` + val + `"}`
				useJudgeReply(t, 200, anthropicText(t, body))
				s, err := a.Summarize(context.Background(), req)
				if err != nil {
					t.Fatalf("Summarize: %v", err)
				}
				cases++
				for _, f := range []struct {
					name, got string
					limit     int
				}{
					{"subject", s.Subject, 200},
					{"label", s.Label, 200},
					{"summary", s.Summary, judgeReasonLimit},
				} {
					if w := sweepLeak(f.got); w != "" {
						t.Fatalf("%s leaks window %q (target %.8q, %d prefix copies, offset %d): %q", f.name, w, target, reps, off, f.got)
					}
					if len(f.got) > f.limit+len("…") {
						t.Fatalf("%s is %d bytes, over its %d-byte bound", f.name, len(f.got), f.limit)
					}
				}
			}
		}
	}
	t.Logf("swept %d summaries", cases)
}
