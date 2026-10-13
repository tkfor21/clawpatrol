package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/denoland/clawpatrol/internal/agentprovider"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

// scrubMarker replaces any real gateway-held secret found in an
// agent-bound body (invariant I13). Defense in depth: upstreams should
// never echo tokens, but if one does the agent must still not see it.
const scrubMarker = "clawpatrol-redacted-secret"

// minScrubLen skips short Extras (usernames, expiries) that can't be
// bearer secrets and would mangle unrelated content. It never drops the
// injected secret itself (scrubSecretsFor, S-04).
const minScrubLen = 16

// wsScrubMessageLimit caps how much of one WS text message (one frame or
// several fragments) the strict scrubber holds. Beyond it the connection
// is closed: a message we cannot scan whole must not reach the agent.
// 16 MiB leaves room for a whole Codex response.completed frame; the
// memory is held per connection only while one message is in flight.
const wsScrubMessageLimit = 16 << 20

var (
	errWSCompressedScrub      = errors.New("compressed websocket frame on a scrubbed connection")
	errWSScrubMessageTooLarge = errors.New("websocket text message exceeds the scrub limit; closing rather than forwarding it unscanned")
)

// scrubSecretList dedupes values, drops short ones, and orders the rest
// longest first, so a secret that contains another is replaced whole.
func scrubSecretList(values ...string) [][]byte {
	var out [][]byte
	seen := map[string]bool{}
	for _, v := range values {
		if len(v) < minScrubLen || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, []byte(v))
	}
	slices.SortStableFunc(out, func(a, b []byte) int { return len(b) - len(a) })
	return out
}

// scrubBytes replaces every secret in b with scrubMarker and reports the
// number of replacements. secrets must come from scrubSecretList.
func scrubBytes(b []byte, secrets [][]byte) ([]byte, int) {
	hits := 0
	for _, sec := range secrets {
		if c := bytes.Count(b, sec); c > 0 {
			hits += c
			b = bytes.ReplaceAll(b, sec, []byte(scrubMarker))
		}
	}
	return b, hits
}

// prepareScrubbedRequest makes the response to an agent request
// scannable (I13, DEV-7): identity encoding, and no permessage-deflate
// on a WebSocket upgrade.
func prepareScrubbedRequest(req *http.Request) {
	req.Header.Set("Accept-Encoding", "identity")
	if isWSUpgrade(req) {
		req.Header.Del("Sec-WebSocket-Extensions")
	}
}

// reframeWSRefusal rewrites the head of a non-101 upgrade reply whose
// body the gateway replaced: drop the framing, encoding and connection
// fields, then state the new length and close the connection.
func reframeWSRefusal(head []byte, bodyLen int) []byte {
	lines := bytes.Split(bytes.TrimSuffix(head, []byte("\r\n\r\n")), []byte("\r\n"))
	var out bytes.Buffer
	for i, line := range lines {
		if i > 0 {
			name, _, _ := bytes.Cut(line, []byte(":"))
			switch strings.ToLower(strings.TrimSpace(string(name))) {
			case "content-length", "transfer-encoding", "content-encoding", "connection":
				continue
			}
		}
		out.Write(line)
		out.WriteString("\r\n")
	}
	fmt.Fprintf(&out, "Content-Length: %d\r\nConnection: close\r\n\r\n", bodyLen)
	return out.Bytes()
}

// wsRefusalBodyLimit caps the refusal body read on a scrubbed
// connection.
const wsRefusalBodyLimit = 2048

const wsRefusalWithheld = "clawpatrol: upstream upgrade refusal withheld: it could not be scanned for secrets in full\n"

// scrubbedWSRefusalBody returns the agent-bound body of a refused
// WebSocket upgrade on a scrubbed connection (I13, R3-02). head is the
// already stripped and scrubbed response head. The reply is parsed as an
// HTTP response, so chunked framing is decoded rather than passed
// through as body text, and the decoded body is scrubbed in one pass. A
// body that is encoded (any Content-Encoding but identity, stacked lines
// included), longer than wsRefusalBodyLimit, or that cannot be read in
// full is replaced by a fixed notice, never cut: a cut body can end in a
// secret prefix that no scrub can recognize.
func scrubbedWSRefusalBody(head []byte, upBR *bufio.Reader, req *http.Request, rewrite wsPayloadRewriter) []byte {
	withheld := []byte(wsRefusalWithheld)
	resp, err := http.ReadResponse(bufio.NewReader(io.MultiReader(bytes.NewReader(head), upBR)), req)
	if err != nil {
		return withheld
	}
	defer func() { _ = resp.Body.Close() }()
	switch strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ","))) {
	case "", "identity":
	default:
		return withheld
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, wsRefusalBodyLimit+1))
	if err != nil || len(body) > wsRefusalBodyLimit {
		return withheld
	}
	if out, changed, err := rewrite(body); err == nil && changed {
		body = out
	}
	return body
}

// scrubActiveFor reports whether I13 applies to a request: the resolved
// credential has a secret to scrub, and either host is a provider API
// host or the credential's type belongs to a provider, whatever the host
// (D9). The API-host trigger stays, so a generic credential bound on a
// provider API host is still scrubbed.
func scrubActiveFor(host, credType string, haveSecrets bool) bool {
	return haveSecrets && (agentprovider.APIProvider(host) != nil || agentprovider.OwnsCredentialType(credType))
}

// scrubHeaderValues replaces every secret in every value of h, in place
// (D4). Header names are not secrets and are left alone.
func scrubHeaderValues(h http.Header, secrets [][]byte, onHit func(int)) {
	for _, vs := range h {
		for i, v := range vs {
			if out, n := scrubBytes([]byte(v), secrets); n > 0 {
				vs[i] = string(out)
				if onHit != nil {
					onHit(n)
				}
			}
		}
	}
}

// trailerScrubBody cleans a response's trailers when its body reaches
// EOF. net/http fills declared trailers at body EOF (transfer.go
// mergeSetHeader copies every received field into resp.Trailer, so a key
// deleted before EOF comes back), and http.Response.Write sends
// resp.Trailer (the same map) after the chunked body, so the cleaning
// lands in between. It strips auth-bearing trailer fields on every MITM
// response (round-2 S108: the existing pre-EOF
// stripAuthResponseHeaders(resp.Trailer) call runs while the values are
// still empty, so a Set-Cookie trailer got through), and scrubs secret
// values when secrets is non-empty (D4).
type trailerScrubBody struct {
	io.ReadCloser
	trailer http.Header
	secrets [][]byte
	onHit   func(int)
	done    bool
}

func newTrailerScrubBody(rc io.ReadCloser, trailer http.Header, secrets [][]byte, onHit func(int)) io.ReadCloser {
	return &trailerScrubBody{ReadCloser: rc, trailer: trailer, secrets: secrets, onHit: onHit}
}

func (b *trailerScrubBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if errors.Is(err, io.EOF) && !b.done {
		b.done = true
		stripAuthResponseHeaders(b.trailer)
		if len(b.secrets) > 0 {
			scrubHeaderValues(b.trailer, b.secrets, b.onHit)
		}
	}
	return n, err
}

// scrubWSHead scrubs secrets from a raw WebSocket upgrade-response head
// with the connection's server rewriter (D4). The marker has no CR or
// LF, so the head's framing is unchanged. A nil rewriter means the
// connection is not scrubbed.
func scrubWSHead(head []byte, rewrite wsPayloadRewriter) []byte {
	if rewrite == nil {
		return head
	}
	if out, changed, err := rewrite(head); err == nil && changed {
		return out
	}
	return head
}

// scrubSecretsFor lists every value of the resolved credential's secret
// plus its OAuth refresh token (which never leaves the gateway either).
// minScrubLen filters only the Extras and the refresh token: the
// injected secret is always on the list, whatever its length, so a short
// credential cannot turn the scrub off (S-04).
func (g *Gateway) scrubSecretsFor(name string, sec runtime.Secret) [][]byte {
	vals := make([]string, 0, len(sec.Extras)+1)
	for _, v := range sec.Extras {
		vals = append(vals, v)
	}
	if g.oauth != nil {
		vals = append(vals, g.oauth.RefreshToken(name))
	}
	out := scrubSecretList(vals...)
	if len(sec.Bytes) > 0 && !slices.ContainsFunc(out, func(b []byte) bool { return bytes.Equal(b, sec.Bytes) }) {
		out = append(out, bytes.Clone(sec.Bytes))
		slices.SortStableFunc(out, func(a, b []byte) int { return len(b) - len(a) })
	}
	return out
}

type secretScrubber struct {
	src     io.Reader
	secrets [][]byte
	onHit   func(int)
	buf     []byte
	pending []byte // scrubbed bytes held back: a possible secret prefix
	out     []byte
	eof     bool
}

// newSecretScrubber streams src with every secret replaced by
// scrubMarker. It holds back only a tail that could be the start of a
// secret, so streaming (SSE) responses are not delayed.
func newSecretScrubber(src io.Reader, secrets [][]byte, onHit func(n int)) io.Reader {
	return &secretScrubber{src: src, secrets: secrets, onHit: onHit, buf: make([]byte, 32*1024)}
}

func (s *secretScrubber) Read(p []byte) (int, error) {
	for len(s.out) == 0 {
		if s.eof {
			if len(s.pending) == 0 {
				return 0, io.EOF
			}
			s.out, s.pending = s.pending, nil
			break
		}
		n, err := s.src.Read(s.buf)
		s.pending = append(s.pending, s.buf[:n]...)
		if errors.Is(err, io.EOF) {
			s.eof = true
		} else if err != nil {
			return 0, err
		}
		s.pending = s.replace(s.pending)
		hold := 0
		if !s.eof {
			hold = s.partialSuffix(s.pending)
		}
		cut := len(s.pending) - hold
		s.out = append(s.out, s.pending[:cut]...)
		s.pending = append([]byte(nil), s.pending[cut:]...)
	}
	n := copy(p, s.out)
	s.out = s.out[n:]
	return n, nil
}

func (s *secretScrubber) replace(b []byte) []byte {
	b, hits := scrubBytes(b, s.secrets)
	if hits > 0 && s.onHit != nil {
		s.onHit(hits)
	}
	return b
}

// partialSuffix returns the length of the longest tail of b that is a
// proper prefix of some secret.
func (s *secretScrubber) partialSuffix(b []byte) int {
	best := 0
	for _, sec := range s.secrets {
		start := max(len(b)-(len(sec)-1), 0)
		for i := start; i < len(b); i++ {
			if len(b)-i <= best {
				break
			}
			if b[i] == sec[0] && bytes.HasPrefix(sec, b[i:]) {
				best = len(b) - i
				break
			}
		}
	}
	return best
}

// scrubbableBody returns resp's body as identity bytes so it can be
// scanned, and whether the caller must wrap and re-frame it. A 101 fails
// closed: net/http hands back the raw upstream connection as the body,
// and http.Response.Write would copy that stream to the agent unscanned
// (S-01). Other responses that carry no body (HEAD, other 1xx, 204, 304,
// or an empty body) are left exactly as they are: re-framing them as
// chunked would put a stray "0\r\n\r\n" on a keep-alive connection. gzip
// is decoded (and the header dropped). Every other encoding fails
// closed, including stacked Content-Encoding lines, so a body we cannot
// scan never reaches the agent. No error text quotes an upstream value:
// it is stored in the event reason and the HITL last_error (S-03).
func scrubbableBody(req *http.Request, resp *http.Response) (io.ReadCloser, bool, error) {
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return nil, false, errors.New("protocol switch cannot be scanned for secrets")
	}
	if req.Method == http.MethodHead || resp.StatusCode < 200 ||
		resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified ||
		resp.Body == nil || resp.Body == http.NoBody || resp.ContentLength == 0 {
		return resp.Body, false, nil
	}
	enc := strings.ToLower(strings.TrimSpace(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	switch enc {
	case "", "identity":
		return resp.Body, true, nil
	case "gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, false, fmt.Errorf("gzip: %w", err)
		}
		resp.Header.Del("Content-Encoding")
		return struct {
			io.Reader
			io.Closer
		}{zr, resp.Body}, true, nil
	default:
		return nil, false, errors.New("content-encoding cannot be scanned for secrets")
	}
}

// wsScrubRewriter scrubs server→client text messages.
func wsScrubRewriter(secrets [][]byte, onHit func(int)) wsPayloadRewriter {
	return func(p []byte) ([]byte, bool, error) {
		out, hits := scrubBytes(p, secrets)
		if hits == 0 {
			return p, false, nil
		}
		if onHit != nil {
			onHit(hits)
		}
		return out, true, nil
	}
}
