package main

// Session-token grants (invariant I15, #25). Some upstream responses hand
// the client a bearer token it then presents on related paths: Claude
// Code's remote control gets a worker token from /bridge and uses it on
// the session's /worker paths. The gateway keeps the real token, gives
// the agent a random placeholder, and puts the real token back only on
// the canonical use path of the same session, for the same agent,
// profile, credential and host. It is opt-in per credential
// (runtime.SessionTokenCredential); an off gateway refuses the issue
// path, so no token is minted through it with the gateway's credential.
//
// An issue response's body is never forwarded as upstream bytes: the
// gateway forwards a canonical re-encoding of exactly the JSON it checked
// (for a 2xx, only the declared fields), so every parser reads what was
// checked. Status and headers pass after the checks. The checks look for
// known spellings of the token; they are not a proof.

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/denoland/clawpatrol/internal/agentprovider"
	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/runtime"
)

const (
	sessionTokenPlaceholderPrefix = "clawpatrol-session-token-"
	// sessionTokenMaxBody bounds an issue response the gateway buffers.
	sessionTokenMaxBody = 64 << 10
	// sessionTokenMaxTTL caps how long a placeholder resolves, whatever
	// lifetime the upstream states.
	sessionTokenMaxTTL = 24 * time.Hour
	// sessionTokenMaxPerOwner bounds live placeholders per owner; the
	// oldest goes first.
	sessionTokenMaxPerOwner = 32
)

var (
	// sessionTokenChars is the token alphabet the gateway accepts: JWT
	// and base64/base64url characters only. validSessionToken adds the
	// length bounds.
	sessionTokenChars = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	// jwtLike finds a JWT-shaped string: a base64url JSON header ("eyJ")
	// and two more dot-separated segments. None may be left in what the
	// agent gets from an issue path.
	jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*`)
	// surrogateEscape finds a JSON \uD800–\uDFFF escape. Go and JavaScript
	// decode a lone one differently, and no token or field needs one.
	surrogateEscape = regexp.MustCompile(`(?i)\\u[d][89a-f][0-9a-f]{2}`)
)

func validSessionToken(tok string) bool {
	return len(tok) >= 16 && len(tok) <= 16384 && sessionTokenChars.MatchString(tok)
}

// sessionTokenOwner is who a placeholder belongs to. Every part must
// match on use. The binding is per device, not per process.
type sessionTokenOwner struct{ agent, profile, credential, host string }

type sessionTokenEntry struct {
	owner   sessionTokenOwner
	session string
	token   string
	expires time.Time
	seq     uint64
}

type sessionTokenStore struct {
	mu            sync.Mutex
	byPlaceholder map[string]*sessionTokenEntry
	seq           uint64
	// ep moves on every drop or prune. An issue request captures it at
	// its start (epoch) and issueAt refuses if it moved meanwhile, so a
	// credential change or reload always wins over one in flight.
	ep     uint64
	now    func() time.Time
	random io.Reader
}

func newSessionTokenStore() *sessionTokenStore {
	return &sessionTokenStore{byPlaceholder: map[string]*sessionTokenEntry{}, now: time.Now, random: rand.Reader}
}

// epoch returns the store's current epoch; see issueAt.
func (s *sessionTokenStore) epoch() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ep
}

// issue is issueAt at the current epoch.
func (s *sessionTokenStore) issue(o sessionTokenOwner, session, token string, ttl time.Duration) (string, error) {
	return s.issueAt(o, session, token, ttl, s.epoch())
}

// issueAt stores token for (o, session) and returns a fresh placeholder,
// unless a drop or prune happened since epoch at.
func (s *sessionTokenStore) issueAt(o sessionTokenOwner, session, token string, ttl time.Duration, at uint64) (string, error) {
	if o.agent == "" || o.profile == "" || o.credential == "" || o.host == "" {
		return "", errors.New("session token: no agent, profile, credential or host to bind the token to")
	}
	if session == "" || token == "" || ttl <= 0 {
		return "", errors.New("session token: missing session, token or lifetime")
	}
	ttl = min(ttl, sessionTokenMaxTTL)
	var raw [16]byte
	if _, err := io.ReadFull(s.random, raw[:]); err != nil {
		return "", fmt.Errorf("session token: random: %w", err)
	}
	ph := sessionTokenPlaceholderPrefix + hex.EncodeToString(raw[:])

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ep != at {
		return "", errors.New("session token: the credential changed while the request was in flight")
	}
	now := s.now()
	var mine []*sessionTokenEntry
	for k, e := range s.byPlaceholder {
		if !now.Before(e.expires) {
			delete(s.byPlaceholder, k)
			continue
		}
		if e.owner == o {
			mine = append(mine, e)
		}
	}
	for len(mine) >= sessionTokenMaxPerOwner {
		oldest := 0
		for i := range mine {
			if mine[i].seq < mine[oldest].seq {
				oldest = i
			}
		}
		for k, e := range s.byPlaceholder {
			if e == mine[oldest] {
				delete(s.byPlaceholder, k)
			}
		}
		mine = append(mine[:oldest], mine[oldest+1:]...)
	}
	if _, dup := s.byPlaceholder[ph]; dup {
		return "", errors.New("session token: placeholder collision")
	}
	s.seq++
	s.byPlaceholder[ph] = &sessionTokenEntry{owner: o, session: session, token: token, expires: now.Add(ttl), seq: s.seq}
	return ph, nil
}

// resolve returns the real token for placeholder when every part of the
// owner and the session match and the entry is live.
func (s *sessionTokenStore) resolve(o sessionTokenOwner, session, placeholder string) (string, bool) {
	if session == "" || !strings.HasPrefix(placeholder, sessionTokenPlaceholderPrefix) {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.byPlaceholder[placeholder]
	if e == nil {
		return "", false
	}
	if !s.now().Before(e.expires) {
		delete(s.byPlaceholder, placeholder)
		return "", false
	}
	if e.owner != o || e.session != session {
		return "", false
	}
	return e.token, true
}

// dropCredential forgets every placeholder of credential name. Called
// when the credential is connected, reconnected, revoked or cleared.
func (s *sessionTokenStore) dropCredential(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ep++
	for k, e := range s.byPlaceholder {
		if e.owner.credential == name {
			delete(s.byPlaceholder, k)
		}
	}
}

// retainCredentials forgets every placeholder whose credential is not
// in keep.
func (s *sessionTokenStore) retainCredentials(keep map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ep++
	for k, e := range s.byPlaceholder {
		if !keep[e.owner.credential] {
			delete(s.byPlaceholder, k)
		}
	}
}

func (s *sessionTokenStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byPlaceholder)
}

// sessionTokenStore returns the gateway's placeholder store, created on
// first use.
func (g *Gateway) sessionTokenStore() *sessionTokenStore {
	g.sessionTokensOnce.Do(func() { g.sessionTokens = newSessionTokenStore() })
	return g.sessionTokens
}

// sessionTokenAfterReadHook is a test seam: when set, the MITM loop
// calls it right after reading a request and capturing the epoch. Nil
// in production.
var sessionTokenAfterReadHook func()

// wireSessionTokenHooks makes connecting, reconnecting or revoking a
// credential in reg retire its session-token placeholders. A refresh
// doesn't come through the hook, so live sessions survive it.
func (g *Gateway) wireSessionTokenHooks(reg *OAuthRegistry) {
	reg.onCredentialChange = func(id string) { g.sessionTokenStore().dropCredential(id) }
}

// pruneSessionTokens runs on config reload: placeholders survive only
// for credentials still declared and still opted in, so turning
// remote_control off and on again can't revive them, while unrelated
// reloads leave live sessions alone.
func (g *Gateway) pruneSessionTokens(policy *config.CompiledPolicy) {
	keep := map[string]bool{}
	if policy != nil {
		for name, ent := range policy.Credentials {
			if c, ok := ent.Body.(runtime.SessionTokenCredential); ok && c.SessionTokensEnabled() {
				keep[name] = true
			}
		}
	}
	g.sessionTokenStore().retainCredentials(keep)
}

// Limits on the issue-path scan (review #25 R4-1): headers are capped
// before anything is decoded, and every scan has a work budget; running
// out counts as "may hold a token", so the response is refused.
const (
	sessionTokenMaxHeaderValue = 8 << 10
	sessionTokenMaxHeaders     = 32 << 10
	sessionTokenScanBudget     = 2 << 20 // bytes examined per response
)

// tokenScan checks strings for tok or anything JWT-shaped in any spelling
// a client could undo: raw, with whitespace removed, after up to three
// layers of lenient percent-decoding, inside a base64 (standard or URL,
// any alignment, line-wrapped) or hex encoding, or inside a decoded
// base64/hex run, recursively (JSON inside included). One tokenScan is
// shared by everything checked for a response, so its budget bounds the
// whole response.
type tokenScan struct {
	tok    string
	forms  []string
	budget int
}

func newTokenScan(tok string) *tokenScan {
	return &tokenScan{tok: tok, forms: encodedTokenForms(tok), budget: sessionTokenScanBudget}
}

// holdsToken is a one-off tokenScan.
func holdsToken(s, tok string) bool { return newTokenScan(tok).holds(s) }

func (t *tokenScan) holds(s string) bool { return t.holdsDepth(s, 0) }

// spend charges n bytes of work; false means the budget is gone.
func (t *tokenScan) spend(n int) bool {
	t.budget -= n
	return t.budget >= 0
}

// encodedRun is a run that might be base64 or hex; decodeCandidates
// also tries the pieces between "/" (which is in the standard alphabet
// but also a URL separator).
var encodedRun = regexp.MustCompile(`[A-Za-z0-9+/_=-]{16,}`)

func (t *tokenScan) holdsDepth(s string, depth int) bool {
	if !t.spend(len(s)) {
		return true
	}
	layers := []string{s}
	for range 3 {
		last := layers[len(layers)-1]
		next := agentprovider.LenientUnescape(last)
		if next == last {
			break
		}
		if !t.spend(len(next)) {
			return true
		}
		layers = append(layers, next)
	}
	for _, l := range layers {
		flat := strings.Join(strings.Fields(l), "")
		for _, v := range []string{l, flat} {
			if jwtLike.MatchString(v) || (t.tok != "" && strings.Contains(v, t.tok)) {
				return true
			}
			for _, f := range t.forms {
				if strings.Contains(v, f) {
					return true
				}
			}
		}
		if depth >= 3 {
			continue
		}
		for _, run := range encodedRun.FindAllString(l, -1) {
			for _, d := range decodeCandidates(run) {
				if !t.spend(len(d)) {
					return true
				}
				if t.holdsDepth(d, depth+1) {
					return true
				}
				var v any
				if json.Unmarshal([]byte(d), &v) == nil {
					for _, str := range jsonStrings(v) {
						if t.holdsDepth(str, depth+1) {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// decodeCandidates returns every base64 (standard and URL, padded or
// not) and hex decoding of run and of its "/"-separated pieces.
func decodeCandidates(run string) []string {
	cands := []string{run}
	if strings.Contains(run, "/") {
		for _, p := range strings.Split(run, "/") {
			if len(p) >= 16 {
				cands = append(cands, p)
			}
		}
	}
	var out []string
	for _, c := range cands {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if d, err := enc.DecodeString(c); err == nil {
				out = append(out, string(d))
			}
			if d, err := enc.WithPadding(base64.NoPadding).DecodeString(strings.TrimRight(c, "=")); err == nil {
				out = append(out, string(d))
			}
		}
		if len(c)%2 == 0 {
			if d, err := hex.DecodeString(c); err == nil {
				out = append(out, string(d))
			}
		}
	}
	return out
}

// encodedTokenForms returns substrings that any base64 (standard or URL,
// at each of the three byte alignments) or hex encoding of a string
// containing tok must contain.
func encodedTokenForms(tok string) []string {
	if tok == "" {
		return nil
	}
	var forms []string
	for shift := range 3 {
		buf := append(make([]byte, shift), tok...)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			e := enc.EncodeToString(buf)
			lo, hi := 0, len(e)-4
			if shift > 0 {
				lo = 4
			}
			if hi-lo >= 16 {
				forms = append(forms, e[lo:hi])
			}
		}
	}
	h := hex.EncodeToString([]byte(tok))
	return append(forms, h, strings.ToUpper(h))
}

// canonicalJSON decodes one JSON value (numbers kept exact) and
// re-encodes it. Duplicate keys resolve to the last value, the same
// value the checks see, and nothing spelled oddly survives.
func canonicalJSON(raw []byte) ([]byte, any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("trailing data")
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), v, nil
}

// jsonStrings returns every string of v (object keys and values, any
// depth).
func jsonStrings(v any) []string {
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case map[string]any:
			for k, c := range t {
				out = append(out, k)
				walk(c)
			}
		case []any:
			for _, c := range t {
				walk(c)
			}
		}
	}
	walk(v)
	return out
}

// jsonHasKey reports whether b is JSON with an object key equal to key
// (decoded, so escaped spellings count) at any depth. Non-JSON is false.
func jsonHasKey(b []byte, key string) bool {
	var v any
	if json.Unmarshal(b, &v) != nil {
		return false
	}
	var walk func(v any) bool
	walk = func(v any) bool {
		switch t := v.(type) {
		case map[string]any:
			if _, ok := t[key]; ok {
				return true
			}
			for _, c := range t {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range t {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

// swapIssuedSessionToken rewrites an issue response in place and returns
// the real token ("" for a non-2xx, which carries none).
//
// A 2xx must be one JSON object with exactly one top-level string token
// field of the accepted shape, a positive numeric TTL field, and no
// duplicate top-level key. The agent gets a canonical re-encoding of the
// placeholder, the TTL and the grant's KeepFields only; everything else
// is dropped. A non-2xx keeps its status; a JSON body is re-encoded
// canonically, any other body is dropped.
//
// An error means the gateway can't prove the result token-free; the
// caller answers 502 and forwards nothing. The error never quotes
// upstream bytes. Refused: an encoded or oversized body, invalid UTF-8 or
// a surrogate escape, the token or anything JWT-shaped in any header or
// trailer, and, after the rewrite, any string (keys and values, any
// depth, also percent-decoded) holding the token, anything JWT-shaped or
// (for a non-2xx) the token field's name.
func swapIssuedSessionToken(resp *http.Response, g *agentprovider.SessionTokenGrant, issue func(token string, ttl time.Duration) (string, error)) (string, error) {
	for _, v := range resp.Header.Values("Content-Encoding") {
		for _, ce := range strings.Split(v, ",") {
			if ce = strings.TrimSpace(ce); ce != "" && !strings.EqualFold(ce, "identity") {
				return "", errors.New("session token: issue response is content-encoded")
			}
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sessionTokenMaxBody+1))
	_ = resp.Body.Close()
	if err != nil {
		return "", errors.New("session token: issue response could not be read")
	}
	if len(body) > sessionTokenMaxBody {
		return "", errors.New("session token: issue response over the size limit")
	}
	if !utf8.Valid(body) || surrogateEscape.Match(body) {
		return "", errors.New("session token: issue response has invalid UTF-8 or a surrogate escape")
	}
	total := 0
	for _, h := range []http.Header{resp.Header, resp.Trailer} {
		for k, vs := range h {
			for _, v := range vs {
				if len(v) > sessionTokenMaxHeaderValue {
					return "", errors.New("session token: issue response header over the size limit")
				}
				total += len(k) + len(v)
			}
		}
	}
	if total > sessionTokenMaxHeaders {
		return "", errors.New("session token: issue response headers over the size limit")
	}
	setBody := func(b []byte) {
		resp.Body = io.NopCloser(bytes.NewReader(b))
		resp.ContentLength = int64(len(b))
		resp.TransferEncoding = nil
		resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	}
	headersHold := func(sc *tokenScan, names bool) bool {
		for _, h := range []http.Header{resp.Header, resp.Trailer} {
			for _, vs := range h {
				for _, v := range vs {
					if sc.holds(v) || (names && strings.Contains(v, g.TokenField)) {
						return true
					}
				}
			}
		}
		return false
	}

	if resp.StatusCode/100 != 2 {
		sc := newTokenScan("")
		if headersHold(sc, true) {
			return "", fmt.Errorf("session token: %d issue response header may carry a token", resp.StatusCode)
		}
		if len(bytes.TrimSpace(body)) == 0 || !json.Valid(body) {
			setBody(nil)
			return "", nil
		}
		out, v, err := canonicalJSON(body)
		if err != nil {
			setBody(nil)
			return "", nil
		}
		for _, s := range jsonStrings(v) {
			if sc.holds(s) || strings.Contains(s, g.TokenField) {
				return "", fmt.Errorf("session token: %d issue response may carry a token", resp.StatusCode)
			}
		}
		setBody(out)
		return "", nil
	}

	keys, raws, err := topLevelObject(body)
	if err != nil {
		return "", fmt.Errorf("session token: issue response: %w", err)
	}
	at := map[string]int{}
	for i, k := range keys {
		if _, dup := at[k]; dup {
			return "", errors.New("session token: issue response repeats a top-level key")
		}
		at[k] = i
	}
	tokenAt, ok := at[g.TokenField]
	if !ok {
		// Clients require the field; a 2xx without it is malformed, and
		// it may carry the token under another name.
		return "", fmt.Errorf("session token: 2xx issue response without %q", g.TokenField)
	}
	var tok string
	if err := json.Unmarshal(raws[tokenAt], &tok); err != nil || !validSessionToken(tok) {
		return "", fmt.Errorf("session token: %q is not a token string", g.TokenField)
	}
	ttlAt, ok := at[g.TTLField]
	if !ok {
		return "", fmt.Errorf("session token: %q missing", g.TTLField)
	}
	// A number, not a quoted one (json.Number would take a string).
	var secs float64
	if err := json.Unmarshal(raws[ttlAt], &secs); err != nil || bytes.Equal(bytes.TrimSpace(raws[ttlAt]), []byte("null")) || math.IsNaN(secs) || secs <= 0 {
		return "", fmt.Errorf("session token: %q is not a positive number", g.TTLField)
	}
	ttl := sessionTokenMaxTTL
	if secs < sessionTokenMaxTTL.Seconds() {
		ttl = time.Duration(secs * float64(time.Second))
	}
	sc := newTokenScan(tok)
	if headersHold(sc, false) {
		return "", errors.New("session token: a response header carries the token")
	}

	// The output: placeholder, TTL and KeepFields, each re-encoded from
	// the decoded value the checks below see.
	type field struct {
		key string
		val []byte
		dec any
	}
	ttlJSON, _, err := canonicalJSON(raws[ttlAt])
	if err != nil {
		return "", fmt.Errorf("session token: %q unreadable", g.TTLField)
	}
	fields := []field{{key: g.TTLField, val: ttlJSON}}
	for _, k := range g.KeepFields {
		i, ok := at[k]
		if !ok {
			continue
		}
		out, dec, err := canonicalJSON(raws[i])
		if err != nil {
			return "", fmt.Errorf("session token: %q unreadable", k)
		}
		fields = append(fields, field{key: k, val: out, dec: dec})
	}
	for _, f := range fields {
		for _, s := range jsonStrings(f.dec) {
			if sc.holds(s) {
				return "", errors.New("session token: the issue response carries the token or a JWT outside its field")
			}
		}
	}
	build := func(ph string) []byte {
		var out bytes.Buffer
		phJSON, _ := json.Marshal(ph)
		kj, _ := json.Marshal(g.TokenField)
		out.WriteByte('{')
		out.Write(kj)
		out.WriteByte(':')
		out.Write(phJSON)
		for _, f := range fields {
			kj, _ := json.Marshal(f.key)
			out.WriteByte(',')
			out.Write(kj)
			out.WriteByte(':')
			out.Write(f.val)
		}
		out.WriteByte('}')
		return out.Bytes()
	}
	// Last check on the exact bytes, with a stand-in of the placeholder's
	// shape, before anything is issued.
	probe := build(sessionTokenPlaceholderPrefix + strings.Repeat("0", 32))
	if bytes.Contains(probe, []byte(tok)) || jwtLike.Match(probe) || !json.Valid(probe) {
		return "", errors.New("session token: rewrite did not remove every copy of the token")
	}
	ph, err := issue(tok, ttl)
	if err != nil {
		return "", err
	}
	setBody(build(ph))
	return tok, nil
}

// topLevelObject decodes b as exactly one JSON object and returns its
// keys (decoded, in order) and raw values. Anything else is an error.
func topLevelObject(b []byte) ([]string, []json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	t, err := dec.Token()
	if err != nil {
		return nil, nil, errors.New("not JSON")
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, nil, errors.New("not a JSON object")
	}
	var keys []string
	var raws []json.RawMessage
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, nil, errors.New("malformed JSON object")
		}
		k, ok := t.(string)
		if !ok {
			return nil, nil, errors.New("malformed JSON object")
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, errors.New("malformed JSON value")
		}
		keys = append(keys, k)
		raws = append(raws, raw)
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, nil, errors.New("malformed JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, nil, errors.New("trailing data after the JSON object")
	}
	return keys, raws, nil
}
