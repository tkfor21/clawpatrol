package agentprovider

import (
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// sessionTokenIDPattern is the session ids a grant binds. Anything else
// in the {id} segment still counts as an issue request, with no id.
var sessionTokenIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// SessionTokenFor reports the role u plays for some provider's
// SessionTokenGrant on host, and the session id it names (I15).
//
// Issue matching is loose: every spelling issueSpellings normalizes
// (escapes, decoding layers, case, dot segments, backslashes, matrix
// parameters, fullwidth and zero-width characters, trailing junk on the
// last segment) counts, to cover what common routers accept. The id is "" when
// the {id} segment is not a plain session id; callers fail closed then.
//
// Use matching is strict: the path must be canonical (no escapes, no
// dot segments, no empty segments, no trailing slash) with exact case,
// so the real token only ever leaves on an unambiguous path.
func SessionTokenFor(host string, u *url.URL) (*Provider, *SessionTokenGrant, SessionTokenRole, string) {
	if u == nil {
		return nil, nil, SessionTokenNone, ""
	}
	h := NormalizeHost(host)
	if h == "" {
		return nil, nil, SessionTokenNone, ""
	}
	for _, p := range All() {
		for i := range p.SessionTokens {
			g := &p.SessionTokens[i]
			if NormalizeHost(g.Host) != h {
				continue
			}
			// An opaque "scheme:path" target has no Path for either
			// matcher to read, yet an upstream could still route it:
			// treat it as an issue request with no id (refused).
			if u.Opaque != "" {
				return p, g, SessionTokenIssue, ""
			}
			if id, ok := matchIssuePath(g.IssuePath, u); ok {
				return p, g, SessionTokenIssue, id
			}
			if id, ok := matchUsePath(g.UsePath, u); ok {
				return p, g, SessionTokenUse, id
			}
		}
	}
	return nil, nil, SessionTokenNone, ""
}

func matchIssuePath(tmpl string, u *url.URL) (string, bool) {
	for _, segs := range issueSpellings(u) {
		if id, ok := matchTemplate(tmpl, segs, false, true); ok {
			if !sessionTokenIDPattern.MatchString(id) {
				id = ""
			}
			return id, true
		}
	}
	return "", false
}

// issueSpellings returns the path segments of every spelling a router
// might normalize u's path to: the decoded and the escaped path and up
// to three more decoding layers; each with backslashes (raw or "%5C")
// read as "/", matrix parameters (";…" or "%3B…") dropped before dot
// segments resolve (Tomcat's "..;"), and each segment folded (NFKC,
// zero-width and control characters removed, trailing spaces and dots
// trimmed).
func issueSpellings(u *url.URL) [][]string {
	cands := []string{u.Path, u.EscapedPath()}
	for i, prev := 0, u.Path; i < 3; i++ {
		next := LenientUnescape(prev)
		if next == prev {
			break
		}
		cands = append(cands, next)
		prev = next
	}
	var out [][]string
	seen := map[string]bool{}
	for _, c := range cands {
		c = strings.NewReplacer(`\`, "/", "%5C", "/", "%5c", "/").Replace(c)
		raw := strings.Split(c, "/")
		for i, seg := range raw {
			if j := strings.Index(seg, ";"); j >= 0 {
				seg = seg[:j]
			}
			if j := strings.Index(strings.ToLower(seg), "%3b"); j >= 0 {
				seg = seg[:j]
			}
			raw[i] = foldSegment(seg)
		}
		clean := path.Clean("/" + strings.Join(raw, "/"))
		if seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, strings.Split(strings.TrimPrefix(clean, "/"), "/"))
	}
	return out
}

// foldSegment applies NFKC (fullwidth letters become ASCII), drops
// zero-width and control characters, and trims trailing spaces and dots
// (but keeps "." and ".." for dot-segment resolution).
func foldSegment(seg string) string {
	if seg == "." || seg == ".." {
		return seg
	}
	seg = norm.NFKC.String(seg)
	seg = strings.Map(func(r rune) rune {
		switch {
		case r == '\u200b', r == '\u200c', r == '\u200d', r == '\u2060', r == '\ufeff':
			return -1
		case unicode.IsControl(r):
			return -1
		}
		return r
	}, seg)
	if t := strings.TrimRight(seg, " \t."); t != "" {
		seg = t
	}
	return seg
}

// LenientUnescape decodes every valid %XX escape in s and leaves the
// rest as is, so one malformed escape can't hide the others (unlike
// url.PathUnescape, which rejects the whole string).
func LenientUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

func matchUsePath(tmpl string, u *url.URL) (string, bool) {
	p := u.Path
	if p == "" || u.EscapedPath() != p || path.Clean(p) != p {
		return "", false
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	tsegs := templateSegments(tmpl)
	if len(segs) < len(tsegs) {
		return "", false
	}
	id, ok := matchTemplate(tmpl, segs[:len(tsegs)], true, false)
	if !ok || !sessionTokenIDPattern.MatchString(id) {
		return "", false
	}
	return id, true
}

func templateSegments(tmpl string) []string {
	return strings.Split(strings.TrimPrefix(tmpl, "/"), "/")
}

// matchTemplate compares path segments with a template's segments.
// Fixed segments compare exactly when exact is set, else
// case-insensitively; with lastPrefix the last segment only has to
// start with the template's ("bridge.json", "bridge%00"). "{id}" takes
// any non-empty segment.
func matchTemplate(tmpl string, segs []string, exact, lastPrefix bool) (string, bool) {
	tsegs := templateSegments(tmpl)
	if len(segs) != len(tsegs) {
		return "", false
	}
	id := ""
	for i, t := range tsegs {
		switch {
		case t == "{id}":
			if segs[i] == "" {
				return "", false
			}
			id = segs[i]
		case lastPrefix && i == len(tsegs)-1:
			if !strings.HasPrefix(strings.ToLower(segs[i]), strings.ToLower(t)) {
				return "", false
			}
		case exact && segs[i] != t, !exact && !strings.EqualFold(segs[i], t):
			return "", false
		}
	}
	return id, true
}
