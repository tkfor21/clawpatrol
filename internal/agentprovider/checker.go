package agentprovider

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/denoland/clawpatrol/internal/config"
)

// PluginLookup returns a fresh decoded body for a registered config
// plugin. Injected so checker tests don't need the real registry.
type PluginLookup func(kind config.Kind, typ string) (body any, ok bool)

func configLookup(kind config.Kind, typ string) (any, bool) {
	p := config.Lookup(kind, typ)
	if p == nil || p.New == nil {
		return nil, false
	}
	return p.New(), true
}

// MustValidate checks the live registry and panics on any violation, so a
// bad declaration stops the gateway at startup. Called from plugins/all
// after every provider and config plugin has registered.
func MustValidate() {
	if err := Validate(All(), configLookup); err != nil {
		panic(err)
	}
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return NormalizeHost(u.Host)
}

// validHostPattern reports whether h is a lowercase DNS name made of
// [a-z0-9-] labels (no empty label, no label starting or ending in
// "-"), optionally behind one leading "*." wildcard. Anything else
// (a port, a path, a trailing dot, uppercase, a "*" elsewhere) can
// never equal NormalizeHost(sni), so the declaration would silently
// switch its gate off (R0-07).
func validHostPattern(h string) bool {
	bare := strings.TrimPrefix(h, "*.")
	if bare == "" || len(bare) > 253 {
		return false
	}
	for _, label := range strings.Split(bare, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			// De Morgan form: golangci-lint (staticcheck QF1001) rejects
			// the negated disjunction (round 4, P1).
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// ownerIn resolves host the way ByHost does (API before aux, exact
// before wildcard), over ps instead of the live registry. Auth hosts are
// not consulted: callers reject them separately.
func ownerIn(ps []*Provider, host string) *Provider {
	for _, list := range []func(*Provider) []string{
		func(p *Provider) []string { return p.APIHosts },
		func(p *Provider) []string { return p.AuxHosts },
	} {
		for _, wildcard := range []bool{false, true} {
			for _, p := range ps {
				if anyMatch(list(p), host, wildcard) {
					return p
				}
			}
		}
	}
	return nil
}

// pathsOverlap reports whether one request path could match both a wire
// route and an auth path rule on the same host. It is conservative: a
// PathContains route overlaps every prefix rule, since the rule's path
// followed by the route's substring matches both.
func pathsOverlap(r WireRoute, ap AuthPath) bool {
	rp := strings.ToLower(r.Path)
	if r.Match == PathExact {
		// AuthPathFor matches the cleaned request path, so an exact route
		// declared with a trailing slash or dot segment is compared in its
		// cleaned form (R0-10).
		rp = path.Clean(rp)
	}
	switch {
	case ap.Match == PathExact && r.Match == PathExact:
		return rp == ap.Path
	case ap.Match == PathExact && r.Match == PathPrefix:
		// A request "/v1/responses/" matches the route prefix
		// "/v1/responses/" raw and the exact rule "/v1/responses" cleaned.
		return strings.HasPrefix(ap.Path, rp) || strings.HasPrefix(ap.Path+"/", rp)
	case ap.Match == PathExact:
		return strings.Contains(ap.Path, rp)
	case r.Match == PathExact:
		return strings.HasPrefix(rp+"/", ap.Path)
	case r.Match == PathPrefix:
		return strings.HasPrefix(rp, ap.Path) || strings.HasPrefix(ap.Path, rp)
	default:
		return true
	}
}

// Validate enforces checks C0–C11 and returns every violation. C1–C7
// come from the spec; C0 and C8–C11 were added while planning (DEV-22).
func Validate(ps []*Provider, lookup PluginLookup) error {
	var errs []error
	bad := func(p *Provider, check, format string, args ...any) {
		errs = append(errs, fmt.Errorf("agentprovider: %s: %s: %s", p.ID, check, fmt.Sprintf(format, args...)))
	}
	ids := map[string]bool{}
	exactOwner := map[string]string{} // exact api/auth/aux host → provider ID
	prefixOwner := map[string]string{}

	for _, p := range ps {
		// C0: identity.
		if p.ID == "" || p.DisplayName == "" {
			bad(p, "C0", "ID and DisplayName are required")
		}
		// C0: every declared host is a lowercase hostname with no port,
		// path or trailing dot. Lookups compare against NormalizeHost of
		// the SNI, so anything else would never match.
		hosts := slices.Concat(p.APIHosts, p.AuthHosts, p.AuxHosts)
		for _, r := range p.Wire {
			hosts = append(hosts, r.Host)
		}
		for _, s := range p.Stubs {
			hosts = append(hosts, s.Host)
		}
		for _, ap := range p.AuthPaths {
			hosts = append(hosts, ap.Host)
		}
		for _, h := range hosts {
			if !validHostPattern(h) {
				bad(p, "C0", "host %q must be a lowercase hostname with no port, path or trailing dot (\"*\" only as a leading \"*.\")", h)
			}
		}
		// C4: unique IDs.
		if ids[p.ID] {
			bad(p, "C4", "duplicate provider ID")
		}
		ids[p.ID] = true

		// C1: auth hosts are exact and never overlap API hosts (any
		// provider) or exact aux hosts. Aux wildcards may cover an auth
		// host because AuthProvider always takes precedence.
		for _, a := range p.AuthHosts {
			if strings.Contains(a, "*") {
				bad(p, "C1", "auth host %q must be exact", a)
				continue
			}
			for _, q := range ps {
				for _, api := range q.APIHosts {
					if hostMatches(api, a) || strings.EqualFold(api, a) {
						bad(p, "C1", "auth host %q overlaps API host %q of %s", a, api, q.ID)
					}
				}
				for _, aux := range q.AuxHosts {
					if strings.EqualFold(aux, a) {
						bad(p, "C1", "auth host %q is also an exact aux host of %s", a, q.ID)
					}
				}
			}
		}

		// C4: no exact host claimed by two providers.
		for _, list := range [][]string{p.APIHosts, p.AuthHosts, p.AuxHosts} {
			for _, h := range list {
				k := strings.ToLower(h)
				if owner, ok := exactOwner[k]; ok && owner != p.ID {
					bad(p, "C4", "host %q already claimed by %s", h, owner)
				}
				exactOwner[k] = p.ID
			}
		}

		// C3: wire routes use a core parser and an API host of this provider.
		for _, r := range p.Wire {
			if !slices.Contains(KnownWireFormats, r.Format) {
				bad(p, "C3", "unknown wire format %q", r.Format)
			}
			if !slices.Contains(p.APIHosts, r.Host) {
				bad(p, "C3", "wire route host %q is not in APIHosts", r.Host)
			}
		}

		// C5: stubs only on this provider's auth hosts, with a responder.
		for _, s := range p.Stubs {
			if !slices.Contains(p.AuthHosts, s.Host) {
				bad(p, "C5", "stub host %q is not in AuthHosts", s.Host)
			}
			if s.Respond == nil || s.PathSuffix == "" || s.Method == "" {
				bad(p, "C5", "stub on %q needs Method, PathSuffix and Respond", s.Host)
			}
		}

		// C6: approver URL on an API host; known format; no prefix collision across providers.
		if a := p.Approver; a != nil {
			h := urlHost(a.URL)
			if !anyMatch(p.APIHosts, h, false) && !anyMatch(p.APIHosts, h, true) {
				bad(p, "C6", "approver URL host %q is not an API host", h)
			}
			if !slices.Contains(KnownWireFormats, a.Format) {
				bad(p, "C6", "approver format %q unknown", a.Format)
			}
			// A prefix that equals, extends or is extended by another
			// provider's prefix collides: ApproverFor would route some
			// models to the wrong judge (R0-12).
			for _, pre := range a.ModelPrefixes {
				for other, owner := range prefixOwner {
					if owner != p.ID && (strings.HasPrefix(pre, other) || strings.HasPrefix(other, pre)) {
						bad(p, "C6", "model prefix %q collides with %q of %s", pre, other, owner)
					}
				}
			}
			for _, pre := range a.ModelPrefixes {
				prefixOwner[pre] = p.ID
			}
		}

		// C7 + C2: owned plugin types exist; every OAuth URL the gateway
		// calls server-side (token, device, dynamic registration, and the
		// openai_device flow's AuthURL, which it POSTs to) sits on this
		// provider's auth hosts. A browser AuthURL (every other flow) is
		// opened by the operator, not called by the gateway, so it is
		// exempt (R0-08).
		for _, typ := range p.CredentialTypes {
			body, ok := lookup(config.KindCredential, typ)
			if !ok {
				bad(p, "C7", "credential type %q is not registered", typ)
				continue
			}
			fp, ok := body.(config.OAuthFlowProvider)
			if !ok {
				continue
			}
			flow := fp.OAuthFlow()
			if flow == nil {
				continue
			}
			urls := []string{flow.OAuth.TokenURL, flow.OAuth.DeviceURL, flow.OAuth.RegisterURL}
			if flow.Flow == "openai_device" {
				urls = append(urls, flow.OAuth.AuthURL)
			}
			for _, raw := range urls {
				if raw == "" {
					continue
				}
				if h := urlHost(raw); !slices.Contains(p.AuthHosts, h) {
					bad(p, "C2", "credential %q calls %q, which is not an auth host", typ, h)
				}
			}
		}
		for _, typ := range p.EndpointTypes {
			if _, ok := lookup(config.KindEndpoint, typ); !ok {
				bad(p, "C7", "endpoint type %q is not registered", typ)
			}
		}

		// C8: path-scoped auth rules (D1) sit on an exact, already
		// normalized host this provider owns that is nobody's auth host,
		// use a clean lowercase path (prefix rules end in "/" and are never
		// the whole host), match exact or by prefix, and never overlap the
		// provider's own wire routes.
		for _, ap := range p.AuthPaths {
			isAuthHost := slices.ContainsFunc(ps, func(q *Provider) bool { return slices.Contains(q.AuthHosts, ap.Host) })
			switch {
			case strings.Contains(ap.Host, "*"):
				bad(p, "C8", "auth path host %q must be exact", ap.Host)
			case ap.Host != NormalizeHost(ap.Host):
				bad(p, "C8", "auth path host %q must be lowercase and normalized", ap.Host)
			case isAuthHost:
				bad(p, "C8", "auth path host %q is a whole-host auth host already", ap.Host)
			case ownerIn(ps, ap.Host) != p:
				bad(p, "C8", "auth path host %q is not an API or aux host this provider owns", ap.Host)
			}
			want := path.Clean(ap.Path)
			switch ap.Match {
			case PathExact:
			case PathPrefix:
				want = strings.TrimSuffix(want, "/") + "/"
			default:
				bad(p, "C8", "auth path %q: match must be PathExact or PathPrefix", ap.Path)
			}
			if !strings.HasPrefix(ap.Path, "/") || ap.Path == "/" || ap.Path != strings.ToLower(ap.Path) || ap.Path != want {
				bad(p, "C8", "auth path %q must be a clean lowercase path other than \"/\" (prefix rules end in \"/\")", ap.Path)
			}
			if strings.ContainsAny(ap.Path, "%?#") {
				bad(p, "C8", "auth path %q must be a decoded path with no '%%', '?' or '#' (AuthPathFor matches decoded paths)", ap.Path)
			}
			for _, r := range p.Wire {
				if hostMatches(r.Host, ap.Host) && pathsOverlap(r, ap) {
					bad(p, "C8", "auth path %s%s overlaps wire route %s%s", ap.Host, ap.Path, r.Host, r.Path)
				}
			}
		}

		if l := p.Launcher; l != nil {
			// C9: a shim trigger (D5) needs a shim, and is a competing
			// name, so the only value it can hold is the gateway
			// placeholder.
			for _, n := range l.ShimTriggerEnv {
				if l.Shim == nil {
					bad(p, "C9", "ShimTriggerEnv %q set but Launcher.Shim is nil", n)
				}
				if strings.Contains(n, "*") || !slices.Contains(l.CompetingEnv, n) {
					bad(p, "C9", "ShimTriggerEnv %q must be an exact name listed in CompetingEnv", n)
				}
			}
			// C10: force-set names (D6) are exact and not also competing
			// (a competing name is force-set already).
			for _, n := range l.ForceSetEnv {
				if n == "" || strings.Contains(n, "*") || slices.Contains(l.CompetingEnv, n) {
					bad(p, "C10", "ForceSetEnv %q must be an exact name that is not in CompetingEnv", n)
				}
			}
			// C11: a preflight (D7) runs only for the provider's own
			// binaries, so it needs at least one.
			if l.Preflight != nil && len(l.Binaries) == 0 {
				bad(p, "C11", "Launcher.Preflight set but Launcher.Binaries is empty")
			}
		}
	}
	return errors.Join(errs...)
}
