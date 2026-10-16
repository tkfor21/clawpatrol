package agentprovider

import (
	"net"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

var (
	mu        sync.RWMutex
	providers []*Provider
)

// Register adds p. Called from provider packages' init; Validate runs
// once every init has finished (see plugins/all).
func Register(p *Provider) {
	mu.Lock()
	defer mu.Unlock()
	providers = append(providers, p)
}

// All returns providers in registration order.
func All() []*Provider {
	mu.RLock()
	defer mu.RUnlock()
	return append([]*Provider(nil), providers...)
}

// Swap replaces the registry with ps and returns a func that restores
// the previous set. Test hook only: production code registers in init
// and never swaps. Callers outside this package (cmd/clawpatrol tests)
// use it to add a provider with a fixture-only property, e.g. a CAEnv.
func Swap(ps []*Provider) (restore func()) {
	mu.Lock()
	saved := providers
	providers = append([]*Provider(nil), ps...)
	mu.Unlock()
	return func() {
		mu.Lock()
		providers = saved
		mu.Unlock()
	}
}

// ByID returns the provider with the given ID, or nil.
func ByID(id string) *Provider {
	for _, p := range All() {
		if p.ID == id {
			return p
		}
	}
	return nil
}

// NormalizeHost lowercases, drops a trailing dot and any :port.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

// hostMatches: "example.com" is exact; "*.example.com" matches any
// subdomain but not the bare name.
func hostMatches(pattern, host string) bool {
	host = NormalizeHost(host)
	pattern = strings.ToLower(pattern)
	if suffix, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == pattern
}

func anyMatch(patterns []string, host string, wildcard bool) bool {
	for _, pat := range patterns {
		if strings.HasPrefix(pat, "*.") != wildcard {
			continue
		}
		if hostMatches(pat, host) {
			return true
		}
	}
	return false
}

// AuthProvider returns the provider that declares host as an auth host.
// Callers must check this before any other routing (invariant I12).
func AuthProvider(host string) *Provider {
	h := NormalizeHost(host)
	for _, p := range All() {
		for _, a := range p.AuthHosts {
			if strings.ToLower(a) == h {
				return p
			}
		}
	}
	return nil
}

// APIProvider resolves an API host: exact patterns first, then wildcards.
func APIProvider(host string) *Provider {
	if AuthProvider(host) != nil {
		return nil
	}
	ps := All()
	for _, wildcard := range []bool{false, true} {
		for _, p := range ps {
			if anyMatch(p.APIHosts, host, wildcard) {
				return p
			}
		}
	}
	return nil
}

// ByHost resolves any non-auth host: API, then aux (exact before
// wildcard at each level).
func ByHost(host string) *Provider {
	if p := APIProvider(host); p != nil {
		return p
	}
	if AuthProvider(host) != nil {
		return nil
	}
	ps := All()
	for _, wildcard := range []bool{false, true} {
		for _, p := range ps {
			if anyMatch(p.AuxHosts, host, wildcard) {
				return p
			}
		}
	}
	return nil
}

// AuthPathFor returns the provider and the AuthPath rule that gate a
// request to host with the decoded path reqPath, or (nil, nil). The path
// is cleaned (dot segments, duplicate slashes, trailing slash) and
// lowercased first, so a spelling the upstream would normalize cannot
// step around a rule (I12, D1).
func AuthPathFor(host, reqPath string) (*Provider, *AuthPath) {
	h := NormalizeHost(host)
	clean := strings.ToLower(path.Clean("/" + reqPath))
	for _, p := range All() {
		for i := range p.AuthPaths {
			ap := &p.AuthPaths[i]
			if NormalizeHost(ap.Host) != h {
				continue
			}
			switch ap.Match {
			case PathExact:
				if clean == ap.Path {
					return p, ap
				}
			case PathPrefix:
				if strings.HasPrefix(clean+"/", ap.Path) {
					return p, ap
				}
			}
		}
	}
	return nil, nil
}

// HasAuthPaths reports whether any provider declares an AuthPaths rule
// for host. A non-443 relay sees no request paths, so it refuses TLS
// whose SNI is such a host outright (I12 on relays; R2-D8).
func HasAuthPaths(host string) bool {
	h := NormalizeHost(host)
	if h == "" {
		return false
	}
	for _, p := range All() {
		for i := range p.AuthPaths {
			if NormalizeHost(p.AuthPaths[i].Host) == h {
				return true
			}
		}
	}
	return false
}

// OwnsCredentialType reports whether typ is in some provider's
// CredentialTypes. I13 turns on for such a credential whatever the host
// (D9).
func OwnsCredentialType(typ string) bool {
	return CredentialTypeOwner(typ) != ""
}

// CredentialTypeOwner returns the ID of the provider whose
// CredentialTypes lists typ, or "" when no provider owns it. An LLM judge
// with no CredentialTypes of its own refuses a credential another
// provider owns (D-R4-8 (A)).
func CredentialTypeOwner(typ string) string {
	if typ == "" {
		return ""
	}
	for _, p := range All() {
		for _, t := range p.CredentialTypes {
			if t == typ {
				return p.ID
			}
		}
	}
	return ""
}

// ByBinary resolves `clawpatrol run <argv0>` to a provider.
func ByBinary(argv0 string) *Provider {
	base := filepath.Base(argv0)
	for _, p := range All() {
		if p.Launcher == nil {
			continue
		}
		for _, b := range p.Launcher.Binaries {
			if b == base {
				return p
			}
		}
	}
	return nil
}

// WireFor returns the provider and parser for a tracked LLM request.
func WireFor(host, path string) (*Provider, WireFormat) {
	p := APIProvider(host)
	if p == nil {
		return nil, ""
	}
	for _, r := range p.Wire {
		if !hostMatches(r.Host, host) {
			continue
		}
		var ok bool
		switch r.Match {
		case PathExact:
			ok = path == r.Path
		case PathPrefix:
			ok = strings.HasPrefix(path, r.Path)
		case PathContains:
			ok = strings.Contains(path, r.Path)
		}
		if ok {
			return p, r.Format
		}
	}
	return nil, ""
}

// ApproverFor picks the provider whose approver prefix is the longest
// match for model. nil means llm_approver must deny.
func ApproverFor(model string) *Provider {
	var best *Provider
	bestLen := 0
	for _, p := range All() {
		if p.Approver == nil {
			continue
		}
		for _, pre := range p.Approver.ModelPrefixes {
			if strings.HasPrefix(model, pre) && len(pre) > bestLen {
				best, bestLen = p, len(pre)
			}
		}
	}
	return best
}

// BrowserTLS reports whether upstream dials to host need the uTLS
// Chrome fingerprint. Auth hosts are excluded: agents never reach them.
func BrowserTLS(host string) bool {
	p := ByHost(host)
	if p == nil || !p.BrowserTLS {
		return false
	}
	return !anyMatch(p.PlainTLSHosts, host, false) && !anyMatch(p.PlainTLSHosts, host, true)
}

// AllCAEnv returns every provider-declared additive CA env var name.
func AllCAEnv() []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range All() {
		if p.Launcher == nil {
			continue
		}
		for _, n := range p.Launcher.CAEnv {
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}
