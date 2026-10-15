package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
)

func TestNewStateBodyEncodingAndPublicClient(t *testing.T) {
	jsonState := newState(&OAuthIntegration{ID: "a", OAuth: config.OAuthConfig{
		TokenURL: "https://idp.example.test/token", BodyEncoding: "json"}}, nil)
	jsonState.setToken(&oauth2.Token{AccessToken: "x", RefreshToken: "r", Expiry: time.Now().Add(time.Hour)})
	if jsonState.bodyEncoding != "json" {
		t.Fatalf("bodyEncoding = %q, want json", jsonState.bodyEncoding)
	}
	pub := newState(&OAuthIntegration{ID: "b", OAuth: config.OAuthConfig{
		TokenURL: "https://idp.example.test/token", PublicClient: true}}, nil)
	if pub.cfg.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("AuthStyle = %v, want AuthStyleInParams", pub.cfg.Endpoint.AuthStyle)
	}
}

// rotatingIDP answers refresh_token=r1 with a2/r2 and rejects any other
// refresh token as invalid_grant (a spent single-use token). hold, when
// non-nil, blocks the successful answer until it is closed.
func rotatingIDP(t *testing.T, calls *atomic.Int32, hold chan struct{}) *httptest.Server {
	t.Helper()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "r1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		calls.Add(1)
		if hold != nil {
			<-hold
		}
		_, _ = w.Write([]byte(`{"access_token":"a2","refresh_token":"r2","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(idp.Close)
	return idp
}

func TestRefreshTokenAccessorTracksRotation(t *testing.T) {
	var calls atomic.Int32
	idp := rotatingIDP(t, &calls, nil)
	r, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Register("rot", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: idp.URL, PublicClient: true}})
	if err := r.Set(t.Context(), "rot", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if got := r.RefreshToken("rot"); got != "r1" {
		t.Fatalf("RefreshToken before refresh = %q, want r1", got)
	}
	// Refresh through the token source, not Set: the accessor must follow
	// a rotation the IdP performs.
	if tok, err := r.Token("rot"); err != nil || tok != "a2" {
		t.Fatalf("Token = %q, %v; want a2", tok, err)
	}
	if got := r.RefreshToken("rot"); got != "r2" {
		t.Fatalf("RefreshToken after refresh = %q, want r2", got)
	}
	if got := r.RefreshToken("missing"); got != "" {
		t.Fatalf("RefreshToken(missing) = %q, want empty", got)
	}
}

// TestReloadDuringRefreshKeepsRotatedToken pins DEV-17: a policy reload
// (registerOAuthCredentials → LoadFromDB) while a rotating refresh is in
// flight must not drop the rotated token or replay the spent one.
func TestReloadDuringRefreshKeepsRotatedToken(t *testing.T) {
	var calls atomic.Int32
	hold := make(chan struct{})
	idp := rotatingIDP(t, &calls, hold)
	db, err := OpenDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	r, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatal(err)
	}
	r.Register("rot", OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: idp.URL, PublicClient: true}})
	if err := r.Set(t.Context(), "rot", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 1)
	go func() {
		tok, _ := r.Token("rot")
		got <- tok
	}()
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("refresh never reached the IdP")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := r.LoadFromDB(); err != nil { // the policy reload, mid-refresh
		t.Fatal(err)
	}
	close(hold)
	if tok := <-got; tok != "a2" {
		t.Fatalf("Token = %q, want a2", tok)
	}
	if rt := r.RefreshToken("rot"); rt != "r2" {
		t.Fatalf("RefreshToken = %q, want r2 (the rotated token was dropped)", rt)
	}
	var stored string
	if err := db.QueryRow(`SELECT refresh_token FROM credentials WHERE id = ?`, "rot").Scan(&stored); err != nil || stored != "r2" {
		t.Fatalf("stored refresh_token = %q, %v; want r2", stored, err)
	}
	if st := r.Status("rot"); st.NeedsReauth || !st.Connected {
		t.Fatalf("Status = %+v, want connected", st)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("IdP refreshes = %d, want 1", n)
	}
}

func TestDeviceFlowSendsExtraParams(t *testing.T) {
	var got url.Values
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		got = r.PostForm
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"device_code":"d","user_code":"ABCD-EFGH","verification_uri":"https://idp.example.test/device","expires_in":600,"interval":5}`))
	}))
	defer idp.Close()
	w := &webMux{sessions: map[string]*oauthSession{}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/oauth/start", nil)
	w.startDeviceFlow(rec, req, "grok", &OAuthIntegration{OAuth: config.OAuthConfig{
		ClientID: "client-1", DeviceURL: idp.URL, TokenURL: idp.URL,
		Scopes: []string{"openid", "offline_access"}, ExtraParams: map[string]string{"referrer": "grok-build"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if got.Get("referrer") != "grok-build" || got.Get("client_id") != "client-1" || got.Get("scope") != "openid offline_access" {
		t.Fatalf("device-code form = %v", got)
	}
}

// TestReloadRebuildsOnFlowChange pins DEV-17's other half: a reload
// whose flow config changed rebuilds the state, so a new token endpoint,
// client or encoding takes effect at once (R1-06).
func TestReloadRebuildsOnFlowChange(t *testing.T) {
	base := config.OAuthConfig{ClientID: "c", ClientSecret: "s", TokenURL: "https://idp.example.test/token", Scopes: []string{"a"}}
	cases := []struct {
		name   string
		change func(*OAuthIntegration)
		check  func(*oauthState) bool
	}{
		{"client secret", func(it *OAuthIntegration) { it.OAuth.ClientSecret = "s2" }, func(s *oauthState) bool { return s.cfg.ClientSecret == "s2" }},
		{"token url", func(it *OAuthIntegration) { it.OAuth.TokenURL = "https://idp2.example.test/token" }, func(s *oauthState) bool { return s.cfg.Endpoint.TokenURL == "https://idp2.example.test/token" }},
		{"scopes", func(it *OAuthIntegration) { it.OAuth.Scopes = []string{"a", "b"} }, func(s *oauthState) bool { return slices.Equal(s.cfg.Scopes, []string{"a", "b"}) }},
		{"public client", func(it *OAuthIntegration) { it.OAuth.PublicClient = true }, func(s *oauthState) bool { return s.cfg.Endpoint.AuthStyle == oauth2.AuthStyleInParams }},
		// Prefix pinned to "Bearer " so only the header changes; otherwise the
		// derived prefix also flips and the prefix compare masks T8F-05a.
		{"header", func(it *OAuthIntegration) { it.Header = "X-Token"; it.Prefix = "Bearer " }, func(s *oauthState) bool { return s.header == "X-Token" }},
		{"prefix", func(it *OAuthIntegration) { it.Prefix = "Token " }, func(s *oauthState) bool { return s.prefix == "Token " }},
		{"flow", func(it *OAuthIntegration) { it.Flow = "device" }, func(s *oauthState) bool { return s.flow == "device" }},
		{"body encoding", func(it *OAuthIntegration) { it.OAuth.BodyEncoding = "json" }, func(s *oauthState) bool { return s.bodyEncoding == "json" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := OpenDB(filepath.Join(t.TempDir(), "t.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			r, err := NewOAuthRegistry(nil, db)
			if err != nil {
				t.Fatal(err)
			}
			r.Register("rot", OAuthIntegration{OAuth: base})
			if err := r.Set(t.Context(), "rot", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			prev := r.get("rot")
			next := OAuthIntegration{OAuth: base}
			next.OAuth.Scopes = slices.Clone(base.Scopes)
			tc.change(&next)
			r.Register("rot", next)
			if err := r.LoadFromDB(); err != nil {
				t.Fatal(err)
			}
			s := r.get("rot")
			if s == prev || !tc.check(s) {
				t.Fatalf("reload kept the old state = %v, new state carries the change = %v; want a rebuilt state", s == prev, tc.check(s))
			}
		})
	}
}

// A live state with no token never shadows a stored row (R1-06).
func TestReloadLoadsRowOverEmptyLiveState(t *testing.T) {
	db, err := OpenDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	it := OAuthIntegration{OAuth: config.OAuthConfig{ClientID: "c", TokenURL: "https://idp.example.test/token"}}
	a, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatal(err)
	}
	a.Register("rot", it)
	if err := a.Set(t.Context(), "rot", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	b, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatal(err)
	}
	b.Register("rot", it)
	b.putState("rot", newState(b.Integration("rot"), db)) // live, but holds no token
	if err := b.LoadFromDB(); err != nil {
		t.Fatal(err)
	}
	if tok, err := b.Token("rot"); err != nil || tok != "a1" {
		t.Fatalf("Token = %q, %v; want a1 from the stored row", tok, err)
	}
}

// TestAnthropicFlowRefreshSendsJSON drives the real Anthropic flow
// declaration through newState to a refresh: the body must be JSON, or
// Anthropic answers "Invalid request format" and every refresh fails
// (R1-07).
func TestAnthropicFlowRefreshSendsJSON(t *testing.T) {
	seen := make(chan [2]string, 1)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GrantType string `json:"grant_type"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		seen <- [2]string{r.Header.Get("Content-Type"), body.GrantType}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a2","refresh_token":"r2","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(idp.Close)
	flow := (&credentials.AnthropicOAuthSubscription{}).OAuthFlow()
	flow.OAuth.TokenURL = idp.URL
	s := newState(flow, nil)
	s.setToken(&oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(-time.Minute)})
	if _, err := s.source.Token(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	got := <-seen
	if !strings.HasPrefix(got[0], "application/json") || got[1] != "refresh_token" {
		t.Fatalf("refresh sent Content-Type %q, grant_type %q; want application/json and refresh_token", got[0], got[1])
	}
}

func TestPKCEStartCarriesBodyEncoding(t *testing.T) {
	w := &webMux{sessions: map[string]*oauthSession{}}
	sess := w.newPKCESessionForTest(t, &OAuthIntegration{OAuth: config.OAuthConfig{
		ClientID: "c", AuthURL: "https://idp.example.test/authorize",
		TokenURL: "https://idp.example.test/token", BodyEncoding: "json",
	}})
	if sess.bodyEncoding != "json" {
		t.Fatalf("PKCE session bodyEncoding = %q, want json", sess.bodyEncoding)
	}
	pub := w.newPKCESessionForTest(t, &OAuthIntegration{OAuth: config.OAuthConfig{
		ClientID: "c", AuthURL: "https://idp.example.test/authorize",
		TokenURL: "https://idp.example.test/token", PublicClient: true,
	}})
	if pub.cfg.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatalf("PKCE session AuthStyle = %v, want AuthStyleInParams for a public client", pub.cfg.Endpoint.AuthStyle)
	}
}

func (w *webMux) newPKCESessionForTest(t *testing.T, flow *OAuthIntegration) *oauthSession {
	t.Helper()
	_, state := w.startPKCEFlow("pkce", flow)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.sessions[state]
}
