package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/denoland/clawpatrol/internal/config"
	"github.com/denoland/clawpatrol/internal/config/plugins/credentials"
)

// grokTestFlow returns the grok_oauth flow with its token endpoint
// pointed at a fake IdP.
func grokTestFlow(idpURL string) config.OAuthIntegration {
	flow := *(&credentials.GrokOAuth{}).OAuthFlow()
	flow.OAuth.TokenURL = idpURL
	return flow
}

// grokTestRegistry opens a scratch DB and an OAuthRegistry with "grok"
// registered against idpURL and seeded with an expired a1/r1 token.
func grokTestRegistry(t *testing.T, idpURL string) (*OAuthRegistry, *sql.DB) {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	reg, err := NewOAuthRegistry(nil, db)
	if err != nil {
		t.Fatal(err)
	}
	reg.Register("grok", grokTestFlow(idpURL))
	if err := reg.Set(t.Context(), "grok", &oauth2.Token{AccessToken: "a1", RefreshToken: "r1", Expiry: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return reg, db
}

// grokPollSetup builds a webMux and a device-flow session ("dev-1") that
// polls a fake IdP at idpURL, with no database.
func grokPollSetup(t *testing.T, idpURL string) (*webMux, *oauthSession, *OAuthRegistry) {
	t.Helper()
	reg, err := NewOAuthRegistry(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	flow := grokTestFlow(idpURL)
	reg.Register("grok", flow)
	w := &webMux{g: &Gateway{oauth: reg}, sessions: map[string]*oauthSession{}}
	sess := &oauthSession{state: "s1", id: "grok", verifier: "dev-1", created: time.Now(),
		cfg: &oauth2.Config{ClientID: flow.OAuth.ClientID, Endpoint: oauth2.Endpoint{TokenURL: idpURL}}}
	w.sessions["s1"] = sess
	return w, sess, reg
}

func grokPoll(t *testing.T, w *webMux, sess *oauthSession) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	w.pollDeviceFlow(rec, httptest.NewRequest(http.MethodPost, "/api/oauth/poll", nil), sess)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("poll response %q: %v", rec.Body.String(), err)
	}
	return out
}

// TestRotatingRefreshSingleFlightPersistBeforeUse: concurrent callers of an
// expired grok credential share one refresh, and the rotated refresh token
// is in the DB before any caller holds the new access token, when the DB
// write succeeds. A failed write is logged and the rotated token stays in
// memory (pre-existing #857 behavior, see Review Focus 5 and D-R4-3).
func TestRotatingRefreshSingleFlightPersistBeforeUse(t *testing.T) {
	var refreshes atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "refresh_token" || r.PostForm.Get("refresh_token") != "r1" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("client_id") == "" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		refreshes.Add(1)
		time.Sleep(50 * time.Millisecond) // widen the race window
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a2","refresh_token":"r2","token_type":"Bearer","expires_in":3600}`))
	}))
	defer idp.Close()
	reg, db := grokTestRegistry(t, idp.URL)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := reg.Token("grok")
			if err != nil || tok != "a2" {
				t.Errorf("Token = %q, %v; want a2", tok, err)
				return
			}
			// Persist-before-use (the DB write succeeds here): by the time any
			// caller holds a2, r2 is durable.
			var stored string
			if err := db.QueryRow(`SELECT refresh_token FROM credentials WHERE id = ?`, "grok").Scan(&stored); err != nil || stored != "r2" {
				t.Errorf("stored refresh_token = %q, %v; want r2", stored, err)
			}
		}()
	}
	wg.Wait()
	if n := refreshes.Load(); n != 1 {
		t.Fatalf("refresh calls = %d, want exactly 1 (single-use rotating refresh tokens)", n)
	}
	if got := reg.RefreshToken("grok"); got != "r2" {
		t.Fatalf("RefreshToken = %q, want r2", got)
	}
}

// TestGrokOAuthTerminalRefreshMarksNeedsReauth pins locked decision 2 for
// grok_oauth on the base's #857 machinery: a grant-level rejection latches
// the credential as needing re-authorization (dashboard: needs_reauth,
// connected false, "Connect" restarts the device flow), the background
// sweep stops asking the IdP, and agent requests get no injection, so
// the placeholder goes upstream and upstream answers 401. There is never
// an agent-side fallback. D8 (user decision, review round 2): the
// request path stays #857's recovery route (claimRefresh), so this test
// pins only these three outcomes and deliberately asserts nothing about
// request-path IdP calls.
func TestGrokOAuthTerminalRefreshMarksNeedsReauth(t *testing.T) {
	var calls atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer idp.Close()
	reg, db := grokTestRegistry(t, idp.URL)
	if _, err := reg.Token("grok"); err == nil {
		t.Fatal("Token succeeded against an IdP that rejected the grant")
	}
	st := reg.Status("grok")
	if !st.NeedsReauth || st.Connected || st.Reason != "the provider rejected the refresh: invalid_grant" {
		t.Fatalf("Status = %+v; want NeedsReauth, not connected, invalid_grant reason", st)
	}
	// The background sweep starts a refresh only for a state that
	// claimRefresh hands over, so asking it directly is a synchronous,
	// deterministic check that the sweep leaves the latched credential
	// alone. Two hours on, the token is well inside the renewal window
	// and past any backoff: only the terminal latch can decline it.
	reg.mu.RLock()
	s := reg.states["grok"]
	reg.mu.RUnlock()
	for _, now := range []time.Time{time.Now(), time.Now().Add(2 * time.Hour)} {
		if _, ok := s.claimRefresh(now); ok {
			s.releaseRefresh()
			t.Fatalf("claimRefresh(%v) claimed a latched credential for a background refresh, want it declined", now)
		}
	}
	before := calls.Load()
	reg.refreshExpiring(time.Now()) // claims nothing, so starts no goroutine
	if n := calls.Load(); n != before {
		t.Fatalf("background sweep made %d IdP call(s) for a latched credential, want 0", n-before)
	}
	// The MITM path reads secrets through this store. An error here is what
	// makes it log "forwarding without injection", so the agent's
	// placeholder goes upstream unchanged.
	if sec, err := newGatewaySecretStore(db, reg).Get("grok"); err == nil {
		t.Fatalf("secret store returned %d byte(s) for a terminal credential; want an error", len(sec.Bytes))
	}
}

// TestGrokDeviceFlowPolling covers RFC 8628 polling against a fake
// auth.x.ai (spec §10.4): pending, slow_down with a new interval passed
// to the dashboard, then the token, whose refresh token the gateway keeps.
func TestGrokDeviceFlowPolling(t *testing.T) {
	replies := []string{
		`{"error":"authorization_pending"}`,
		`{"error":"slow_down","interval":10}`,
		`{"access_token":"a1","refresh_token":"r1","token_type":"Bearer","expires_in":3600}`,
	}
	var n atomic.Int32
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" || r.PostForm.Get("device_code") != "dev-1" {
			t.Errorf("poll form = %v", r.PostForm)
		}
		i := min(int(n.Add(1))-1, len(replies)-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(replies[i]))
	}))
	defer idp.Close()
	w, sess, reg := grokPollSetup(t, idp.URL)
	if out := grokPoll(t, w, sess); out["error"] != "authorization_pending" {
		t.Fatalf("poll 1 = %v, want authorization_pending", out)
	}
	if out := grokPoll(t, w, sess); out["error"] != "slow_down" || out["interval"] != float64(10) {
		t.Fatalf("poll 2 = %v, want slow_down with interval 10", out)
	}
	if out := grokPoll(t, w, sess); out["connected"] != true {
		t.Fatalf("poll 3 = %v, want connected", out)
	}
	if got := reg.RefreshToken("grok"); got != "r1" {
		t.Fatalf("RefreshToken = %q, want r1", got)
	}
}

// Terminal device-flow answers reach the dashboard as errors, with no
// credential stored.
func TestGrokDeviceFlowTerminalCodes(t *testing.T) {
	for _, code := range []string{"expired_token", "access_denied"} {
		idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
		}))
		w, sess, reg := grokPollSetup(t, idp.URL)
		out := grokPoll(t, w, sess)
		idp.Close()
		if out["error"] != code || reg.RefreshToken("grok") != "" {
			t.Fatalf("%s: poll = %v, stored refresh token %q; want the error and nothing stored", code, out, reg.RefreshToken("grok"))
		}
	}
}
