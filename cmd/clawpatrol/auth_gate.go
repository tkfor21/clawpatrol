package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// plainResponse builds a small clawpatrol-generated text response.
func plainResponse(req *http.Request, status int, msg string) *http.Response {
	return &http.Response{
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		StatusCode:    status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}, "Cache-Control": {"no-store"}},
		Body:          io.NopCloser(strings.NewReader(msg)),
		ContentLength: int64(len(msg)),
		Request:       req,
	}
}

// serveAuthGate handles an agent connection to a provider login/token
// host (invariant I12). It terminates TLS with our CA and answers every
// request locally — a declared AuthStub, or 403 — so nothing is ever
// forwarded or spliced upstream, whatever the endpoint config or
// defaults.unknown_host says. The gateway's own OAuth calls use
// http.DefaultClient and never enter this path, so dashboard login and
// token refresh are unaffected.
func (g *Gateway) serveAuthGate(c net.Conn, host string, p *agentprovider.Provider) {
	agentAddr := g.agentIPFor(c)
	certHost := agentprovider.NormalizeHost(host)
	cert, err := g.certs.mint(certHost)
	if err != nil {
		log.Printf("auth-gate mint %s: %v", certHost, err)
		return
	}
	tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}})
	if err := tc.Handshake(); err != nil {
		log.Printf("auth-gate tls handshake %s: %v", certHost, err)
		return
	}
	defer func() { _ = tc.Close() }()
	br := bufio.NewReader(tc)
	for {
		_ = tc.SetReadDeadline(time.Now().Add(60 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 1<<20))
		_ = req.Body.Close()
		resp, action, reason := authGateResponse(req, certHost, p)
		if err := g.writeAuthGateAnswer(tc, req, certHost, agentAddr, p, resp, action, reason); err != nil {
			return
		}
	}
}

// writeAuthGateAnswer sends one answer of the auth gate (I12), for a
// whole auth host or an AuthPaths rule: it adds the once-per-agent login
// hint to a deny (spec §8.2), strips auth-bearing headers exactly as the
// MITM path does, records the auth-gate event, and writes resp.
func (g *Gateway) writeAuthGateAnswer(w io.Writer, req *http.Request, host, agentAddr string, p *agentprovider.Provider, resp *http.Response, action, reason string) error {
	if action == "deny" {
		// Spec §8.2: the first gated request per agent tells the
		// operator, in the dashboard request log, where login moved.
		if _, seen := g.authGateHints.LoadOrStore(agentAddr+"|"+p.ID, struct{}{}); !seen {
			reason += "; hint: " + p.DisplayName + " login now happens in the dashboard"
		}
	}
	stripAuthResponseHeaders(resp.Header)
	stripAuthResponseHeaders(resp.Trailer)
	stripAltSvc(resp.Header)
	g.emit(Event{
		ID: newReqID(), Mode: "auth-gate", Host: host,
		Method: req.Method, Path: req.URL.Path, AgentIP: agentAddr,
		Action: action, Reason: reason, Status: strconv.Itoa(resp.StatusCode),
	})
	err := resp.Write(w)
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	return err
}

func authGateResponse(req *http.Request, host string, p *agentprovider.Provider) (*http.Response, string, string) {
	for _, s := range p.Stubs {
		if strings.EqualFold(s.Host, host) && req.Method == s.Method && strings.HasSuffix(req.URL.Path, s.PathSuffix) {
			if r := s.Respond(req, agentprovider.PublicMaterial{}); r != nil {
				return r, "synth", "auth-host stub (" + p.ID + ")"
			}
		}
	}
	msg := fmt.Sprintf("login for %s is managed by clawpatrol; connect it in the dashboard\n", p.DisplayName)
	return plainResponse(req, http.StatusForbidden, msg), "deny", "auth host gated (" + p.ID + ")"
}
