package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/denoland/clawpatrol/internal/agentprovider"
)

// relayGateAuthSNI applies I12 to a non-443 relay (D3). up is already
// dialed. It reads the agent's first bytes while forwarding whatever the
// upstream sends first, so a server-first protocol (SSH, SMTP) gets its
// banner without delay. When the agent opens with a TLS record it
// reassembles the whole ClientHello, even one split across records
// (S101). A non-empty deny means the relay must close without forwarding
// anything more: the SNI names a provider auth host or an AuthPaths rule
// host (R2-D8), or the handshake does not parse (fail closed). An allowed
// ClientHello 1 is written to up here, and the upstream's first
// handshake bytes are read back; on a HelloRetryRequest, ClientHello 2 is
// peeked and gated the same way, and refused when its SNI differs from
// ClientHello 1 (R2-01, D-R4-6 (A)). Otherwise it returns the agent conn
// wrapped so the bytes it read and did not forward are replayed, how many
// upstream bytes it forwarded to the agent (forwarded), and how many
// agent bytes it wrote to up itself (sent; ClientHello 1). A nil agent
// with an empty deny means the agent broke off mid-record or a write
// failed; the caller closes the relay.
func relayGateAuthSNI(c, up net.Conn) (agent net.Conn, deny string, forwarded, sent int64) {
	return gateClientHellos(c, up, "a non-443 relay", relayGateHost)
}

// spliceGateAuthSNI applies the same ClientHello gate to a 443 splice
// (unknown_host = "passthrough", D-R4-10 (A)). handle() picked the splice
// target from peekSNI, which reads the first server_name entry of any
// type; here the strict parser refuses a mixed or duplicated list, and
// after a HelloRetryRequest ClientHello 2 must keep the SNI. Only
// provider auth hosts are refused by name: an AuthPaths rule host stays
// spliced on 443 (R2-D1).
func spliceGateAuthSNI(c, up net.Conn) (agent net.Conn, deny string, forwarded, sent int64) {
	return gateClientHellos(c, up, "443 passthrough", spliceGateHost)
}

// gateClientHellos is the ClientHello gate shared by non-443 relays and
// 443 splices (relayGateAuthSNI, spliceGateAuthSNI). where names the path
// in deny reasons; gateHost returns a deny reason for a gated SNI.
func gateClientHellos(c, up net.Conn, where string, gateHost func(string) string) (agent net.Conn, deny string, forwarded, sent int64) {
	var fwd atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 32<<10)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
				fwd.Add(int64(n))
			}
			if err != nil {
				select {
				case <-stop: // the hand-off deadline below
				default:
					// The upstream closed before the agent spoke: pass the
					// half-close on, so a client waiting for more sees it.
					if cw, ok := c.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
				}
				return
			}
		}
	}()
	handOff := func() {
		close(stop)
		_ = up.SetReadDeadline(time.Now())
		<-done
		_ = up.SetReadDeadline(time.Time{})
	}

	first := make([]byte, 1)
	if n, _ := c.Read(first); n == 0 { // blocks until the agent sends or closes
		handOff()
		return c, "", fwd.Load(), 0
	}
	// R2-02, D-R4-6 (A): Go's TLS server skips leading warning alerts, so
	// a first byte of 0x15 is a TLS candidate as well as 0x16.
	if first[0] != 0x16 && first[0] != 0x15 {
		handOff()
		return wrapPeek(c, first), "", fwd.Load(), 0
	}
	host, buf, err := peekClientHelloSNI(wrapPeek(c, first))
	handOff()
	switch {
	case errors.Is(err, errNotTLSRecord):
		// A first record that no TLS server accepts (Go: version byte
		// >= 0x10 or over 16384 bytes; OpenSSL and BoringSSL: not 0x03xx):
		// not TLS, so relay as before.
		return wrapPeek(c, buf), "", fwd.Load(), 0
	case err != nil && buf == nil:
		return nil, "", fwd.Load(), 0 // the agent broke off mid-record; bytes were consumed
	case err != nil && !errors.Is(err, errNoSNI):
		// Fail closed (S101): a TLS handshake the gate cannot read could
		// name an auth host, so it is never forwarded.
		return nil, "unparsable TLS ClientHello on " + where + " (" + err.Error() + ")", fwd.Load(), 0
	}
	if d := gateHost(host); d != "" {
		return nil, d, fwd.Load(), 0
	}
	// R2-01, D-R4-6 (A): forward ClientHello 1 and read the upstream's
	// first handshake bytes. On a HelloRetryRequest the agent sends
	// ClientHello 2, which is peeked and gated too before any of it
	// reaches up. sent reports the ClientHello 1 bytes written here, so
	// the relay's outbound byte count stays whole.
	if _, err := up.Write(buf); err != nil {
		return nil, "", fwd.Load(), 0
	}
	sent = int64(len(buf))
	// While waiting on the upstream, also read the agent's next byte, so an
	// agent that closes does not hold the relay for the whole wait. A byte
	// read here is replayed.
	var agentGone atomic.Bool
	type agentRead struct {
		b   []byte
		err error
	}
	ach := make(chan agentRead, 1)
	go func() {
		b := make([]byte, 1)
		n, err := c.Read(b)
		if n == 0 && err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			agentGone.Store(true)
			_ = up.SetReadDeadline(time.Now())
		}
		ach <- agentRead{b[:n], err}
	}()
	sh, hrr := readServerHelloPrefix(up, &agentGone)
	_ = c.SetReadDeadline(time.Now())
	ar := <-ach
	_ = c.SetReadDeadline(time.Time{})
	if len(sh) > 0 {
		if _, err := c.Write(sh); err != nil {
			return nil, "", fwd.Load(), sent
		}
		fwd.Add(int64(len(sh)))
	}
	if !hrr || agentGone.Load() {
		return wrapPeek(c, ar.b), "", fwd.Load(), sent
	}
	host2, buf2, err2 := peekClientHelloSNI(wrapPeek(c, ar.b))
	switch {
	case buf2 == nil && err2 != nil:
		return nil, "", fwd.Load(), sent
	case err2 != nil && !errors.Is(err2, errNoSNI):
		return nil, "unparsable TLS ClientHello after a HelloRetryRequest on " + where + " (" + err2.Error() + ")", fwd.Load(), sent
	case host2 != host:
		return nil, "SNI changed across a HelloRetryRequest on " + where + ": " + host + " -> " + host2, fwd.Load(), sent
	}
	if d := gateHost(host2); d != "" {
		return nil, d, fwd.Load(), sent
	}
	// No SNI, or a host with no auth host or AuthPaths rule, in both
	// ClientHellos: relay exactly as before.
	return wrapPeek(c, buf2), "", fwd.Load(), sent
}

// relayGateHost returns a deny reason when host is a provider auth host or
// an AuthPaths rule host, and "" otherwise.
func relayGateHost(host string) string {
	if p := agentprovider.AuthProvider(host); p != nil {
		return "auth host gated on a non-443 relay (" + p.ID + "): SNI " + host
	}
	if agentprovider.HasAuthPaths(host) {
		// R2-D8: a relay sees no request paths, so it cannot tell a login
		// path from a doc fetch; TLS to any AuthPaths rule host is refused.
		return "auth-path host gated on a non-443 relay: SNI " + host
	}
	return ""
}

// spliceGateHost returns a deny reason when host is a provider auth host,
// and "" otherwise. handle() already gates an auth host named in
// ClientHello 1 before any splice, so this matters for a name only the
// strict parse sees.
func spliceGateHost(host string) string {
	if p := agentprovider.AuthProvider(host); p != nil {
		return "auth host gated on 443 passthrough (" + p.ID + "): SNI " + host
	}
	return ""
}

// hrrRandom is the ServerHello.random of a HelloRetryRequest (RFC 8446
// §4.1.3).
var hrrRandom = []byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// readServerHelloPrefix reads the upstream's records until the first 38
// bytes of its first handshake message are known (type, length, version,
// random), and reports whether it is a HelloRetryRequest. It returns every
// byte it read, to be forwarded to the agent. It waits at most
// relayPeekTimeout for a silent upstream, and stops at once when the
// agent goes away.
func readServerHelloPrefix(up net.Conn, agentGone *atomic.Bool) ([]byte, bool) {
	_ = up.SetReadDeadline(time.Now().Add(relayPeekTimeout))
	if agentGone.Load() {
		_ = up.SetReadDeadline(time.Now())
	}
	defer func() { _ = up.SetReadDeadline(time.Time{}) }()
	var raw, msg []byte
	for len(msg) < 38 && len(raw) < maxClientHelloBytes {
		hdr := make([]byte, 5)
		n, err := io.ReadFull(up, hdr)
		raw = append(raw, hdr[:n]...)
		if err != nil || hdr[0] != 0x16 {
			return raw, false
		}
		rec := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		n, err = io.ReadFull(up, rec)
		raw = append(raw, rec[:n]...)
		if err != nil {
			return raw, false
		}
		msg = append(msg, rec...)
	}
	return raw, len(msg) >= 38 && msg[0] == 0x02 && bytes.Equal(msg[6:38], hrrRandom)
}

var (
	errNotTLSRecord = errors.New("not a TLS record")
	errNoSNI        = errors.New("no SNI")
)

// maxClientHelloBytes bounds how much the relay gate buffers while it
// reassembles a ClientHello split across TLS records.
const maxClientHelloBytes = 64 << 10

// relayPeekTimeout bounds how long the relay gate waits for a whole
// ClientHello, and for the upstream's first handshake bytes after
// ClientHello 1. A var so tests can shorten it.
var relayPeekTimeout = 10 * time.Second

// peekClientHelloSNI reads TLS handshake records from c until the first
// handshake message (the ClientHello) is complete, so a ClientHello split
// across several records (openssl -max_send_frag, or any TLS stack the
// agent controls) is read whole. Up to 16 leading alert or CCS records of
// at most 2 bytes are skipped: Go's server drops warning alerts before
// the ClientHello, and a TLS 1.3 client sends a CCS before ClientHello 2
// (R2-01, R2-02). It returns the SNI and every byte it read. buf is nil
// only when c broke off mid-record. peekSNI (main.go:244) stays unchanged
// for handle(); it reads one record only.
func peekClientHelloSNI(c net.Conn) (string, []byte, error) {
	_ = c.SetReadDeadline(time.Now().Add(relayPeekTimeout))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()

	var raw, msg []byte
	need := -1 // handshake message length incl. its 4-byte header, once known
	skipped := 0
	for need < 0 || len(msg) < need {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return "", nil, err // broke off mid-header
		}
		raw = append(raw, hdr...)
		recLen := int(hdr[3])<<8 | int(hdr[4])
		// R2-02, D-R4-6 (A): Go accepts any record version below 0x1000
		// before it has negotiated one (crypto/tls conn.go, "first record
		// does not look like a TLS handshake"), and rejects over 16 KiB of
		// plaintext. Only a first record outside that is "not TLS";
		// OpenSSL and BoringSSL need 0x03xx, which is inside it.
		if len(raw) == 5 && (hdr[1] >= 0x10 || recLen > 16384) {
			return "", raw, errNotTLSRecord
		}
		if hdr[1] >= 0x10 {
			return "", raw, errors.New("bad record version in a continuation record")
		}
		if len(msg) == 0 && (hdr[0] == 0x15 || hdr[0] == 0x14) && recLen <= 2 && skipped < 16 {
			skipped++
			rec := make([]byte, recLen)
			if _, err := io.ReadFull(c, rec); err != nil {
				return "", nil, err
			}
			raw = append(raw, rec...)
			continue
		}
		if hdr[0] != 0x16 {
			return "", raw, errors.New("non-handshake record before the ClientHello ended")
		}
		if recLen == 0 || recLen > 16384 {
			return "", raw, errors.New("bad TLS record length")
		}
		if len(raw)+recLen > maxClientHelloBytes {
			return "", raw, errors.New("ClientHello larger than 64 KiB")
		}
		rec := make([]byte, recLen)
		if _, err := io.ReadFull(c, rec); err != nil {
			return "", nil, err
		}
		raw = append(raw, rec...)
		msg = append(msg, rec...)
		if need < 0 && len(msg) >= 4 {
			if msg[0] != 0x01 {
				return "", raw, errors.New("not ClientHello")
			}
			need = 4 + (int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3]))
			if need > maxClientHelloBytes {
				return "", raw, errors.New("ClientHello larger than 64 KiB")
			}
		}
	}
	host, err := clientHelloSNI(msg[:need])
	return host, raw, err
}

// clientHelloSNI parses the server_name extension out of one complete
// ClientHello handshake message (type byte first). The field walk is the
// one peekSNI uses on its single record. It refuses a server_name
// extension that is duplicated, holds more than one entry, an entry of
// another type, or a name with a byte outside 0x21–0x7e (R2-03).
func clientHelloSNI(p []byte) (string, error) {
	if len(p) < 38 || p[0] != 0x01 {
		return "", errors.New("not ClientHello")
	}
	p = p[38:]
	if len(p) < 1 {
		return "", errors.New("truncated")
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return "", errors.New("truncated sid")
	}
	p = p[sidLen:]
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen+1 {
		return "", errors.New("truncated cs")
	}
	p = p[csLen:]
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return "", errors.New("truncated cm")
	}
	p = p[cmLen:]
	if len(p) == 0 {
		return "", errNoSNI // a ClientHello with no extensions block
	}
	if len(p) < 2 {
		return "", errors.New("truncated ext")
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < extLen {
		return "", errors.New("truncated ext")
	}
	exts := p[:extLen]
	sni, seen := "", false
	for len(exts) >= 4 {
		t := int(exts[0])<<8 | int(exts[1])
		l := int(exts[2])<<8 | int(exts[3])
		exts = exts[4:]
		if l > len(exts) {
			return "", errors.New("truncated ext body")
		}
		if t == 0x00 {
			// R2-03: exactly one server_name extension holding exactly one
			// host_name entry of hostname bytes; anything else is refused.
			// Go's server takes the first host_name entry of a mixed list,
			// so a leading entry of another type must not hide it.
			if seen {
				return "", errors.New("duplicate server_name extension")
			}
			seen = true
			body := exts[:l]
			if len(body) < 2 || int(body[0])<<8|int(body[1]) != len(body)-2 {
				return "", errors.New("bad sni")
			}
			list := body[2:]
			count := 0
			for len(list) > 0 {
				if len(list) < 3 {
					return "", errors.New("bad sni")
				}
				n := int(list[1])<<8 | int(list[2])
				if 3+n > len(list) {
					return "", errors.New("truncated sni name")
				}
				if list[0] != 0 {
					return "", fmt.Errorf("server_name entry of type %d", list[0])
				}
				count++
				if count > 1 {
					return "", errors.New("more than one server_name entry")
				}
				for _, b := range list[3 : 3+n] {
					if b <= 0x20 || b >= 0x7f {
						return "", errors.New("non-hostname byte in server_name")
					}
				}
				sni = string(list[3 : 3+n])
				list = list[3+n:]
			}
			if count == 0 {
				return "", errors.New("empty server_name list")
			}
		}
		exts = exts[l:]
	}
	if seen {
		return sni, nil
	}
	return "", errNoSNI
}
