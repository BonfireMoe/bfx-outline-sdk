// Copyright 2026 The Outline Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package dnstt provides a [transport.StreamDialer] that tunnels TCP traffic
// over a DNS resolver using the dnstt protocol (KCP + smux over Noise_NK,
// transported via DoH, DoT, or plain-UDP DNS).
//
// dnstt is a point-to-point pipe: the destination address passed to DialStream
// is ignored; the dnstt server forwards every connection to whatever local
// address it has been configured for (typically a Shadowsocks or SOCKS server).
//
// Upstream reference: https://www.bamsoftware.com/git/dnstt.git
package dnstt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	sdkdns "golang.getoutline.org/sdk/dns"
	"golang.getoutline.org/sdk/transport"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// idleTimeout is the smux session keep-alive timeout. It matches dnstt's
// upstream default so streams die together with idle sessions.
const idleTimeout = 2 * time.Minute

// TransportKind selects how the dnstt tunnel reaches its DNS resolver.
type TransportKind int

const (
	// TransportInvalid is the zero value and indicates an unconfigured transport.
	TransportInvalid TransportKind = iota
	// TransportDoH sends DNS messages over HTTPS (RFC 8484).
	TransportDoH
	// TransportDoT sends DNS messages over TLS (RFC 7858).
	TransportDoT
	// TransportUDP sends DNS messages over plain UDP.
	TransportUDP
	// TransportResolver tunnels DNS messages through the [sdkdns.Resolver] in
	// Config.Resolver rather than opening dnstt's own connection to a resolver.
	// This lets dnstt reuse a resolver selected elsewhere (e.g. the resolver the
	// smart dialer chose from its config's "dns" list).
	TransportResolver
)

// Config configures a [StreamDialer].
//
// Exactly one of DoHURL, DoTAddr, or UDPAddr must be non-empty, matching Kind.
type Config struct {
	// Kind selects the underlying DNS transport.
	Kind TransportKind
	// Domain is the tunnel root domain operated by the dnstt server, e.g.
	// "t.example.com".
	Domain string
	// PubKey is the 32-byte X25519 Noise static public key of the dnstt server.
	PubKey []byte
	// DoHURL is the DoH endpoint, e.g. "https://resolver.example/dns-query".
	DoHURL string
	// DoTAddr is the DoT host:port, e.g. "resolver.example:853".
	DoTAddr string
	// UDPAddr is the plain-UDP DNS resolver host:port, e.g. "8.8.8.8:53".
	UDPAddr string
	// Resolver, when set with Kind == TransportResolver, is used as the DNS
	// transport: dnstt tunnels its DNS messages (TXT queries under Domain)
	// through this resolver instead of dialing DoHURL/DoTAddr/UDPAddr directly.
	// It lets dnstt reuse a resolver configured elsewhere.
	Resolver sdkdns.Resolver
}

// dnsNameCapacity computes how many bytes are available for encoded data in a
// DNS QNAME after subtracting the tunnel domain (and base32-encoding overhead).
// Mirrors dnstt-client's upstream helper of the same name.
func dnsNameCapacity(domain dns.Name) int {
	capacity := 255
	capacity -= 1 // null terminator
	for _, label := range domain {
		capacity -= len(label) + 1
	}
	// Each label may be up to 63 bytes long and requires 64 bytes to encode.
	capacity = capacity * 63 / 64
	// Base32 expands every 5 bytes to 8.
	capacity = capacity * 5 / 8
	return capacity
}

// StreamDialer is a [transport.StreamDialer] that funnels every DialStream call
// through a single, lazily-established dnstt session shared across the dialer.
//
// The dialer is safe for concurrent use. The underlying session is rebuilt on
// demand if the previous one dies.
type StreamDialer struct {
	cfg    Config
	domain dns.Name

	mu       sync.Mutex
	sess     *smux.Session
	closeFns []func() error
}

// NewStreamDialer validates cfg and returns a [StreamDialer]. The session is
// not yet established; the first DialStream call opens it.
func NewStreamDialer(cfg Config) (*StreamDialer, error) {
	if cfg.Domain == "" {
		return nil, errors.New("dnstt: domain is required")
	}
	if len(cfg.PubKey) != noise.KeyLen {
		return nil, fmt.Errorf("dnstt: pubkey must be %d bytes, got %d", noise.KeyLen, len(cfg.PubKey))
	}
	domain, err := dns.ParseName(cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("dnstt: invalid domain %q: %w", cfg.Domain, err)
	}
	switch cfg.Kind {
	case TransportDoH:
		if cfg.DoHURL == "" {
			return nil, errors.New("dnstt: doh URL is required for DoH transport")
		}
	case TransportDoT:
		if cfg.DoTAddr == "" {
			return nil, errors.New("dnstt: dot address is required for DoT transport")
		}
	case TransportUDP:
		if cfg.UDPAddr == "" {
			return nil, errors.New("dnstt: udp address is required for UDP transport")
		}
	case TransportResolver:
		if cfg.Resolver == nil {
			return nil, errors.New("dnstt: resolver is required for resolver transport")
		}
	default:
		return nil, errors.New("dnstt: transport kind is required (doh/dot/udp/resolver)")
	}
	return &StreamDialer{cfg: cfg, domain: domain}, nil
}

// DialStream opens a fresh multiplexed stream over the shared dnstt session.
// addr is ignored: dnstt is a point-to-point pipe whose far end is fixed at the
// server's configuration.
func (d *StreamDialer) DialStream(ctx context.Context, _ string) (transport.StreamConn, error) {
	sess, err := d.session(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := sess.OpenStream()
	if err != nil {
		// If OpenStream failed because the session died, force a reconnect on the
		// next call so callers do not keep hitting the same dead session.
		d.mu.Lock()
		if d.sess == sess {
			d.sess = nil
		}
		d.mu.Unlock()
		return nil, fmt.Errorf("dnstt: open stream: %w", err)
	}
	return &streamConn{Stream: stream}, nil
}

// Close tears down the underlying session and any DNS transports.
func (d *StreamDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	if d.sess != nil {
		if err := d.sess.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		d.sess = nil
	}
	for _, fn := range d.closeFns {
		if err := fn(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	d.closeFns = nil
	return firstErr
}

func (d *StreamDialer) session(ctx context.Context) (*smux.Session, error) {
	d.mu.Lock()
	if d.sess != nil && !d.sess.IsClosed() {
		s := d.sess
		d.mu.Unlock()
		return s, nil
	}
	// Drop any previous (now-dead) session before re-establishing.
	if d.sess != nil {
		d.sess.Close()
		d.sess = nil
	}
	d.mu.Unlock()

	// Session setup may block on network I/O; perform it outside the lock and
	// race with ctx.
	type result struct {
		sess     *smux.Session
		closeFns []func() error
		err      error
	}
	done := make(chan result, 1)
	go func() {
		sess, closeFns, err := d.dialSession()
		done <- result{sess, closeFns, err}
	}()

	select {
	case <-ctx.Done():
		// We do not abort the goroutine — it owns I/O state we cannot safely
		// interrupt mid-handshake. Whatever it returns will be cleaned up by the
		// next caller via Close.
		go func() {
			r := <-done
			if r.err == nil {
				r.sess.Close()
				for _, fn := range r.closeFns {
					_ = fn()
				}
			}
		}()
		return nil, ctx.Err()
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		d.mu.Lock()
		if d.sess != nil && !d.sess.IsClosed() {
			// Another caller raced us and won; discard ours.
			existing := d.sess
			d.mu.Unlock()
			r.sess.Close()
			for _, fn := range r.closeFns {
				_ = fn()
			}
			return existing, nil
		}
		d.sess = r.sess
		d.closeFns = append(d.closeFns, r.closeFns...)
		d.mu.Unlock()
		return r.sess, nil
	}
}

func (d *StreamDialer) dialSession() (*smux.Session, []func() error, error) {
	dnsTransport, remoteAddr, closeTransport, err := d.openTransport()
	if err != nil {
		return nil, nil, err
	}
	pconn := newDNSPacketConn(dnsTransport, remoteAddr, d.domain)

	mtu := dnsNameCapacity(d.domain) - 8 - 1 - numPadding - 1
	if mtu < 80 {
		pconn.Close()
		closeTransport()
		return nil, nil, fmt.Errorf("dnstt: domain %s leaves only %d bytes for payload", d.cfg.Domain, mtu)
	}

	conn, err := kcp.NewConn2(remoteAddr, nil, 0, 0, pconn)
	if err != nil {
		pconn.Close()
		closeTransport()
		return nil, nil, fmt.Errorf("dnstt: open KCP: %w", err)
	}
	conn.SetStreamMode(true)
	// nc=1 disables KCP's dynamic congestion window, leaving only the static
	// windows below.
	conn.SetNoDelay(0, 0, 0, 1)
	conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
	if rc := conn.SetMtu(mtu); !rc {
		conn.Close()
		pconn.Close()
		closeTransport()
		return nil, nil, fmt.Errorf("dnstt: SetMtu(%d) rejected", mtu)
	}

	rw, err := noise.NewClient(conn, d.cfg.PubKey)
	if err != nil {
		conn.Close()
		pconn.Close()
		closeTransport()
		return nil, nil, fmt.Errorf("dnstt: Noise handshake: %w", err)
	}

	smuxCfg := smux.DefaultConfig()
	smuxCfg.Version = 2
	smuxCfg.KeepAliveTimeout = idleTimeout
	smuxCfg.MaxStreamBuffer = 1 * 1024 * 1024 // default is 65536
	sess, err := smux.Client(rw, smuxCfg)
	if err != nil {
		conn.Close()
		pconn.Close()
		closeTransport()
		return nil, nil, fmt.Errorf("dnstt: open smux: %w", err)
	}
	closeFns := []func() error{
		func() error { return sess.Close() },
		func() error { return conn.Close() },
		func() error { return pconn.Close() },
		func() error { return closeTransport() },
	}
	return sess, closeFns, nil
}

// openTransport opens the underlying DNS transport (DoH, DoT, or UDP) and
// returns it together with the resolver address to which DNS messages should
// be sent. closeFn releases the transport's network resources.
func (d *StreamDialer) openTransport() (net.PacketConn, net.Addr, func() error, error) {
	switch d.cfg.Kind {
	case TransportDoH:
		// Use a plain http.Transport. Users who want uTLS camouflage can wrap the
		// dnstt:// scheme inside something else if needed.
		rt := http.DefaultTransport.(*http.Transport).Clone()
		rt.Proxy = nil
		pc := newDoHPacketConn(rt, d.cfg.DoHURL, 32)
		return pc, turbotunnel.DummyAddr{}, func() error { return pc.Close() }, nil
	case TransportDoT:
		pc, err := newDoTPacketConn(d.cfg.DoTAddr, nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dnstt: dial DoT: %w", err)
		}
		return pc, turbotunnel.DummyAddr{}, func() error { return pc.Close() }, nil
	case TransportUDP:
		addr, err := net.ResolveUDPAddr("udp", d.cfg.UDPAddr)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dnstt: resolve UDP %q: %w", d.cfg.UDPAddr, err)
		}
		pc, err := net.ListenUDP("udp", nil)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("dnstt: listen UDP: %w", err)
		}
		return pc, addr, func() error { return pc.Close() }, nil
	case TransportResolver:
		pc := newResolverPacketConn(d.cfg.Resolver, resolverNumSenders)
		return pc, turbotunnel.DummyAddr{}, func() error { return pc.Close() }, nil
	default:
		return nil, nil, nil, errors.New("dnstt: unsupported transport kind")
	}
}

// streamConn wraps a smux.Stream into a [transport.StreamConn].
//
// smux streams are full-duplex but do not natively expose CloseRead / CloseWrite;
// we approximate the half-close contract by ignoring CloseRead (smux delivers
// EOF when the peer closes its write side) and treating CloseWrite as the
// terminal write — a subsequent Close still releases the stream.
type streamConn struct {
	*smux.Stream
}

func (s *streamConn) CloseRead() error {
	// NOTE: smux v1 streams expose no separate read-shutdown; we keep the read
	// side open until Close. This is consistent with how net.Pipe and similar
	// in-memory full-duplex streams handle CloseRead.
	return nil
}

func (s *streamConn) CloseWrite() error {
	// NOTE: smux v1 does not provide half-close on writes either. Closing the
	// whole stream is the closest available behaviour and matches what the
	// upstream dnstt-client does when its local TCP peer half-closes.
	return s.Stream.Close()
}

var (
	_ transport.StreamConn = (*streamConn)(nil)
	_ io.ReadWriteCloser   = (*streamConn)(nil)
)
