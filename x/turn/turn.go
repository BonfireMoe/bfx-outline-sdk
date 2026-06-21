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

// Package turn provides a [transport.PacketListener] (and through
// [transport.PacketListenerDialer] a [transport.PacketDialer]) that tunnels
// UDP packets through a TURN relay (RFC 5766 / 8656). The data path can
// optionally be wrapped in DTLS for confidentiality and to look like WebRTC
// media to in-path filters.
//
// The TURN client is built on github.com/pion/turn/v2; DTLS, when enabled,
// uses github.com/pion/dtls/v2.
//
// The pipeline is adapted from github.com/samosvalishe/free-turn-proxy's
// internal turndial and dtlsdial packages, translated to the pion v2 APIs
// already pinned by the outline-sdk x module.
package turn

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v2"
	dtlsselfsign "github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/turn/v2"
	"golang.getoutline.org/sdk/transport"
)

// Default timeouts for TURN dial and DTLS handshake. Picked to match
// free-turn-proxy's defaults so behaviour against censored networks is similar.
const (
	defaultDialTimeout      = 5 * time.Second
	defaultHandshakeTimeout = 10 * time.Second
)

// Config configures a [PacketListener]. ServerAddress, Username and Password
// are required. Peer is also required and identifies the single peer the
// allocation will be permissioned to talk to.
type Config struct {
	// ServerAddress is the TURN server address in "host:port" form.
	ServerAddress string
	// Username and Password are the long-term TURN credentials.
	Username string
	Password string
	// Realm is the optional authentication realm. The server's realm is
	// usually discovered by the client on a 401 challenge, so this field is
	// rarely needed.
	Realm string
	// Peer is the UDP address of the peer (the far end of the tunnel) that the
	// TURN allocation will create a permission for. All WriteTo calls on the
	// returned [net.PacketConn] are routed to this peer regardless of the
	// address the caller passes; reads come back via the relay.
	Peer *net.UDPAddr
	// TCP, if true, transports the TURN signalling and data over TCP instead of
	// UDP (via [turn.NewSTUNConn]). TURN-over-TCP is useful when censorship
	// blocks UDP outright.
	TCP bool
	// DTLS, if true, performs a DTLS handshake over the relay data path before
	// returning the conn. The DTLS layer uses a freshly-generated self-signed
	// certificate and InsecureSkipVerify=true: it is here for obfuscation and
	// to make the flow look like WebRTC media, not as an authenticated channel.
	DTLS bool
	// DialTimeout caps the TCP dial when TCP is true. Zero means
	// [defaultDialTimeout].
	DialTimeout time.Duration
	// HandshakeTimeout caps the DTLS handshake when DTLS is true. Zero means
	// [defaultHandshakeTimeout].
	HandshakeTimeout time.Duration
}

// PacketListener is a [transport.PacketListener] backed by a TURN relay.
//
// Each ListenPacket call opens a fresh TURN allocation, creates a permission
// for the configured peer, and returns a [net.PacketConn] tied to the peer.
// Closing the returned PacketConn tears down the allocation, the TURN client,
// and the underlying network conn.
type PacketListener struct {
	cfg Config
}

var _ transport.PacketListener = (*PacketListener)(nil)

// NewPacketListener validates cfg and returns a [PacketListener].
func NewPacketListener(cfg Config) (*PacketListener, error) {
	if cfg.ServerAddress == "" {
		return nil, errors.New("turn: server address is required")
	}
	if cfg.Username == "" || cfg.Password == "" {
		return nil, errors.New("turn: username and password are required")
	}
	if cfg.Peer == nil {
		return nil, errors.New("turn: peer is required")
	}
	if _, _, err := net.SplitHostPort(cfg.ServerAddress); err != nil {
		return nil, fmt.Errorf("turn: parse server address: %w", err)
	}
	return &PacketListener{cfg: cfg}, nil
}

// ListenPacket implements [transport.PacketListener].ListenPacket.
func (l *PacketListener) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	// 1. Set up the transport to the TURN server.
	turnUDPAddr, err := net.ResolveUDPAddr("udp", l.cfg.ServerAddress)
	if err != nil {
		return nil, fmt.Errorf("turn: resolve server: %w", err)
	}
	turnServerAddr := turnUDPAddr.String()

	var turnConn net.PacketConn
	var closeTransport func() error
	if l.cfg.TCP {
		timeout := l.cfg.DialTimeout
		if timeout == 0 {
			timeout = defaultDialTimeout
		}
		dctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		var d net.Dialer
		tcpConn, derr := d.DialContext(dctx, "tcp", turnServerAddr)
		if derr != nil {
			return nil, fmt.Errorf("turn: dial TCP: %w", derr)
		}
		turnConn = turn.NewSTUNConn(tcpConn)
		closeTransport = tcpConn.Close
	} else {
		udpConn, derr := net.ListenPacket("udp", ":0")
		if derr != nil {
			return nil, fmt.Errorf("turn: listen UDP: %w", derr)
		}
		turnConn = udpConn
		closeTransport = udpConn.Close
	}

	// 2. Construct the TURN client and allocate a relay.
	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: turnServerAddr,
		TURNServerAddr: turnServerAddr,
		Conn:           turnConn,
		Username:       l.cfg.Username,
		Password:       l.cfg.Password,
		Realm:          l.cfg.Realm,
	})
	if err != nil {
		_ = closeTransport()
		return nil, fmt.Errorf("turn: new client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		_ = closeTransport()
		return nil, fmt.Errorf("turn: listen: %w", err)
	}
	relay, err := client.Allocate()
	if err != nil {
		client.Close()
		_ = closeTransport()
		return nil, fmt.Errorf("turn: allocate: %w", err)
	}
	if err := client.CreatePermission(l.cfg.Peer); err != nil {
		relay.Close()
		client.Close()
		_ = closeTransport()
		return nil, fmt.Errorf("turn: create permission: %w", err)
	}

	// 3. Wrap the relay so WriteTo always targets peer and reads come back from
	// it; if DTLS is requested, do the handshake over that wrapped conn.
	pinned := &pinnedPacketConn{PacketConn: relay, peer: l.cfg.Peer}
	closeAll := func() error {
		var firstErr error
		if err := relay.Close(); err != nil {
			firstErr = err
		}
		client.Close()
		if err := closeTransport(); err != nil && firstErr == nil {
			firstErr = err
		}
		return firstErr
	}

	if !l.cfg.DTLS {
		return &cleanupConn{PacketConn: pinned, cleanup: closeAll}, nil
	}

	dtlsConn, err := dialDTLS(ctx, pinned, l.cfg.Peer, l.cfg.HandshakeTimeout)
	if err != nil {
		_ = closeAll()
		return nil, fmt.Errorf("turn: DTLS handshake: %w", err)
	}
	pc := &dtlsPacketConn{Conn: dtlsConn, peer: l.cfg.Peer}
	return &cleanupConn{PacketConn: pc, cleanup: closeAll}, nil
}

// pinnedPacketConn wraps a [net.PacketConn] so that WriteTo ignores the caller's
// address and always sends to peer. ReadFrom is delegated unchanged: pion's
// TURN relay returns the actual peer address as the source.
type pinnedPacketConn struct {
	net.PacketConn
	peer *net.UDPAddr
}

func (c *pinnedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(p, c.peer)
}

// cleanupConn is a [net.PacketConn] that runs cleanup on Close. We use it to
// tear down the TURN allocation, client, and underlying transport when the
// caller closes the conn returned from ListenPacket.
type cleanupConn struct {
	net.PacketConn
	cleanup func() error
}

func (c *cleanupConn) Close() error {
	innerErr := c.PacketConn.Close()
	cleanupErr := c.cleanup()
	if innerErr != nil {
		return innerErr
	}
	return cleanupErr
}

// dialDTLS performs a client DTLS handshake over pc to peer and returns the
// resulting [*dtls.Conn]. A fresh self-signed certificate is generated each
// call so that successive sessions are not trivially fingerprintable by peer
// certificate, matching free-turn-proxy's dtlsdial.
func dialDTLS(ctx context.Context, pc net.PacketConn, peer *net.UDPAddr, handshakeTimeout time.Duration) (*dtls.Conn, error) {
	cert, err := dtlsselfsign.GenerateSelfSigned()
	if err != nil {
		return nil, fmt.Errorf("self-signed cert: %w", err)
	}
	timeout := handshakeTimeout
	if timeout == 0 {
		timeout = defaultHandshakeTimeout
	}
	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// dtls.ClientWithContext requires a net.Conn pointed at the peer; wrap pc.
	wrapped := &boundDTLSConn{PacketConn: pc, peer: peer}
	return dtls.ClientWithContext(hsCtx, wrapped, &dtls.Config{
		Certificates:         []tls.Certificate{cert},
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		// AES-128-GCM is widely supported and matches what free-turn-proxy uses.
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	})
}

// boundDTLSConn turns a [net.PacketConn] into a [net.Conn] for pion/dtls by
// pinning a single remote peer.
type boundDTLSConn struct {
	net.PacketConn
	peer *net.UDPAddr
}

func (c *boundDTLSConn) Read(b []byte) (int, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(b)
		if err != nil {
			return n, err
		}
		// Filter out stray packets from unexpected sources.
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			if !udpAddr.IP.Equal(c.peer.IP) || udpAddr.Port != c.peer.Port {
				continue
			}
		}
		return n, nil
	}
}

func (c *boundDTLSConn) Write(b []byte) (int, error) {
	return c.PacketConn.WriteTo(b, c.peer)
}

func (c *boundDTLSConn) RemoteAddr() net.Addr { return c.peer }

// dtlsPacketConn re-exposes a [*dtls.Conn] (which is stream-shaped) as a
// [net.PacketConn] so the same outline-sdk PacketDialer plumbing keeps working
// after the DTLS layer is added. The "addresses" are fixed at peer.
type dtlsPacketConn struct {
	*dtls.Conn
	peer *net.UDPAddr
}

func (c *dtlsPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(p)
	return n, c.peer, err
}

func (c *dtlsPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Conn.Write(p)
}

func (c *dtlsPacketConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

// PacketDialer returns a [transport.PacketDialer] backed by this listener via
// [transport.PacketListenerDialer]. The address passed to DialPacket should
// match the peer in [Config], otherwise the returned [net.Conn] will see no
// reads (because [transport.PacketListenerDialer] filters by source address).
func (l *PacketListener) PacketDialer() transport.PacketDialer {
	return transport.PacketListenerDialer{Listener: l}
}
