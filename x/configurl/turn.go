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

package configurl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/turn"
)

// parseTURNConfig pulls TURN credentials, server host:port and tunnel options
// out of a parsed configurl URL.
//
// Format: turn://<user>:<pass>@<turn-host>:<turn-port>?peer=<host:port>[&transport=udp|tcp][&dtls=1]
func parseTURNConfig(u url.URL) (turn.Config, error) {
	if u.Host == "" {
		return turn.Config{}, errors.New("turn: server host:port is required")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return turn.Config{}, fmt.Errorf("turn: server address: %w", err)
	}
	if u.User == nil {
		return turn.Config{}, errors.New("turn: username and password are required")
	}
	user := u.User.Username()
	pass, hasPass := u.User.Password()
	if user == "" || !hasPass {
		return turn.Config{}, errors.New("turn: username and password are required")
	}

	peerStr := u.Query().Get("peer")
	if peerStr == "" {
		return turn.Config{}, errors.New("turn: peer parameter is required")
	}
	peerAddr, err := net.ResolveUDPAddr("udp", peerStr)
	if err != nil {
		return turn.Config{}, fmt.Errorf("turn: resolve peer %q: %w", peerStr, err)
	}

	cfg := turn.Config{
		ServerAddress: u.Host,
		Username:      user,
		Password:      pass,
		Peer:          peerAddr,
	}

	switch strings.ToLower(u.Query().Get("transport")) {
	case "", "udp":
		cfg.TCP = false
	case "tcp":
		cfg.TCP = true
	default:
		return turn.Config{}, fmt.Errorf("turn: transport must be udp or tcp, got %q", u.Query().Get("transport"))
	}

	switch strings.ToLower(u.Query().Get("dtls")) {
	case "", "0", "false":
		cfg.DTLS = false
	case "1", "true":
		cfg.DTLS = true
	default:
		return turn.Config{}, fmt.Errorf("turn: dtls must be 0/1, got %q", u.Query().Get("dtls"))
	}
	return cfg, nil
}

func registerTURNPacketListener(r TypeRegistry[transport.PacketListener], typeID string) {
	r.RegisterType(typeID, func(_ context.Context, config *Config) (transport.PacketListener, error) {
		if config.BaseConfig != nil {
			return nil, errors.New("turn: base dialer is not supported (turn is a leaf transport)")
		}
		cfg, err := parseTURNConfig(config.URL)
		if err != nil {
			return nil, err
		}
		return turn.NewPacketListener(cfg)
	})
}

// turnStreamDialer is a no-op StreamDialer that lets users construct the dialer
// chain without error while still failing fast at DialStream time with a clear
// message. We do not provide a real stream layer because turn alone yields a
// best-effort UDP path; users must layer a reliable transport on top (e.g.
// `ss://...|turn://...`) to get a StreamDialer that actually streams.
type turnStreamDialer struct {
	cfg turn.Config
}

func (d *turnStreamDialer) DialStream(_ context.Context, _ string) (transport.StreamConn, error) {
	return nil, errors.New("turn: not usable as a StreamDialer; layer a reliable transport on top (e.g. ss://...|turn://...)")
}

func registerTURNStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string) {
	r.RegisterType(typeID, func(_ context.Context, config *Config) (transport.StreamDialer, error) {
		if config.BaseConfig != nil {
			return nil, errors.New("turn: base dialer is not supported (turn is a leaf transport)")
		}
		cfg, err := parseTURNConfig(config.URL)
		if err != nil {
			return nil, err
		}
		return &turnStreamDialer{cfg: cfg}, nil
	})
}

func registerTURNPacketDialer(r TypeRegistry[transport.PacketDialer], typeID string) {
	r.RegisterType(typeID, func(_ context.Context, config *Config) (transport.PacketDialer, error) {
		if config.BaseConfig != nil {
			return nil, errors.New("turn: base dialer is not supported (turn is a leaf transport)")
		}
		cfg, err := parseTURNConfig(config.URL)
		if err != nil {
			return nil, err
		}
		listener, err := turn.NewPacketListener(cfg)
		if err != nil {
			return nil, err
		}
		return transport.PacketListenerDialer{Listener: listener}, nil
	})
}

// sanitizeTURNURL replaces the user:password credentials with REDACTED and
// returns the resulting string. The peer/transport/dtls query parameters carry
// no secrets and are preserved.
func sanitizeTURNURL(u *url.URL) (string, error) {
	const redactedPlaceholder = "REDACTED"
	if u.User != nil {
		u.User = url.UserPassword(redactedPlaceholder, redactedPlaceholder)
	}
	return u.String(), nil
}
