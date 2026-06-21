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
	"net/url"

	"golang.getoutline.org/sdk/transport"
	"golang.getoutline.org/sdk/x/dnstt"
	"www.bamsoftware.com/git/dnstt.git/noise"
)

// parseDNSTTConfig pulls the dnstt parameters out of a parsed configurl URL.
//
// The dnstt scheme uses opaque form so that the query string can sit alongside
// arbitrary other dnstt parameters without colliding with URL host/path
// semantics. Supported forms (any one transport selector is required):
//
//	dnstt:?domain=t.example.com&pubkey=<64-hex>&doh=https://doh.example/dns-query
//	dnstt:?domain=t.example.com&pubkey=<64-hex>&dot=resolver.example:853
//	dnstt:?domain=t.example.com&pubkey=<64-hex>&udp=8.8.8.8:53
func parseDNSTTConfig(u url.URL) (dnstt.Config, error) {
	// configurl puts the query string in either RawQuery (for dnstt://?...) or
	// embedded inside Opaque (for dnstt:?...). Both forms should work.
	rawQuery := u.RawQuery
	if rawQuery == "" && u.Opaque != "" {
		// Strip a leading "?" if the user wrote "dnstt:?foo=bar".
		opaque := u.Opaque
		if len(opaque) > 0 && opaque[0] == '?' {
			opaque = opaque[1:]
		}
		rawQuery = opaque
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return dnstt.Config{}, fmt.Errorf("dnstt: parse query: %w", err)
	}

	cfg := dnstt.Config{
		Domain:  values.Get("domain"),
		DoHURL:  values.Get("doh"),
		DoTAddr: values.Get("dot"),
		UDPAddr: values.Get("udp"),
	}
	if cfg.Domain == "" {
		return dnstt.Config{}, errors.New("dnstt: domain parameter is required")
	}

	pubkeyHex := values.Get("pubkey")
	if pubkeyHex == "" {
		return dnstt.Config{}, errors.New("dnstt: pubkey parameter is required")
	}
	pub, err := noise.DecodeKey(pubkeyHex)
	if err != nil {
		return dnstt.Config{}, fmt.Errorf("dnstt: decode pubkey: %w", err)
	}
	cfg.PubKey = pub

	// Exactly one transport selector is required.
	selected := 0
	if cfg.DoHURL != "" {
		cfg.Kind = dnstt.TransportDoH
		selected++
	}
	if cfg.DoTAddr != "" {
		cfg.Kind = dnstt.TransportDoT
		selected++
	}
	if cfg.UDPAddr != "" {
		cfg.Kind = dnstt.TransportUDP
		selected++
	}
	switch selected {
	case 0:
		return dnstt.Config{}, errors.New("dnstt: one of doh, dot, or udp is required")
	case 1:
		// ok
	default:
		return dnstt.Config{}, errors.New("dnstt: only one of doh, dot, or udp may be given")
	}
	return cfg, nil
}

func registerDNSTTStreamDialer(r TypeRegistry[transport.StreamDialer], typeID string) {
	r.RegisterType(typeID, func(_ context.Context, config *Config) (transport.StreamDialer, error) {
		// dnstt is a leaf transport: it opens its own connections to the DNS
		// resolver and does not layer on a base StreamDialer. Reject configs
		// that try to stack something below it.
		if config.BaseConfig != nil {
			return nil, errors.New("dnstt: base dialer is not supported (dnstt is a leaf transport)")
		}
		cfg, err := parseDNSTTConfig(config.URL)
		if err != nil {
			return nil, err
		}
		return dnstt.NewStreamDialer(cfg)
	})
}
