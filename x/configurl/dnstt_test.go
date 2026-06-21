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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/x/dnstt"
)

// 64 hex chars => 32 bytes, the expected length of an X25519 Noise public key.
const validPubKey = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"

func TestParseDNSTTConfigDoH(t *testing.T) {
	cfg, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey="+validPubKey+"&doh=https://doh.example/dns-query")
	require.NoError(t, err)
	require.Equal(t, dnstt.TransportDoH, cfg.Kind)
	require.Equal(t, "t.example.com", cfg.Domain)
	require.Equal(t, "https://doh.example/dns-query", cfg.DoHURL)
	require.Len(t, cfg.PubKey, 32)
}

func TestParseDNSTTConfigDoT(t *testing.T) {
	cfg, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey="+validPubKey+"&dot=resolver.example:853")
	require.NoError(t, err)
	require.Equal(t, dnstt.TransportDoT, cfg.Kind)
	require.Equal(t, "resolver.example:853", cfg.DoTAddr)
}

func TestParseDNSTTConfigUDP(t *testing.T) {
	cfg, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey="+validPubKey+"&udp=8.8.8.8:53")
	require.NoError(t, err)
	require.Equal(t, dnstt.TransportUDP, cfg.Kind)
	require.Equal(t, "8.8.8.8:53", cfg.UDPAddr)
}

func TestParseDNSTTConfigMissingDomain(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?pubkey="+validPubKey+"&udp=8.8.8.8:53")
	require.Error(t, err)
	require.Contains(t, err.Error(), "domain")
}

func TestParseDNSTTConfigMissingPubKey(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&udp=8.8.8.8:53")
	require.Error(t, err)
	require.Contains(t, err.Error(), "pubkey")
}

func TestParseDNSTTConfigInvalidPubKey(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey=not-hex&udp=8.8.8.8:53")
	require.Error(t, err)
}

func TestParseDNSTTConfigShortPubKey(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey=deadbeef&udp=8.8.8.8:53")
	require.Error(t, err)
}

func TestParseDNSTTConfigMissingTransport(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey="+validPubKey)
	require.Error(t, err)
	require.Contains(t, err.Error(), "one of")
}

func TestParseDNSTTConfigMultipleTransports(t *testing.T) {
	_, err := mustParseDNSTT(t, "dnstt:?domain=t.example.com&pubkey="+validPubKey+"&dot=resolver.example:853&udp=8.8.8.8:53")
	require.Error(t, err)
	require.Contains(t, err.Error(), "only one")
}

func TestDNSTTStreamDialerConstruction(t *testing.T) {
	providers := NewDefaultProviders()
	dialer, err := providers.NewStreamDialer(context.Background(),
		"dnstt:?domain=t.example.com&pubkey="+validPubKey+"&udp=8.8.8.8:53")
	require.NoError(t, err)
	require.NotNil(t, dialer)
}

func TestDNSTTStreamDialerConstructionInvalidConfig(t *testing.T) {
	providers := NewDefaultProviders()
	_, err := providers.NewStreamDialer(context.Background(),
		"dnstt:?domain=t.example.com&pubkey=BAD&udp=8.8.8.8:53")
	require.Error(t, err)
}

func TestDNSTTSanitizeConfig(t *testing.T) {
	sanitized, err := SanitizeConfig("dnstt:?domain=t.example.com&pubkey=" + validPubKey + "&udp=8.8.8.8:53")
	require.NoError(t, err)
	// dnstt carries no secrets; the URL should round-trip unchanged.
	require.True(t, strings.Contains(sanitized, "domain=t.example.com"))
	require.True(t, strings.Contains(sanitized, validPubKey))
	require.True(t, strings.Contains(sanitized, "udp=8.8.8.8%3A53") || strings.Contains(sanitized, "udp=8.8.8.8:53"))
}

func mustParseDNSTT(t *testing.T, configText string) (dnstt.Config, error) {
	t.Helper()
	parsed, err := ParseConfig(configText)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	return parseDNSTTConfig(parsed.URL)
}
