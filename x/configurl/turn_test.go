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
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/x/turn"
)

func TestParseTURNConfigBasic(t *testing.T) {
	cfg, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000")
	require.NoError(t, err)
	require.Equal(t, "turn.example.com:3478", cfg.ServerAddress)
	require.Equal(t, "alice", cfg.Username)
	require.Equal(t, "secret", cfg.Password)
	require.NotNil(t, cfg.Peer)
	require.Equal(t, "1.2.3.4:5000", cfg.Peer.String())
	require.False(t, cfg.TCP)
	require.False(t, cfg.DTLS)
}

func TestParseTURNConfigTCP(t *testing.T) {
	cfg, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&transport=tcp")
	require.NoError(t, err)
	require.True(t, cfg.TCP)
}

func TestParseTURNConfigDTLS(t *testing.T) {
	cfg, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&dtls=1")
	require.NoError(t, err)
	require.True(t, cfg.DTLS)
}

func TestParseTURNConfigDTLSFalse(t *testing.T) {
	cfg, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&dtls=0")
	require.NoError(t, err)
	require.False(t, cfg.DTLS)
}

func TestParseTURNConfigMissingPeer(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478")
	require.Error(t, err)
	require.Contains(t, err.Error(), "peer")
}

func TestParseTURNConfigMissingCredentials(t *testing.T) {
	_, err := mustParseTURN(t, "turn://turn.example.com:3478?peer=1.2.3.4:5000")
	require.Error(t, err)
	require.Contains(t, err.Error(), "username")
}

func TestParseTURNConfigMissingPassword(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice@turn.example.com:3478?peer=1.2.3.4:5000")
	require.Error(t, err)
	require.Contains(t, err.Error(), "username")
}

func TestParseTURNConfigBadHost(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice:secret@turn.example.com?peer=1.2.3.4:5000")
	require.Error(t, err)
}

func TestParseTURNConfigBadPeer(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=not-a-valid-addr")
	require.Error(t, err)
}

func TestParseTURNConfigBadTransport(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&transport=quic")
	require.Error(t, err)
}

func TestParseTURNConfigBadDTLS(t *testing.T) {
	_, err := mustParseTURN(t, "turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&dtls=maybe")
	require.Error(t, err)
}

func TestTURNPacketDialerConstruction(t *testing.T) {
	providers := NewDefaultProviders()
	dialer, err := providers.NewPacketDialer(context.Background(),
		"turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000")
	require.NoError(t, err)
	require.NotNil(t, dialer)
}

func TestTURNPacketListenerConstruction(t *testing.T) {
	providers := NewDefaultProviders()
	listener, err := providers.NewPacketListener(context.Background(),
		"turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000&dtls=1")
	require.NoError(t, err)
	require.NotNil(t, listener)
}

func TestSanitizeTURNURL(t *testing.T) {
	u, err := url.Parse("turn://alice:s3cret@turn.example.com:3478?peer=1.2.3.4:5000&dtls=1")
	require.NoError(t, err)
	sanitized, err := sanitizeTURNURL(u)
	require.NoError(t, err)
	require.Contains(t, sanitized, "REDACTED:REDACTED@turn.example.com:3478")
	require.Contains(t, sanitized, "peer=1.2.3.4")
	require.NotContains(t, sanitized, "alice")
	require.NotContains(t, sanitized, "s3cret")
}

func TestSanitizeConfigTURN(t *testing.T) {
	sanitized, err := SanitizeConfig("turn://alice:s3cret@turn.example.com:3478?peer=1.2.3.4:5000")
	require.NoError(t, err)
	require.NotContains(t, sanitized, "alice")
	require.NotContains(t, sanitized, "s3cret")
	require.Contains(t, sanitized, "REDACTED")
}

func mustParseTURN(t *testing.T, configText string) (turn.Config, error) {
	t.Helper()
	parsed, err := ParseConfig(configText)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	return parseTURNConfig(parsed.URL)
}
