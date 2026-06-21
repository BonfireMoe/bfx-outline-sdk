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

package mobileproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNewStreamDialerFromConfig_DNSTT verifies the dnstt scheme is reachable
// through the mobileproxy registry. Construction-only: no live dial is made.
func TestNewStreamDialerFromConfig_DNSTT(t *testing.T) {
	const pubkey = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
	d, err := NewStreamDialerFromConfig("dnstt:?domain=t.example.com&pubkey=" + pubkey + "&doh=https://doh.example/dns-query")
	require.NoError(t, err)
	require.NotNil(t, d)
}

// TestNewStreamDialerFromConfig_TURN verifies the turn scheme is reachable
// through the mobileproxy registry. Construction-only: no live dial is made.
// DialStream will return an explanatory error at runtime; layering a reliable
// transport (e.g. ss://...|turn://...) provides the actual stream path.
func TestNewStreamDialerFromConfig_TURN(t *testing.T) {
	d, err := NewStreamDialerFromConfig("turn://alice:secret@turn.example.com:3478?peer=1.2.3.4:5000")
	require.NoError(t, err)
	require.NotNil(t, d)
}
