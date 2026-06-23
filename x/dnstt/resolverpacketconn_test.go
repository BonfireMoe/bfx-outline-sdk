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

package dnstt

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	sdkdns "golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	updns "www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// framePacket length-prefixes p the way the dnstt server frames downstream
// packets inside a TXT answer.
func framePacket(p []byte) []byte {
	b := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(b[:2], uint16(len(p)))
	copy(b[2:], p)
	return b
}

// TestResolverPacketConnRoundTrip checks that a wire-format dnstt query written
// to the resolver transport is turned into a resolver Query, and that the
// resolver's response is re-serialized into a wire message that decodes back to
// the original payload via the same path dnsPacketConn.recvLoop uses.
func TestResolverPacketConnRoundTrip(t *testing.T) {
	const domainStr = "t.example.com"
	wantPayload := []byte("hello-tunnel")

	var gotQuestion dnsmessage.Question
	resolver := sdkdns.FuncResolver(func(_ context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
		gotQuestion = q
		return &dnsmessage.Message{
			Header:    dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess},
			Questions: []dnsmessage.Question{q},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.TXTResource{TXT: []string{string(framePacket(wantPayload))}},
			}},
		}, nil
	})

	pc := newResolverPacketConn(resolver, 1)
	defer pc.Close()

	// Build a dnstt-style TXT query: "<label>.t.example.com".
	name, err := updns.ParseName("aaaa." + domainStr)
	require.NoError(t, err)
	query := &updns.Message{
		ID:       1234,
		Flags:    0x0100, // QR=0, RD=1
		Question: []updns.Question{{Name: name, Type: updns.RRTypeTXT, Class: updns.ClassIN}},
	}
	wireQuery, err := query.WireFormat()
	require.NoError(t, err)

	_, err = pc.WriteTo(wireQuery, turbotunnel.DummyAddr{})
	require.NoError(t, err)

	// Read the response (guarded with a timeout so a conversion bug can't hang).
	type readResult struct {
		buf []byte
		err error
	}
	readCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _, rerr := pc.ReadFrom(buf)
		readCh <- readResult{buf[:n], rerr}
	}()

	var res readResult
	select {
	case res = <-readCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resolver response")
	}
	require.NoError(t, res.err)

	// The resolver must have been asked for the exact name dnstt encoded.
	require.Equal(t, "aaaa."+domainStr+".", gotQuestion.Name.String())
	require.Equal(t, dnsmessage.TypeTXT, gotQuestion.Type)

	// Decode the wire response the way dnsPacketConn.recvLoop does.
	resp, err := updns.MessageFromWireFormat(res.buf)
	require.NoError(t, err)
	domain, err := updns.ParseName(domainStr)
	require.NoError(t, err)
	payload := dnsResponsePayload(&resp, domain)
	require.NotNil(t, payload)

	p, err := nextPacket(bytes.NewReader(payload))
	require.NoError(t, err)
	require.Equal(t, wantPayload, p)
}

var _ net.PacketConn = (*resolverPacketConn)(nil)
