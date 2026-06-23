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
	"context"
	"errors"
	"time"

	sdkdns "golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
	updns "www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// resolverNumSenders is the number of concurrent workers issuing resolver
	// queries. It matches the DoH transport's sender count so a slow resolver
	// does not serialize the tunnel.
	resolverNumSenders = 32
	// resolverQueryTimeout bounds a single resolver round trip so a stuck query
	// cannot pin a worker indefinitely.
	resolverQueryTimeout = 30 * time.Second
)

// resolverPacketConn is a DNS transport that ships dnstt's pre-encoded DNS
// messages through an [sdkdns.Resolver]. Outgoing wire-format queries are parsed
// back into a question, resolved, and the response is re-serialized so the
// upper dnsPacketConn layer can decode it as if it had come off the wire.
//
// It follows the same shape as dohPacketConn: WriteTo (inherited from
// QueuePacketConn) only enqueues, and a pool of sender goroutines performs the
// blocking resolver round trips, queueing responses for ReadFrom.
type resolverPacketConn struct {
	resolver sdkdns.Resolver
	*turbotunnel.QueuePacketConn
}

func newResolverPacketConn(resolver sdkdns.Resolver, numSenders int) *resolverPacketConn {
	c := &resolverPacketConn{
		resolver:        resolver,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	for i := 0; i < numSenders; i++ {
		go c.sendLoop()
	}
	return c
}

func (c *resolverPacketConn) sendLoop() {
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		// A failed query is treated as a lost packet: KCP retransmits, so we do
		// not surface the error.
		_ = c.query(p)
	}
}

// query parses a dnstt wire-format DNS query, resolves it via the resolver, and
// queues the wire-format response for ReadFrom.
func (c *resolverPacketConn) query(wireQuery []byte) error {
	msg, err := updns.MessageFromWireFormat(wireQuery)
	if err != nil {
		return err
	}
	if len(msg.Question) != 1 {
		return errors.New("dnstt: query must have exactly one question")
	}
	q := msg.Question[0]
	// dnstt encodes the payload as base32 labels (only [a-z2-7]) below Domain, so
	// Name.String() never produces \xXX escapes and round-trips losslessly.
	question, err := sdkdns.NewQuestion(q.Name.String(), dnsmessage.Type(q.Type))
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolverQueryTimeout)
	defer cancel()
	resp, err := c.resolver.Query(ctx, *question)
	if err != nil {
		return err
	}
	wireResp, err := resp.Pack()
	if err != nil {
		return err
	}
	c.QueuePacketConn.QueueIncoming(wireResp, turbotunnel.DummyAddr{})
	return nil
}
