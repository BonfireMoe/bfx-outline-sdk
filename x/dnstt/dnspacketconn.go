// SPDX-License-Identifier: CC0-1.0
//
// Vendored with minimal adaptation from https://www.bamsoftware.com/git/dnstt.git
// (dnstt-client package main, file dns.go). dnstt is released into the public
// domain under Creative Commons CC0 1.0 Universal.
//
// Only the client-side DNS encoding/decoding glue is reproduced here; the
// upstream code lives in package main and is therefore not importable as a
// library. The behaviour is preserved verbatim apart from removing the
// log.Printf calls that referenced upstream's process-wide logger.

package dnstt

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	// numPadding is the number of bytes of random padding inserted into queries.
	numPadding = 3
	// numPaddingForPoll is the padding length used in empty polling queries, to
	// reduce the chance of a cache hit. Must be <= 31.
	numPaddingForPoll = 8

	// sendLoop has a poll timer that fires when no data has been sent for a while,
	// causing an empty polling query to be issued.
	initPollDelay       = 500 * time.Millisecond
	maxPollDelay        = 10 * time.Second
	pollDelayMultiplier = 2.0

	// pollLimit caps the burst of empty polls issued after receiving data.
	pollLimit = 16
)

// base32Encoding is base32 without padding.
var base32Encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsPacketConn provides a packet interface over arbitrary DNS transports.
// Outgoing packets are encoded as DNS queries (base32 in the QNAME), and
// incoming packets are extracted from the TXT records of the responses.
type dnsPacketConn struct {
	clientID turbotunnel.ClientID
	domain   dns.Name
	pollChan chan struct{}
	*turbotunnel.QueuePacketConn
}

// newDNSPacketConn wraps transport (a net.PacketConn that ships pre-encoded DNS
// messages) in a packet conn that exchanges arbitrary payloads with the dnstt
// server reachable via addr inside the given tunnel domain.
func newDNSPacketConn(transport net.PacketConn, addr net.Addr, domain dns.Name) *dnsPacketConn {
	clientID := turbotunnel.NewClientID()
	c := &dnsPacketConn{
		clientID:        clientID,
		domain:          domain,
		pollChan:        make(chan struct{}, pollLimit),
		QueuePacketConn: turbotunnel.NewQueuePacketConn(clientID, 0),
	}
	go c.recvLoop(transport)
	go c.sendLoop(transport, addr)
	return c
}

// dnsResponsePayload extracts the payload of a DNS response from the single
// expected TXT answer. It returns nil if any of the format checks fail.
func dnsResponsePayload(resp *dns.Message, domain dns.Name) []byte {
	if resp.Flags&0x8000 != 0x8000 {
		return nil
	}
	if resp.Flags&0x000f != dns.RcodeNoError {
		return nil
	}
	if len(resp.Answer) != 1 {
		return nil
	}
	answer := resp.Answer[0]
	if _, ok := answer.Name.TrimSuffix(domain); !ok {
		return nil
	}
	if answer.Type != dns.RRTypeTXT {
		return nil
	}
	payload, err := dns.DecodeRDataTXT(answer.Data)
	if err != nil {
		return nil
	}
	return payload
}

// nextPacket reads one length-prefixed packet from r.
func nextPacket(r *bytes.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return p, err
}

func (c *dnsPacketConn) recvLoop(transport net.PacketConn) {
	for {
		var buf [4096]byte
		n, addr, err := transport.ReadFrom(buf[:])
		if err != nil {
			return
		}
		resp, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}
		payload := dnsResponsePayload(&resp, c.domain)
		r := bytes.NewReader(payload)
		any := false
		for {
			p, perr := nextPacket(r)
			if perr != nil {
				break
			}
			any = true
			c.QueuePacketConn.QueueIncoming(p, addr)
		}
		if any {
			select {
			case c.pollChan <- struct{}{}:
			default:
			}
		}
	}
}

// chunks breaks p into non-empty subslices of at most n bytes.
func chunks(p []byte, n int) [][]byte {
	var result [][]byte
	for len(p) > 0 {
		sz := len(p)
		if sz > n {
			sz = n
		}
		result = append(result, p[:sz])
		p = p[sz:]
	}
	return result
}

func (c *dnsPacketConn) send(transport net.PacketConn, p []byte, addr net.Addr) error {
	var decoded []byte
	{
		if len(p) >= 224 {
			return fmt.Errorf("payload too long: %d", len(p))
		}
		var buf bytes.Buffer
		buf.Write(c.clientID[:])
		n := numPadding
		if len(p) == 0 {
			n = numPaddingForPoll
		}
		buf.WriteByte(byte(224 + n))
		if _, err := io.CopyN(&buf, rand.Reader, int64(n)); err != nil {
			return err
		}
		if len(p) > 0 {
			buf.WriteByte(byte(len(p)))
			buf.Write(p)
		}
		decoded = buf.Bytes()
	}

	encoded := make([]byte, base32Encoding.EncodedLen(len(decoded)))
	base32Encoding.Encode(encoded, decoded)
	encoded = bytes.ToLower(encoded)
	labels := chunks(encoded, 63)
	labels = append(labels, c.domain...)
	name, err := dns.NewName(labels)
	if err != nil {
		return err
	}

	var id uint16
	if err := binary.Read(rand.Reader, binary.BigEndian, &id); err != nil {
		return err
	}
	query := &dns.Message{
		ID:    id,
		Flags: 0x0100, // QR=0, RD=1
		Question: []dns.Question{
			{Name: name, Type: dns.RRTypeTXT, Class: dns.ClassIN},
		},
		// EDNS(0) opt RR widens the UDP payload to 4096 bytes.
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: 4096, TTL: 0, Data: []byte{}},
		},
	}
	buf, err := query.WireFormat()
	if err != nil {
		return err
	}
	_, err = transport.WriteTo(buf, addr)
	return err
}

func (c *dnsPacketConn) sendLoop(transport net.PacketConn, addr net.Addr) {
	pollDelay := initPollDelay
	pollTimer := time.NewTimer(pollDelay)
	for {
		var p []byte
		outgoing := c.QueuePacketConn.OutgoingQueue(addr)
		pollTimerExpired := false
		select {
		case p = <-outgoing:
		default:
			select {
			case p = <-outgoing:
			case <-c.pollChan:
			case <-pollTimer.C:
				pollTimerExpired = true
			}
		}

		if len(p) > 0 {
			select {
			case <-c.pollChan:
			default:
			}
		}

		if pollTimerExpired {
			pollDelay = time.Duration(float64(pollDelay) * pollDelayMultiplier)
			if pollDelay > maxPollDelay {
				pollDelay = maxPollDelay
			}
		} else {
			if !pollTimer.Stop() {
				select {
				case <-pollTimer.C:
				default:
				}
			}
			pollDelay = initPollDelay
		}
		pollTimer.Reset(pollDelay)

		if err := c.send(transport, p, addr); err != nil {
			// Transport may be temporarily unavailable; retry after the next
			// poll without surfacing the error to the caller.
			continue
		}
	}
}
