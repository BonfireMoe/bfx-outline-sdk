// SPDX-License-Identifier: CC0-1.0
//
// Vendored with minimal adaptation from https://www.bamsoftware.com/git/dnstt.git
// (dnstt-client package main, file tls.go). dnstt is released into the public
// domain under Creative Commons CC0 1.0 Universal.

package dnstt

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const dotDialTimeout = 30 * time.Second

// dotPacketConn is a DoT-based packet transport that ships pre-encoded DNS
// messages over a TLS-protected TCP connection.
type dotPacketConn struct {
	*turbotunnel.QueuePacketConn
}

func newDoTPacketConn(addr string, dialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)) (*dotPacketConn, error) {
	if dialTLSContext == nil {
		dialTLSContext = (&tls.Dialer{}).DialContext
	}
	dial := func() (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), dotDialTimeout)
		defer cancel()
		return dialTLSContext(ctx, "tcp", addr)
	}
	conn, err := dial()
	if err != nil {
		return nil, err
	}
	c := &dotPacketConn{
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	go func() {
		defer c.Close()
		for {
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				_ = c.recvLoop(conn)
			}()
			go func() {
				defer wg.Done()
				_ = c.sendLoop(conn)
			}()
			wg.Wait()
			conn.Close()

			conn, err = dial()
			if err != nil {
				return
			}
		}
	}()
	return c, nil
}

func (c *dotPacketConn) recvLoop(conn net.Conn) error {
	br := bufio.NewReader(conn)
	for {
		var length uint16
		if err := binary.Read(br, binary.BigEndian, &length); err != nil {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		p := make([]byte, int(length))
		if _, err := io.ReadFull(br, p); err != nil {
			return err
		}
		c.QueuePacketConn.QueueIncoming(p, turbotunnel.DummyAddr{})
	}
}

func (c *dotPacketConn) sendLoop(conn net.Conn) error {
	bw := bufio.NewWriter(conn)
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		length := uint16(len(p))
		if int(length) != len(p) {
			// Drop oversize packets rather than panicking.
			continue
		}
		if err := binary.Write(bw, binary.BigEndian, &length); err != nil {
			return err
		}
		if _, err := bw.Write(p); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}
	return nil
}
