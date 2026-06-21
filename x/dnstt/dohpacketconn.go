// SPDX-License-Identifier: CC0-1.0
//
// Vendored with minimal adaptation from https://www.bamsoftware.com/git/dnstt.git
// (dnstt-client package main, file http.go). dnstt is released into the public
// domain under Creative Commons CC0 1.0 Universal.

package dnstt

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

// defaultRetryAfter is the default Retry-After delay applied when the DoH
// server returns a non-200 response without a Retry-After header.
const defaultRetryAfter = 10 * time.Second

// dohPacketConn is a DoH-based packet transport that ships pre-encoded DNS
// messages over HTTPS.
type dohPacketConn struct {
	client        *http.Client
	urlString     string
	notBefore     time.Time
	notBeforeLock sync.RWMutex
	*turbotunnel.QueuePacketConn
}

func newDoHPacketConn(rt http.RoundTripper, urlString string, numSenders int) *dohPacketConn {
	c := &dohPacketConn{
		client: &http.Client{
			Transport: rt,
			Timeout:   1 * time.Minute,
		},
		urlString:       urlString,
		QueuePacketConn: turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, 0),
	}
	for i := 0; i < numSenders; i++ {
		go c.sendLoop()
	}
	return c
}

func (c *dohPacketConn) send(p []byte) error {
	req, err := http.NewRequest("POST", c.urlString, bytes.NewReader(p))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "") // Disable default "Go-http-client/1.1".
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
			return fmt.Errorf("unknown DoH content-type %q", ct)
		}
		body, rerr := io.ReadAll(io.LimitReader(resp.Body, 64000))
		if rerr == nil {
			c.QueuePacketConn.QueueIncoming(body, turbotunnel.DummyAddr{})
		}
	default:
		now := time.Now()
		var retryAfter time.Time
		if value := resp.Header.Get("Retry-After"); value != "" {
			if t, perr := parseRetryAfter(value, now); perr == nil {
				retryAfter = t
			}
		}
		if retryAfter.IsZero() {
			retryAfter = now.Add(defaultRetryAfter)
		}
		if !retryAfter.Before(now) {
			c.notBeforeLock.Lock()
			if !retryAfter.Before(c.notBefore) {
				c.notBefore = retryAfter
			}
			c.notBeforeLock.Unlock()
		}
	}
	return nil
}

func (c *dohPacketConn) sendLoop() {
	for p := range c.QueuePacketConn.OutgoingQueue(turbotunnel.DummyAddr{}) {
		c.notBeforeLock.RLock()
		notBefore := c.notBefore
		c.notBeforeLock.RUnlock()
		if wait := time.Until(notBefore); wait > 0 {
			continue
		}
		_ = c.send(p)
	}
}

func parseRetryAfter(value string, now time.Time) (time.Time, error) {
	if t, err := http.ParseTime(value); err == nil {
		return t, nil
	}
	i, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return time.Time{}, err
	}
	return now.Add(time.Duration(i) * time.Second), nil
}
