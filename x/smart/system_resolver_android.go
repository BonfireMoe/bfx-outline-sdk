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

//go:build android

package smart

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

typedef int  (*go_res_nsend_t)(uint64_t network, const uint8_t *msg, size_t msglen, uint32_t flags);
typedef int  (*go_res_nresult_t)(int fd, int *rcode, uint8_t *answer, size_t anslen);
typedef void (*go_res_cancel_t)(int fd);

static go_res_nsend_t   p_res_nsend;
static go_res_nresult_t p_res_nresult;
static go_res_cancel_t  p_res_cancel;

// go_res_init resolves the android_res_* symbols from libandroid.so. They exist
// only on API level 29+, so dlsym returns NULL on older devices. We resolve at
// runtime (rather than linking -landroid) so the binary loads on older devices
// and we can fall back cleanly. Returns 1 when all symbols are available.
static int go_res_init(void) {
	void *h = dlopen("libandroid.so", RTLD_LAZY | RTLD_LOCAL);
	if (h == NULL) {
		return 0;
	}
	p_res_nsend   = (go_res_nsend_t)dlsym(h, "android_res_nsend");
	p_res_nresult = (go_res_nresult_t)dlsym(h, "android_res_nresult");
	p_res_cancel  = (go_res_cancel_t)dlsym(h, "android_res_cancel");
	return (p_res_nsend != NULL && p_res_nresult != NULL && p_res_cancel != NULL) ? 1 : 0;
}

// go_res_nsend issues a raw DNS query on the default network (NETWORK_UNSPECIFIED == 0).
static int go_res_nsend(const uint8_t *msg, size_t msglen, uint32_t flags) {
	if (p_res_nsend == NULL) {
		return -ENOSYS;
	}
	return p_res_nsend((uint64_t)0, msg, msglen, flags);
}

static int go_res_nresult(int fd, int *rcode, uint8_t *answer, size_t anslen) {
	if (p_res_nresult == NULL) {
		return -ENOSYS;
	}
	return p_res_nresult(fd, rcode, answer, anslen);
}

static void go_res_cancel(int fd) {
	if (p_res_cancel != NULL) {
		p_res_cancel(fd);
	}
}
*/
import "C"

import (
	"context"
	"fmt"
	"net"
	"sync"
	"unsafe"

	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// androidResNoCacheFlags bypasses the resolver cache: every dnstt query carries
// unique tunnel data, so caching is pointless and would pollute the system cache.
// Bits are ANDROID_RESOLV_NO_CACHE_STORE | ANDROID_RESOLV_NO_CACHE_LOOKUP.
const androidResNoCacheFlags = 1<<1 | 1<<2

// maxDNSMessageSize is the largest possible DNS message (the 2-byte length prefix
// caps it), so a single buffer this size always holds a complete response.
const maxDNSMessageSize = 65535

var (
	androidResInitOnce sync.Once
	androidResReady    bool
)

func androidResAvailable() bool {
	androidResInitOnce.Do(func() {
		androidResReady = C.go_res_init() != 0
	})
	return androidResReady
}

// newSystemResolver returns the native Android resolver when android_res_nsend is
// available (API 29+), falling back to the OS stub resolver otherwise.
func newSystemResolver() dns.Resolver {
	if androidResAvailable() {
		return androidResolver{}
	}
	return &systemResolver{resolver: new(net.Resolver)}
}

// androidResolver is a [dns.Resolver] backed by Android's native resolver via
// android_res_nsend / android_res_nresult. Unlike the pure-Go resolver it works
// on Android (it queries the active network's configured DNS, honoring Private
// DNS), and unlike net.Resolver.LookupTXT it exchanges raw DNS messages, so
// binary TXT data and the full response round-trip losslessly.
type androidResolver struct{}

// Query implements [dns.Resolver].
func (androidResolver) Query(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
	query, err := packAndroidQuery(q)
	if err != nil {
		return nil, fmt.Errorf("android resolver: build query: %w", err)
	}

	fd := C.go_res_nsend((*C.uint8_t)(unsafe.Pointer(&query[0])), C.size_t(len(query)), C.uint32_t(androidResNoCacheFlags))
	if fd < 0 {
		return nil, fmt.Errorf("android resolver: android_res_nsend failed (errno %d)", int(-fd))
	}

	type queryResult struct {
		msg *dnsmessage.Message
		err error
	}
	// android_res_nresult blocks and closes fd before returning. Run it off the
	// caller's goroutine so we can honor ctx; on cancellation we android_res_cancel
	// and still reap the result so the fd is always closed.
	done := make(chan queryResult, 1)
	go func() {
		answer := make([]byte, maxDNSMessageSize)
		var rcode C.int
		n := C.go_res_nresult(fd, &rcode, (*C.uint8_t)(unsafe.Pointer(&answer[0])), C.size_t(len(answer)))
		if n < 0 {
			done <- queryResult{nil, fmt.Errorf("android resolver: android_res_nresult failed (errno %d)", int(-n))}
			return
		}
		var msg dnsmessage.Message
		if err := msg.Unpack(answer[:int(n)]); err != nil {
			done <- queryResult{nil, fmt.Errorf("android resolver: unpack response: %w", err)}
			return
		}
		done <- queryResult{&msg, nil}
	}()

	select {
	case <-ctx.Done():
		C.go_res_cancel(fd)
		<-done // reap so the fd is closed by android_res_nresult
		return nil, ctx.Err()
	case r := <-done:
		return r.msg, r.err
	}
}

// packAndroidQuery serializes q into a DNS query message with EDNS(0) advertising
// a 4096-byte buffer, matching dnstt's own queries so large TXT answers are not
// needlessly truncated.
func packAndroidQuery(q dnsmessage.Question) ([]byte, error) {
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAdditionals(); err != nil {
		return nil, err
	}
	var rh dnsmessage.ResourceHeader
	if err := rh.SetEDNS0(4096, dnsmessage.RCodeSuccess, false); err != nil {
		return nil, err
	}
	if err := b.OPTResource(rh, dnsmessage.OPTResource{}); err != nil {
		return nil, err
	}
	return b.Finish()
}
