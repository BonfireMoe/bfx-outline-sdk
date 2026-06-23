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

package smart

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

// maxTXTCharStringLen is the largest DNS character-string (a single TXT chunk),
// bounded by its one-byte length prefix.
const maxTXTCharStringLen = 255

// systemResolver adapts the operating system's stub resolver ([net.Resolver]) to
// the [dns.Resolver] interface so that a "system" DNS selection can still back a
// resolver-less DNS-tunnel transport (currently dnstt).
//
// net.Resolver exposes only typed lookups, so this implements just the query
// type dnstt uses: TXT. Other types return an error.
//
// Caveat: this only works where Go's resolver works. On Android and iOS the
// pure-Go resolver typically falls back to a refused [::1]:53 (see cname_unix.go),
// so a system-backed dnstt will not function there. On Android, newSystemResolver
// prefers the native android_res_nsend resolver instead (see
// system_resolver_android.go); elsewhere this is the only system option.
type systemResolver struct {
	resolver *net.Resolver
}

// Query implements [dns.Resolver]. Only TXT questions are supported.
func (r *systemResolver) Query(ctx context.Context, q dnsmessage.Question) (*dnsmessage.Message, error) {
	if q.Type != dnsmessage.TypeTXT {
		return nil, fmt.Errorf("system resolver only supports TXT queries, got %v", q.Type)
	}
	// q.Name is fully qualified (trailing dot), which forces an absolute lookup
	// with no search-domain expansion.
	txts, err := r.resolver.LookupTXT(ctx, q.Name.String())
	if err != nil {
		return nil, err
	}
	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:           true,
			RecursionAvailable: true,
			RCode:              dnsmessage.RCodeSuccess,
		},
		Questions: []dnsmessage.Question{q},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET},
			// LookupTXT concatenates each record's character-strings; re-chunk so
			// every string fits in a DNS character-string. The consumer only cares
			// about the concatenation, so the chunk boundaries need not match the
			// original wire layout.
			Body: &dnsmessage.TXTResource{TXT: chunkTXT(txts)},
		}},
	}, nil
}

// chunkTXT re-splits TXT record strings into DNS character-strings of at most
// maxTXTCharStringLen bytes. It always returns at least one (possibly empty)
// chunk so the TXT record is well-formed.
func chunkTXT(txts []string) []string {
	out := make([]string, 0, len(txts))
	for _, txt := range txts {
		for len(txt) > maxTXTCharStringLen {
			out = append(out, txt[:maxTXTCharStringLen])
			txt = txt[maxTXTCharStringLen:]
		}
		out = append(out, txt)
	}
	if len(out) == 0 {
		out = append(out, "")
	}
	return out
}
