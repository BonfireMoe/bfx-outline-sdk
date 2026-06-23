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
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestChunkTXT(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"nil yields one empty chunk", nil, []string{""}},
		{"empty string preserved", []string{""}, []string{""}},
		{"short unchanged", []string{"abc"}, []string{"abc"}},
		{"exactly max unchanged", []string{strings.Repeat("a", 255)}, []string{strings.Repeat("a", 255)}},
		{"just over max splits", []string{strings.Repeat("a", 256)}, []string{strings.Repeat("a", 255), "a"}},
		{"long splits into three", []string{strings.Repeat("a", 600)}, []string{strings.Repeat("a", 255), strings.Repeat("a", 255), strings.Repeat("a", 90)}},
		{"multiple records", []string{"x", strings.Repeat("y", 300)}, []string{"x", strings.Repeat("y", 255), strings.Repeat("y", 45)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := chunkTXT(tc.in)
			require.Equal(t, tc.want, got)
			// Every chunk must be a valid DNS character-string.
			for _, s := range got {
				require.LessOrEqual(t, len(s), maxTXTCharStringLen)
			}
			// Concatenation must be preserved.
			require.Equal(t, strings.Join(tc.in, ""), strings.Join(got, ""))
		})
	}
}

func TestSystemResolverRejectsNonTXT(t *testing.T) {
	r := &systemResolver{resolver: new(net.Resolver)}
	q := dnsmessage.Question{Name: dnsmessage.MustNewName("example.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	_, err := r.Query(context.Background(), q)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TXT")
}
