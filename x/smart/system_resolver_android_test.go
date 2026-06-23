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

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.getoutline.org/sdk/dns"
	"golang.org/x/net/dns/dnsmessage"
)

// TestAndroidResolverLiveTXT exercises the native Android resolver against the
// real network. It only runs on a device/emulator and only when explicitly
// requested, since it depends on live DNS.
//
// Build and run on a connected device (API 29+):
//
//	CGO_ENABLED=1 GOOS=android GOARCH=amd64 \
//	  CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android29-clang \
//	  go test -c -o /tmp/smarttest ./smart/
//	adb push /tmp/smarttest /data/local/tmp/
//	adb shell DNSTT_ANDROID_LIVE_TEST=1 /data/local/tmp/smarttest \
//	  -test.run TestAndroidResolverLiveTXT -test.v
func TestAndroidResolverLiveTXT(t *testing.T) {
	if os.Getenv("DNSTT_ANDROID_LIVE_TEST") == "" {
		t.Skip("set DNSTT_ANDROID_LIVE_TEST=1 to run the live Android resolver test")
	}
	if !androidResAvailable() {
		t.Skip("android_res_nsend unavailable (requires API level 29+)")
	}

	q, err := dns.NewQuestion("google.com", dnsmessage.TypeTXT)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	msg, err := androidResolver{}.Query(ctx, *q)
	require.NoError(t, err)
	require.NotNil(t, msg)

	var txtAnswers int
	for _, a := range msg.Answers {
		if a.Header.Type == dnsmessage.TypeTXT {
			txtAnswers++
		}
	}
	t.Logf("rcode=%v, answers=%d, txt=%d", msg.RCode, len(msg.Answers), txtAnswers)
	require.Greater(t, txtAnswers, 0, "expected at least one TXT answer for google.com")
}
