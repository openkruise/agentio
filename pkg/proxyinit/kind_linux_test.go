//go:build linux && proxyinit_integration

// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxyinit

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestKindDNSClient(t *testing.T) {
	service := os.Getenv("DNS_TEST_SERVICE_IP")
	if service == "" {
		t.Skip("run bin/test_proxy_init_kind.sh")
	}
	for _, protocol := range []string{"udp", "tcp"} {
		t.Run(protocol, func(t *testing.T) {
			query := new(dns.Msg)
			query.SetQuestion("kubernetes.default.svc.cluster.local.", dns.TypeA)
			response, _, err := (&dns.Client{Net: protocol, Timeout: 3 * time.Second}).Exchange(
				query,
				net.JoinHostPort(service, "53"),
			)
			require.NoError(t, err)
			require.Equal(t, dns.RcodeSuccess, response.Rcode)
			require.Len(t, response.Answer, 1)
			require.Equal(t, os.Getenv("DNS_TEST_EXPECT_IP"), response.Answer[0].(*dns.A).A.String())
			require.Equal(t, uint32(15), response.Answer[0].Header().Ttl, "DNS bypassed the local proxy")
		})
	}
	assertNonDNSUDPRejected(t)
}
