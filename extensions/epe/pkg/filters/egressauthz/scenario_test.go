// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package egressauthz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/subject"
	"github.com/openkruise/agentio/extensions/epe/pkg/testing/enginetest"
	"github.com/openkruise/agentio/pkg/dns"
)

// Exercise target resolution through the request engine with an empty rule chain.
func authHarness(t *testing.T, client *dns.Client) *enginetest.Harness {
	t.Helper()
	return enginetest.New(t, enginetest.Options{
		Resolve: func(context.Context, subject.Subject, *httpreq.HTTPRequest) (engine.Resolution, error) {
			return engine.Resolution{}, nil
		},
		AuthorizeRequest: egressauthz.NewAggregate(client).Authorize,
	})
}

func authRequest(host string) *enginetest.RequestBuilder {
	return enginetest.NewRequest("GET", host, "/v1").Workload("default", "sandbox", nil)
}

func TestScenario_EgressAuthzChecksLiteralCONNECTDestination(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("literal target must not query DNS")
	}), time.Second)
	h := authHarness(t, client)
	request := func(port string) *enginetest.RequestBuilder {
		return enginetest.NewRequest("CONNECT", "[2001:db8::10]:"+port, "").
			Workload("default", "sandbox", nil)
	}
	h.Run(t, request("8443")).RequireUpstream(t, "[2001:db8::10]:8443")
	h.Run(t, request("443")).RequireUpstream(t, "[2001:db8::10]:443")
}

func TestScenario_EgressAuthzDNSFailureNeverEmitsTarget(t *testing.T) {
	client := dns.NewClient(dns.LookupFunc(func(context.Context, string, dns.Family) (dns.LookupResult, error) {
		return dns.LookupResult{}, errors.New("DNS unavailable")
	}), time.Second)
	v := authHarness(t, client).Run(t, authRequest("api.example.com:443"))
	v.RequireBlocked(t, 500)
	v.RequireNoUpstream(t)
	if v.ImmediateDetails != "epe_request_authorization_failed" {
		t.Fatalf("unexpected failure detail: %q", v.ImmediateDetails)
	}
}
