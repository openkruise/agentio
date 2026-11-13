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

package main

import (
	"context"
	"flag"
	"net/netip"
	"testing"
	"testing/synctest"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpreq"
	"github.com/openkruise/agentio/extensions/epe/pkg/wiring"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/krt"
)

func TestTrafficPolicyAuthorizationFlagsRemoved(t *testing.T) {
	if flag.Lookup("enable-xds-egressauthz") != nil {
		t.Fatal("TrafficPolicy authorization flag is still registered")
	}
	if flag.Lookup("enable-egressauthz") != nil {
		t.Fatal("legacy opt-in authorization flag is still registered")
	}
}

func TestValidateGlobalDeniedCIDRs(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		valid bool
	}{
		{"127.0.0.0/8", true}, {"::1/128", true}, {"192.0.2.1/32", true},
		{"192.0.2.9/24", true}, {"0.0.0.0/0", true}, {"::/0", true},
		{"localhost", false}, {"127.0.0.1", false}, {"127.0.0.1/33", false},
		{"::ffff:127.0.0.1/128", false}, {"fe80::1%eth0/128", false},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := &configv1.EPEConfig{
				EgressAuthorization: &configv1.EgressAuthorization{DeniedCidrs: []string{tc.raw}},
			}
			if err := validateEPEConfig(cfg); (err == nil) != tc.valid {
				t.Fatalf("validation=%v, valid=%t", err, tc.valid)
			}
		})
	}
}

func TestStaticAuthorizationConfigLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cm := func(name, content string) *corev1.ConfigMap {
			return &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "system"},
				Data:       map[string]string{"config": content},
			}
		}
		defaults, err := wiring.DefaultEPEConfig()
		if err != nil {
			t.Fatal(err)
		}
		sources := krt.NewMutableCollection(nil, []*corev1.ConfigMap{}, krt.WithStop(ctx.Done()))
		configs := config.NewCollection(sources.AsCollection(), config.Options[*configv1.EPEConfig]{
			Namespace: "system",
			Names:     []string{"base", "primary"},
			Defaults:  defaults,
			Apply:     wiring.ApplyEPEConfig,
			Validate:  validateEPEConfig,
		}, krt.WithStop(ctx.Done()))
		// No resource store, xDS connection, workload binding, or source identity.
		authorize, reg := newRequestAuthorizer(configs.AsCollection(), dns.NewClient(nil, 0))
		if !reg.WaitUntilSynced(ctx.Done()) {
			t.Fatal("authorization configuration did not sync")
		}
		target, reply, err := authorize.Authorize(ctx, &filter.Stream{
			RequestContext: filter.RequestContext{
				Request: httpreq.HTTPRequest{Host: "192.0.2.1", Port: 443},
				Policies: filter.PolicySnapshot{DestinationAuthorizer: egressauthz.Config{
					DeniedCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
				}},
			},
			StreamRuntime: filter.StreamRuntime{Info: filter.NewStreamInfo()},
		})
		if err != nil || target != nil || reply == nil || reply.Status != 403 {
			t.Fatalf("profile authorization was not applied: target=%v reply=%v err=%v", target, reply, err)
		}
		check := func(host string, denied bool) {
			t.Helper()
			synctest.Wait()
			target, reply, err := authorize.Authorize(
				ctx,
				&filter.Stream{
					RequestContext: filter.RequestContext{Request: httpreq.HTTPRequest{Host: host, Port: 15000}},
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if denied {
				if reply == nil || reply.Status != 403 || target != nil {
					t.Fatalf("%s: target=%v reply=%v", host, target, reply)
				}
			} else if reply != nil || target == nil {
				t.Fatalf("%s: target=%v reply=%v", host, target, reply)
			}
		}
		mandatoryHosts := []string{
			"127.0.0.1", "127.255.255.254", "::1", "0.0.0.0", "::",
			"::ffff:127.0.0.1", "::ffff:0.0.0.0",
			"169.254.169.254", "169.254.1.1", "fe80::1", "febf::1",
			"::ffff:169.254.169.254",
		}
		checkMandatory := func() {
			t.Helper()
			for _, host := range mandatoryHosts {
				check(host, true)
			}
		}
		optionalHosts := []string{"100.100.100.200", "::ffff:100.100.100.200"}
		checkOptional := func(denied bool) {
			t.Helper()
			for _, host := range optionalHosts {
				check(host, denied)
			}
		}
		checkMandatory()
		checkOptional(false)
		for _, host := range []string{"192.0.2.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "fd00::1"} {
			check(host, false) // Business private networks are not implicitly denied.
		}
		sources.UpdateObject(cm("base", "egressAuthorization: {deniedCIDRs: [invalid]}"))
		checkMandatory() // Invalid initial configuration retains built-ins.
		sources.UpdateObject(cm("base", "egressAuthorization: {deniedCIDRs: [192.0.2.1/32]}"))
		check("192.0.2.1", true)
		checkMandatory()
		sources.UpdateObject(cm("primary", "egressAuthorization: null"))
		check("192.0.2.1", true) // Null inherits user entries from the lower layer.
		checkMandatory()
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: ['2001:db8::1/128']}"))
		check("2001:db8::1", true)
		check("192.0.2.1", false) // Replacing the block only replaces user entries.
		checkMandatory()
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: [invalid]}"))
		check("2001:db8::1", true) // Invalid updates keep the last good configuration.
		checkMandatory()
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: []}"))
		check("2001:db8::1", false)
		check("192.0.2.1", false)
		checkMandatory() // Explicit clearing cannot remove mandatory restrictions.
		sources.DeleteObject("system/primary")
		check("192.0.2.1", true)
		checkMandatory()
		sources.DeleteObject("system/base")
		check("192.0.2.1", false)
		checkMandatory()
		checkOptional(false)
		sources.UpdateObject(cm("primary", `egressAuthorization:
  deniedCIDRs: [100.100.100.200/32]`))
		checkOptional(true) // Operators can explicitly deny Alibaba Cloud metadata.
		checkMandatory()
		sources.UpdateObject(cm("primary", "egressAuthorization: {deniedCIDRs: []}"))
		checkOptional(false)
		checkMandatory()
	})
}
