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
	"fmt"
	"net/netip"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
	"github.com/openkruise/agentio/extensions/epe/pkg/filters/egressauthz"
	"github.com/openkruise/agentio/pkg/config"
	"github.com/openkruise/agentio/pkg/dns"
	"github.com/openkruise/agentio/pkg/krt"
)

func validateEPEConfig(cfg *configv1.EPEConfig) error {
	if err := extensionprovider.Validate(cfg); err != nil {
		return err
	}
	for _, raw := range cfg.GetEgressAuthorization().GetDeniedCidrs() {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.Addr().Is4In6() {
			return fmt.Errorf("egressAuthorization.deniedCIDRs: invalid or IPv4-mapped CIDR %q", raw)
		}
	}
	return nil
}

func newRequestAuthorizer(
	configs krt.Collection[config.Config[*configv1.EPEConfig]],
	client *dns.Client,
) (*egressauthz.Aggregate, krt.HandlerRegistration) {
	global := egressauthz.NewStaticAuthorizer(egressauthz.Config{})
	reg := configs.Register(func(event krt.Event[config.Config[*configv1.EPEConfig]]) {
		cfg := egressauthz.Config{}
		for _, raw := range event.Latest().Value.GetEgressAuthorization().GetDeniedCidrs() {
			// The upstream EPEConfig collection validates every published value.
			cfg.DeniedCIDRs = append(cfg.DeniedCIDRs, netip.MustParsePrefix(raw).Masked())
		}
		global.Update(cfg)
	})
	// Serving waits for reg to sync, so the first request sees the configured restrictions.
	return egressauthz.NewAggregate(client, global), reg
}
