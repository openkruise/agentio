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

package egresspolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
)

type spec struct {
	DefaultAction string `json:"defaultAction,omitempty"`
	DenyResponse  *struct {
		StatusCode int    `json:"statusCode,omitempty"`
		Body       string `json:"body,omitempty"`
	} `json:"denyResponse,omitempty"`
	Rules []struct {
		Name  string `json:"name"`
		Match struct {
			CIDRs      []string    `json:"cidrs,omitempty"`
			Ports      []uint16    `json:"ports,omitempty"`
			PortRanges []portRange `json:"portRanges,omitempty"`
		} `json:"match"`
		Action string `json:"action"`
	} `json:"rules,omitempty"`
}

// Parse validates and compiles a standalone JSON payload once at projection.
func Parse(raw json.RawMessage) (Config, error) {
	var s spec
	if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{")) {
		return Config{}, fmt.Errorf("egresspolicy: expected an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Config{}, err
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Config{}, fmt.Errorf("egresspolicy: trailing JSON content")
	}
	if s.DefaultAction == "" {
		s.DefaultAction = "deny"
	}
	allow, err := parseAction(s.DefaultAction)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{allowDefault: allow, reply: filter.Reply{Status: 403}}
	if s.DenyResponse != nil {
		if s.DenyResponse.StatusCode != 0 {
			cfg.reply.Status = s.DenyResponse.StatusCode
		}
		if cfg.reply.Status < 400 || cfg.reply.Status > 599 {
			return Config{}, fmt.Errorf("egresspolicy: deny status must be 400–599")
		}
		cfg.reply.Body = []byte(s.DenyResponse.Body)
	}
	names := make(map[string]bool)
	for _, entry := range s.Rules {
		if strings.TrimSpace(entry.Name) == "" || names[entry.Name] {
			return Config{}, fmt.Errorf("egresspolicy: empty or duplicate rule name %q", entry.Name)
		}
		names[entry.Name] = true
		allow, err := parseAction(entry.Action)
		if err != nil {
			return Config{}, fmt.Errorf("rule %q: %w", entry.Name, err)
		}
		r := rule{allow: allow}
		for _, text := range entry.Match.CIDRs {
			p, err := netip.ParsePrefix(text)
			if err != nil {
				return Config{}, fmt.Errorf("rule %q: invalid CIDR %q", entry.Name, text)
			}
			if p.Addr().Is4In6() {
				if p.Bits() < 96 {
					return Config{}, fmt.Errorf("rule %q: mapped IPv4 prefix must be at least /96", entry.Name)
				}
				p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
			}
			r.cidrs = append(r.cidrs, p.Masked())
		}
		for _, port := range entry.Match.Ports {
			if port == 0 {
				return Config{}, fmt.Errorf("rule %q: port must be 1–65535", entry.Name)
			}
			r.ports = append(r.ports, portRange{Start: port, End: port})
		}
		for _, ports := range entry.Match.PortRanges {
			if ports.Start == 0 || ports.End < ports.Start {
				return Config{}, fmt.Errorf("rule %q: invalid port range", entry.Name)
			}
			r.ports = append(r.ports, ports)
		}
		if len(r.cidrs) == 0 && len(r.ports) == 0 {
			return Config{}, fmt.Errorf("rule %q: match requires a nonempty constraint", entry.Name)
		}
		cfg.rules = append(cfg.rules, r)
	}
	return cfg, nil
}

func parseAction(action string) (bool, error) {
	switch action {
	case "allow":
		return true, nil
	case "deny":
		return false, nil
	}
	return false, fmt.Errorf("egresspolicy: unknown action %q", action)
}
