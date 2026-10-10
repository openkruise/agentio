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

package gatewayagent

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// policyReadiness is a startup gate, not a continuous policy freshness check.
// The caller serializes checks with the Envoy readiness probe.
type policyReadiness struct{ ready bool }

func (p *policyReadiness) check(ctx context.Context, c Config) error {
	if p.ready || !c.policyEnabled() {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	host, _ := localAddresses(c.IP)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		"http://"+net.JoinHostPort(
			host,
			strconv.Itoa(int(c.Proxy.AdminPort)),
		)+"/stats?filter=%5Epolicy_store%5C.initial_sync_ready%24",
		nil,
	)
	if err != nil {
		return err
	}
	response, err := adminClient.Do(request)
	if err != nil {
		return err
	}
	defer closeResource(response.Body)
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("policy readiness: %s", response.Status)
	}
	scanner := bufio.NewScanner(response.Body)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && strings.TrimSpace(name) == "policy_store.initial_sync_ready" && strings.TrimSpace(value) == "1" {
			p.ready = true
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("gateway policy store has not completed initial sync")
}
