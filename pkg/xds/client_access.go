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

package xds

import (
	"fmt"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/pkg/model"
)

type clientAccess struct {
	mu      sync.Mutex
	clients []*configv1.XDSClient
	changed chan struct{}
}

// SetClientAccess publishes validated, immutable AgentioConfig.xdsClients entries.
// Changed grants disconnect affected streams so pending watches cannot retain access.
func (s *Server) SetClientAccess(clients []*configv1.XDSClient) {
	a := &s.clientAccess
	a.mu.Lock()
	defer a.mu.Unlock()
	if slices.EqualFunc(a.clients, clients, func(a, b *configv1.XDSClient) bool { return proto.Equal(a, b) }) {
		return
	}
	a.clients = clients
	close(a.changed)
	a.changed = make(chan struct{})
}

func (a *clientAccess) resolve(scope model.ClientScope) (model.ClientScope, <-chan struct{}, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	scope.Access = nil
	for _, client := range a.clients {
		if client.GetPrincipal() == scope.Principal.String() {
			scope.Access = client
			break
		}
	}
	if scope.Class == model.ClientResourceConsumer && len(scope.Access.GetResources()) == 0 {
		return scope, a.changed, fmt.Errorf("no xDS access granted to principal %q", scope.Principal.String())
	}
	return scope, a.changed, nil
}

func clientTypeAccess(scope model.ClientScope, typeURL string) (known, allowed bool) {
	known, allowed = typeAccess(scope.Class, typeURL)
	if scope.Access == nil {
		return known, allowed && scope.Class != model.ClientResourceConsumer
	}
	if !known {
		return false, false
	}
	for _, resource := range scope.Access.GetResources() {
		if resource == "*" {
			return true, true
		}
		if typ, _ := model.XDSResourceType(resource); typ == typeURL {
			return true, true
		}
	}
	return true, false
}
