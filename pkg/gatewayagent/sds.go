// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
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
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"time"

	discovery "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	sds "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

const secretType = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret"

// Extracted from release-0.1 nodeagent/sds. Upstream's generic xDS connection
// framework is replaced by a bounded stream loop for the two local secrets.
// Local SDS uses SotW GRPC, as in pilot-agent; on-demand domain certs use ADS.
type localSDS struct {
	sds.UnimplementedSecretDiscoveryServiceServer
	identity *identityManager
}

func (s *localSDS) StreamSecrets(stream sds.SecretDiscoveryService_StreamSecretsServer) error {
	updates := make(chan struct{}, 1)
	s.identity.mu.Lock()
	s.identity.clients[updates] = struct{}{}
	s.identity.mu.Unlock()
	defer func() {
		s.identity.mu.Lock()
		delete(s.identity.clients, updates)
		s.identity.mu.Unlock()
	}()
	requests := make(chan *discovery.DiscoveryRequest)
	recvError := make(chan error, 1)
	finished := make(chan struct{})
	defer close(finished)
	go receiveSDSRequests(stream, requests, recvError, finished)
	var names []string
	var nonce string
	sequence := uint64(0)
	send := func() error {
		response, err := s.identity.generate(names)
		if err != nil {
			return err
		}
		sequence++
		nonce = strconv.FormatUint(sequence, 10)
		response.Nonce = nonce
		return stream.Send(response)
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case err := <-recvError:
			return err
		case request := <-requests:
			if request.TypeUrl != "" && request.TypeUrl != secretType {
				return status.Error(codes.InvalidArgument, "unsupported SDS type")
			}
			if request.ResponseNonce != "" && request.ResponseNonce != nonce {
				continue
			}
			requested, err := localSecretNames(request.ResourceNames)
			if err != nil {
				return err
			}
			s.recordNack(request)
			changed := !slices.Equal(requested, names)
			names = requested
			if len(names) != 0 && (request.ResponseNonce == "" || changed) {
				if err := send(); err != nil {
					return err
				}
			}
		case <-updates:
			if len(names) != 0 {
				if err := send(); err != nil {
					return err
				}
			}
		}
	}
}

func (m *identityManager) generate(names []string) (*discovery.DiscoveryResponse, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	response := &discovery.DiscoveryResponse{TypeUrl: secretType, VersionInfo: strconv.FormatUint(m.version, 10)}
	for _, name := range names {
		secret := m.root
		if name == "default" {
			if m.certificate == nil || !time.Now().Before(m.expires) {
				return nil, status.Error(codes.Unavailable, "workload certificate is unavailable or expired")
			}
			secret = m.certificate
		} else if name != "ROOTCA" {
			return nil, fmt.Errorf("unsupported secret %q", name)
		}
		resource, err := anypb.New(secret)
		if err != nil {
			return nil, err
		}
		response.Resources = append(response.Resources, resource)
	}
	return response, nil
}

func localSecretNames(names []string) ([]string, error) {
	requested := slices.Clone(names)
	slices.Sort(requested)
	requested = slices.Compact(requested)
	for _, name := range requested {
		if name != "default" && name != "ROOTCA" {
			return nil, status.Error(codes.PermissionDenied, "unsupported local secret")
		}
	}
	return requested, nil
}

func (s *localSDS) recordNack(request *discovery.DiscoveryRequest) {
	if request.ErrorDetail == nil {
		return
	}
	if s.identity.config.metrics != nil {
		s.identity.config.metrics.sdsNacks.Inc()
	}
	slog.Warn("Envoy rejected gateway SDS update", "nonce", request.ResponseNonce)
}

func receiveSDSRequests(stream sds.SecretDiscoveryService_StreamSecretsServer,
	requests chan<- *discovery.DiscoveryRequest, recvError chan<- error, finished <-chan struct{},
) {
	for {
		request, err := stream.Recv()
		if err != nil {
			recvError <- err
			return
		}
		select {
		case requests <- request:
		case <-finished:
			return
		}
	}
}
