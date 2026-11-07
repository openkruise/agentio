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

package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/openkruise/agentio/extensions/epe/pkg/engine/filter"
	"github.com/openkruise/agentio/extensions/epe/pkg/metrics"
	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

var (
	securityProfileSource = flag.String(
		"security-profile-source",
		"kubernetes",
		"SecurityProfile and Sandbox policy source: kubernetes (informer cache) or xds (control plane)",
	)
	xdsCacheIdleTTL = flag.Duration(
		"xds-cache-idle-ttl",
		10*time.Minute,
		"Idle lifetime of retained Workload, TrafficPolicy, SecurityProfile and Sandbox subscriptions; zero disables expiry",
	)
	xdsCacheMaxEntries = flag.Int(
		"xds-cache-max-entries",
		10000,
		"Maximum retained Workload, TrafficPolicy, SecurityProfile and Sandbox subscriptions; active resolutions are pinned; zero disables capacity eviction",
	)
	clusterDomain = flag.String(
		"domain",
		"cluster.local",
		"Kubernetes DNS suffix used in the default ADS node ID",
	)
	enableXDSEgressAuthz = flag.Bool(
		"enable-xds-egressauthz",
		false,
		"Apply native Workload and TrafficPolicy xDS policies in addition to global egress authorization",
	)
	xdsAddress = flag.String(
		"xds-address",
		"",
		"Agentiod TLS ADS endpoint (host:port); required for Workload SecurityProfile bindings",
	)
	xdsRootPath  = flag.String("xds-root-path", "", "PEM trust bundle for Agentiod ADS")
	xdsTokenPath = flag.String(
		"xds-token-path",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"Projected Pod-bound token for ADS (requires an identity listed in AgentioConfig.trustedEPEIdentities)",
	)
	xdsClusterID = flag.String(
		"xds-cluster-id",
		"Kubernetes",
		"Source Pod cluster ID; must match Agentiod --cluster-id",
	)
	xdsNodeID = flag.String(
		"xds-node-id",
		"",
		"ADS node ID; defaults to epe~POD_IP~POD_NAME.POD_NAMESPACE~POD_NAMESPACE.svc.<domain>",
	)
)

func newEgressXDS(
	regs []filter.Registration,
	source *xdsstore.ProfileSource,
) (*xdsclient.Client, *grpc.ClientConn, error) {
	if *xdsAddress == "" {
		return nil, nil, fmt.Errorf("--xds-address is required for Workload SecurityProfile bindings")
	}
	if *xdsClusterID == "" {
		return nil, nil, fmt.Errorf("--xds-cluster-id must not be empty")
	}
	id := *xdsNodeID
	if id == "" {
		name, ns := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
		if name == "" || ns == "" {
			return nil, nil, fmt.Errorf("POD_NAME and POD_NAMESPACE or --xds-node-id are required")
		}
		id = "epe~" + os.Getenv("POD_IP") + "~" + name + "." + ns + "~" + ns + ".svc." + *clusterDomain
	}
	metadata, err := structpb.NewStruct(
		map[string]any{
			"POD_NAME":      os.Getenv("POD_NAME"),
			"POD_NAMESPACE": os.Getenv("POD_NAMESPACE"),
			"POD_UID":       os.Getenv("POD_UID"),
		},
	)
	if err != nil {
		return nil, nil, err
	}
	conn, err := xdsclient.Dial(*xdsAddress, *xdsRootPath, *xdsTokenPath)
	if err != nil {
		return nil, nil, err
	}
	c, err := xdsclient.New(
		conn,
		xdsclient.Config{
			Node:              &core.Node{Id: id, Metadata: metadata},
			Watches:           epeWatches(*securityProfileSource, regs, source),
			MetricsRegisterer: metrics.Registry,
		},
	)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, nil, fmt.Errorf("%w (close connection: %w)", err, closeErr)
		}
		return nil, nil, err
	}
	return c, conn, nil
}

func epeWatches(mode string, regs []filter.Registration, source *xdsstore.ProfileSource) []xdsclient.Watch {
	watches := xdsstore.Watches()
	if mode == "xds" {
		watches = append(watches, source.Watches(regs)...)
	}
	return watches
}
