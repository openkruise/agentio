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

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	xdsstore "github.com/openkruise/agentio/extensions/epe/pkg/store/xds"
	"github.com/openkruise/agentio/pkg/xdsclient"
)

var (
	enableXDSEgressAuthz = flag.Bool(
		"enable-xds-egressauthz",
		false,
		"Apply native Workload and TrafficPolicy xDS policies in addition to global egress authorization",
	)
	xdsAddress = flag.String(
		"xds-address",
		"",
		"Agentiod TLS ADS endpoint (host:port); required with --enable-xds-egressauthz",
	)
	xdsRootPath  = flag.String("xds-root-path", "", "PEM trust bundle for Agentiod ADS")
	xdsTokenPath = flag.String(
		"xds-token-path",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"Projected Pod-bound token for ADS (requires an authorized xDS principal)",
	)
	xdsClusterID = flag.String(
		"xds-cluster-id",
		"Kubernetes",
		"Source Pod cluster ID; must match Agentiod --cluster-id",
	)
	xdsNodeID = flag.String(
		"xds-node-id",
		"",
		"ADS node ID; defaults to resource-consumer~POD_IP~POD_NAME.POD_NAMESPACE~POD_NAMESPACE.svc.cluster.local",
	)
)

func newEgressXDS() (*xdsclient.Client, *grpc.ClientConn, error) {
	if *xdsClusterID == "" {
		return nil, nil, fmt.Errorf("--xds-cluster-id must not be empty")
	}
	id := *xdsNodeID
	if id == "" {
		name, ns := os.Getenv("POD_NAME"), os.Getenv("POD_NAMESPACE")
		if name == "" || ns == "" {
			return nil, nil, fmt.Errorf("POD_NAME and POD_NAMESPACE or --xds-node-id are required")
		}
		id = "resource-consumer~" + os.Getenv("POD_IP") + "~" + name + "." + ns + "~" + ns + ".svc.cluster.local"
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
		xdsclient.Config{Node: &core.Node{Id: id, Metadata: metadata}, Watches: xdsstore.Watches()},
	)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			return nil, nil, fmt.Errorf("%w (close connection: %w)", err, closeErr)
		}
		return nil, nil, err
	}
	return c, conn, nil
}
