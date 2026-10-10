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
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"

	"text/template"

	_ "github.com/cncf/xds/go/udpa/type/v1"

	bootstrapv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/bootstrap/internal_listener/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"google.golang.org/protobuf/encoding/protojson"
)

//go:embed envoy_bootstrap.json.tmpl
var bootstrapTemplate string

//go:embed envoy_bootstrap_legacy.json.tmpl
var legacyBootstrapTemplate string

func bootstrapConfig(c Config) (*bootstrapv3.Bootstrap, error) {
	localhost, wildcard := localAddresses(c.IP)
	metadata := maps.Clone(c.Metadata)
	if metadata == nil {
		metadata = map[string]any{}
	}
	for key, value := range map[string]string{"POD_NAME": c.PodName,
		"POD_NAMESPACE":    c.Namespace,
		"POD_UID":          c.PodUID,
		"NODE_NAME":        c.NodeName,
		"CLUSTER_ID":       c.ClusterID,
		"AGENTIO_VERSION":  BuildInfo().Version,
		"AGENTIO_REVISION": BuildInfo().Revision} {
		metadata[key] = value
	}
	source := bootstrapTemplate
	if c.Legacy {
		if err := c.legacyMetadata(metadata); err != nil {
			return nil, err
		}
		source = legacyBootstrapTemplate
	}
	parameters := map[string]any{
		"NodeID":    c.nodeID(),
		"LogAsJSON": c.LogAsJSON,
		"ServiceCluster": envString(
			"AGENTIO_SERVICE_CLUSTER",
			envString("ISTIO_META_WORKLOAD_NAME", c.PodName)+"."+c.Namespace,
		),
		"Metadata":           metadata,
		"Localhost":          localhost,
		"Wildcard":           wildcard,
		"SDSSocket":          c.SDSSocket,
		"XDSSocket":          c.XDSSocket,
		"StatsFlushInterval": fmt.Sprintf("%.9fs", c.StatsFlushInterval.Seconds()),
	}
	t, err := template.New("gateway").Funcs(template.FuncMap{"json": func(v any) (string, error) {
		b, err := json.Marshal(v)
		return string(b), err
	}}).Parse(source)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, parameters); err != nil {
		return nil, err
	}
	content, err := customizeBootstrap(b.Bytes(), c)
	if err != nil {
		return nil, err
	}
	result := &bootstrapv3.Bootstrap{}
	if err := protojson.Unmarshal(content, result); err != nil {
		return nil, err
	}
	return result, result.ValidateAll()
}
