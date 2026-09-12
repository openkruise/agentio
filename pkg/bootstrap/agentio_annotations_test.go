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
package bootstrap

import (
	"istio.io/istio/pkg/bootstrap/option"
	"istio.io/istio/pkg/model"
	"testing"
	"time"
)

func TestAgentioStatsAnnotations(t *testing.T) {
	meta := &model.BootstrapNodeMetadata{}
	meta.ProxyConfig = &model.NodeMetaProxyConfig{}
	meta.Annotations = map[string]string{
		"sidecar.istio.io/statsFlushInterval":               "5s",
		"sidecar.agentio.kruise.io/stats-flush-interval":    "2s",
		"sidecar.istio.io/statsEvictionInterval":            "30s",
		"sidecar.agentio.kruise.io/stats-eviction-interval": "8s",
	}
	params, err := option.NewTemplateParams(getStatsOptions(meta)...)
	if err != nil {
		t.Fatal(err)
	}
	if params["stats_flush_interval"] != 2*time.Second {
		t.Fatalf("stats flush = %v", params["stats_flush_interval"])
	}
	if params["stats_eviction_interval"] != "8s" {
		t.Fatalf("stats eviction = %#v", params["stats_eviction_interval"])
	}
}
