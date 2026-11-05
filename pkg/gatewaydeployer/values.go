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

package gatewaydeployer

import (
	"fmt"
	"maps"
	"sync"

	"google.golang.org/protobuf/proto"
	meshconfig "istio.io/api/mesh/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
)

const (
	egressGatewayTemplateName = "egress-gateway"
	agentgatewayTemplateName  = "agentgateway"
)

type Options struct {
	ClusterID             string
	SystemNamespace       string
	InjectorConfigMapName string
	TrustDomain           string
	ClusterDomain         string
	// CAAddress is the fallback CA and xDS address when injector values omit both.
	CAAddress    string
	LeaseName    string
	Agentgateway AgentgatewaySources
}

// AgentgatewaySources reuses the registry's validated configuration and discovery caches.
type AgentgatewaySources struct {
	Config      krt.Collection[model.AgentioConfiguration]
	Services    krt.Collection[model.Service]
	Endpoints   krt.Collection[model.Endpoint]
	Secrets     krt.Collection[*corev1.Secret]
	TrustBundle string
}

// templateProvider serves the gateway templates and shared values from
// the injector ConfigMap. Runtime values only fill fields omitted there.
type templateProvider struct {
	renderer    *renderer
	runtime     map[string]any
	proxyConfig *meshconfig.ProxyConfig

	mu        sync.Mutex
	handlers  map[uint64]func()
	handlerID uint64
}

func newTemplateProvider(o Options, proxyConfig *meshconfig.ProxyConfig) (*templateProvider, error) {
	p := &templateProvider{
		runtime:     runtimeOverlay(o),
		proxyConfig: proxyConfig,
		handlers:    map[uint64]func(){},
	}
	rend, err := newRenderer(func() map[string]any { return p.runtime }, proxyConfig, o.TrustDomain)
	if err != nil {
		return nil, err
	}
	p.renderer = rend
	return p, nil
}

func (p *templateProvider) currentValues() map[string]any {
	return p.renderer.state.Load().values
}

func (p *templateProvider) Renderer() *renderer {
	return p.renderer
}

// AddHandler registers fn to be called after every successful ConfigMap
// update and returns a deregistration func.
func (p *templateProvider) AddHandler(fn func()) func() {
	p.mu.Lock()
	id := p.handlerID
	p.handlerID++
	p.handlers[id] = fn
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		delete(p.handlers, id)
		p.mu.Unlock()
	}
}

type injectorTemplateConfig struct {
	Templates map[string]string `json:"templates"`
}

func (p *templateProvider) updateFromInjectorConfig(rawConfig, rawValues string) error {
	var config injectorTemplateConfig
	if err := yaml.Unmarshal([]byte(rawConfig), &config); err != nil {
		return fmt.Errorf("parse injector config: %w", err)
	}
	templateContent := config.Templates[egressGatewayTemplateName]
	if templateContent == "" {
		return fmt.Errorf("injector config is missing template %q", egressGatewayTemplateName)
	}
	values := map[string]any{}
	if err := yaml.Unmarshal([]byte(rawValues), &values); err != nil {
		return fmt.Errorf("parse injector values: %w", err)
	}
	merged := mergeMaps(p.runtime, values)
	if address := nestedString(merged, "global", "gatewayXdsAddress"); address != "" {
		merged["global"].(map[string]any)["caAddress"] = address
	}
	proxyConfig := proto.Clone(p.proxyConfig).(*meshconfig.ProxyConfig)
	if address := nestedString(merged, "global", "gatewayXdsAddress"); address != "" {
		proxyConfig.DiscoveryAddress = address
	} else if address := nestedString(merged, "global", "xdsAddress"); address != "" {
		proxyConfig.DiscoveryAddress = address
	} else if address := nestedString(merged, "global", "caAddress"); address != "" {
		proxyConfig.DiscoveryAddress = address
	}
	templates := map[string]string{egressGatewayTemplateName: templateContent}
	// Optional so older injector ConfigMaps continue serving Envoy gateways.
	if content := config.Templates[agentgatewayTemplateName]; content != "" {
		templates[agentgatewayTemplateName] = content
	}
	if err := p.renderer.updateTemplates(templates, merged, proxyConfig); err != nil {
		return err
	}
	p.notifyHandlers()
	return nil
}

func (p *templateProvider) notifyHandlers() {
	p.mu.Lock()
	handlers := make([]func(), 0, len(p.handlers))
	for _, fn := range p.handlers {
		handlers = append(handlers, fn)
	}
	p.mu.Unlock()
	for _, fn := range handlers {
		fn()
	}
}

func mergeMaps(base, overlay map[string]any) map[string]any {
	out := make(map[string]any, len(base))
	maps.Copy(out, base)
	for key, value := range overlay {
		baseChild, baseOK := out[key].(map[string]any)
		overlayChild, overlayOK := value.(map[string]any)
		if baseOK && overlayOK {
			out[key] = mergeMaps(baseChild, overlayChild)
			continue
		}
		out[key] = value
	}
	return out
}

func nestedString(values map[string]any, path ...string) string {
	var current any = values
	for _, key := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = object[key]
	}
	value, _ := current.(string)
	return value
}

func runtimeOverlay(o Options) map[string]any {
	return map[string]any{
		"global": map[string]any{
			"caAddress":   o.CAAddress,
			"trustDomain": o.TrustDomain,
			"proxy": map[string]any{
				"clusterDomain": o.ClusterDomain,
			},
		},
	}
}
