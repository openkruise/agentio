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

package inject

import (
	"fmt"
	"text/template"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

// InjectionPolicy determines the policy for injecting the
// sidecar proxy into the watched namespace(s).
type InjectionPolicy string

const (
	// InjectionPolicyDisabled specifies that the sidecar injector
	// will not inject the sidecar into resources by default for the
	// namespace(s) being watched. Resources can enable injection
	// using the "agentio.kruise.io/dataplane-mode" label with value
	// of "sidecar".
	InjectionPolicyDisabled InjectionPolicy = "disabled"

	// InjectionPolicyEnabled specifies that the sidecar injector will
	// inject the sidecar into resources by default for the
	// namespace(s) being watched. Resources can disable injection
	// by declaring any other "agentio.kruise.io/dataplane-mode"
	// label value, such as "none".
	InjectionPolicyEnabled InjectionPolicy = "enabled"
)

const (
	// ProxyContainerName is the default name of an injected Agentio proxy.
	ProxyContainerName = "agentio-proxy"

	legacyProxyContainerName = "istio-proxy"

	// dataplaneModeLabel is the pod-level dataplane declaration; the value
	// dataplaneModeSidecar opts a pod into ztunnel sidecar injection, and any
	// other declared mode opts it out.
	dataplaneModeLabel   = "agentio.kruise.io/dataplane-mode"
	dataplaneModeSidecar = "sidecar"

	// ValidationContainerName is the name of the init container that validates
	// if CNI has made the necessary changes to iptables
	ValidationContainerName = "agentio-validation"

	// InitContainerName is the name of the init container that deploys iptables
	InitContainerName = "agentio-init"

	// EnableCoreDumpName is the name of the init container that allows core dumps
	EnableCoreDumpName = "enable-core-dump"
)

// Agentio injection metadata and Pod tuning annotations.
// Traffic annotations consumed by the pinned CNI plugin keep their Istio keys.
const (
	injectionStatusAnnotation   = "sidecar.agentio.kruise.io/status"
	proxyOverridesAnnotation    = "sidecar.agentio.kruise.io/overrides"
	prometheusMergeAnnotation   = "prometheus.agentio.kruise.io/merge-metrics"
	networkLabel                = "agentio.kruise.io/network"
	injectTemplatesAnnotation   = "inject.agentio.kruise.io/templates"
	nativeSidecarAnnotation     = "sidecar.agentio.kruise.io/native-sidecar"
	proxyImageTypeAnnotation    = "sidecar.agentio.kruise.io/proxy-image-type"
	rewriteAppProbersAnnotation = "sidecar.agentio.kruise.io/rewrite-app-http-probers"
	proxyCPUAnnotation          = "sidecar.agentio.kruise.io/proxy-cpu"
	proxyMemoryAnnotation       = "sidecar.agentio.kruise.io/proxy-memory"
	proxyCPULimitAnnotation     = "sidecar.agentio.kruise.io/proxy-cpu-limit"
	proxyMemoryLimitAnnotation  = "sidecar.agentio.kruise.io/proxy-memory-limit"
)

func isProxyContainerName(name string) bool {
	return name == ProxyContainerName || name == legacyProxyContainerName
}

// proxyContainerName keeps an existing legacy proxy name, while new
// injections use the Agentio-native default.
func proxyContainerName(spec corev1.PodSpec) string {
	for _, containers := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
		if FindContainer(ProxyContainerName, containers) != nil {
			return ProxyContainerName
		}
	}
	for _, containers := range [][]corev1.Container{spec.Containers, spec.InitContainers} {
		if FindContainer(legacyProxyContainerName, containers) != nil {
			return legacyProxyContainerName
		}
	}
	return ProxyContainerName
}

const (
	SidecarTemplateName = "sidecar"
)

type (
	RawTemplates map[string]string
	Templates    map[string]*template.Template
)

// Config specifies the templates and cluster-side injection policy carried by
// the injector ConfigMap. The webhook consumes the default or pod-selected
// templates; the gateway deployer independently consumes the raw
// egress-gateway template.
type Config struct {
	Policy InjectionPolicy `json:"policy"`

	// DefaultTemplates defines the default template to use for pods that do not explicitly specify a template
	DefaultTemplates []string `json:"defaultTemplates"`

	// RawTemplates defines a set of templates to be used. The specified template will be run, provided with
	// SidecarTemplateData, and merged with the original pod spec using a strategic merge patch.
	RawTemplates RawTemplates `json:"templates"`

	// Aliases defines a translation of a name to inject template. For example, `sidecar: [proxy,init]` could allow
	// referencing two templates, "proxy" and "init" by a single name, "sidecar".
	// Expansion is not recursive.
	Aliases map[string][]string `json:"aliases"`

	// NeverInjectSelector: Refuses the injection on pods whose labels match this selector.
	// It's an array of label selectors, that will be OR'ed, meaning we will iterate
	// over it and stop at the first match
	// Takes precedence over AlwaysInjectSelector.
	NeverInjectSelector []metav1.LabelSelector `json:"neverInjectSelector"`

	// AlwaysInjectSelector: Forces the injection on pods whose labels match this selector.
	// It's an array of label selectors, that will be OR'ed, meaning we will iterate
	// over it and stop at the first match
	AlwaysInjectSelector []metav1.LabelSelector `json:"alwaysInjectSelector"`

	// InjectedAnnotations are additional annotations that will be added to the pod spec after injection
	// This is primarily to support PSP annotations.
	InjectedAnnotations map[string]string `json:"injectedAnnotations"`

	// Templates is a pre-parsed copy of RawTemplates
	Templates Templates `json:"-"`
}

// UnmarshalConfig unmarshals the provided YAML configuration, while normalizing the resulting configuration
func UnmarshalConfig(yml []byte) (Config, error) {
	var injectConfig Config
	if err := yaml.Unmarshal(yml, &injectConfig); err != nil {
		return injectConfig, fmt.Errorf("failed to unmarshal injection template: %v", err)
	}
	if injectConfig.RawTemplates == nil {
		injectConfig.RawTemplates = make(map[string]string)
	}
	if len(injectConfig.DefaultTemplates) == 0 {
		injectConfig.DefaultTemplates = []string{SidecarTemplateName}
	}
	if len(injectConfig.RawTemplates) == 0 {
		log.Warn(
			"injection templates are empty; check the Agentio injector ConfigMap and template versions. Pods may not be injected.",
		)
	}

	var err error
	injectConfig.Templates, err = ParseTemplates(injectConfig.RawTemplates)
	if err != nil {
		return injectConfig, err
	}

	return injectConfig, nil
}

func ParseTemplates(tmpls RawTemplates) (Templates, error) {
	ret := make(Templates, len(tmpls))
	for k, t := range tmpls {
		p, err := parseDryTemplate(t, InjectionFuncmap)
		if err != nil {
			return nil, err
		}
		ret[k] = p
	}
	return ret, nil
}

// ValuesConfig is the parsed sidecar-injector values document (raw string plus map).
type ValuesConfig struct {
	raw   string
	asMap map[string]any
}

func (v ValuesConfig) Map() map[string]any {
	return v.asMap
}

func NewValuesConfig(v string) (ValuesConfig, error) {
	c := ValuesConfig{raw: v}
	values := map[string]any{}
	if err := yaml.Unmarshal([]byte(v), &values); err != nil {
		return c, fmt.Errorf("could not parse configuration values: %v", err)
	}
	c.asMap = values
	return c, nil
}

// lookup walks a parsed values map by key path, returning the value and
// whether every step existed.
func lookup(values map[string]any, path ...string) (any, bool) {
	var current any = values
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[key]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func (v ValuesConfig) stringValue(path ...string) string {
	value, ok := lookup(v.asMap, path...)
	if !ok {
		return ""
	}
	s, _ := value.(string)
	return s
}

func (v ValuesConfig) boolValue(path ...string) bool {
	b, _ := v.boolValueWithPresence(path...)
	return b
}

func (v ValuesConfig) boolValueWithPresence(path ...string) (bool, bool) {
	value, ok := lookup(v.asMap, path...)
	if !ok {
		return false, false
	}
	b, ok := value.(bool)
	return b, ok
}

func (v ValuesConfig) intValue(path ...string) (int, bool) {
	value, ok := lookup(v.asMap, path...)
	if !ok {
		return 0, false
	}
	switch number := value.(type) {
	case int:
		return number, true
	case int64:
		return int(number), true
	case float64:
		return int(number), number == float64(int(number))
	default:
		return 0, false
	}
}

func (v ValuesConfig) stringMapValue(path ...string) map[string]string {
	value, ok := lookup(v.asMap, path...)
	if !ok {
		return nil
	}
	raw, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(raw))
	for key, value := range raw {
		if stringValue, ok := value.(string); ok {
			result[key] = stringValue
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
