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
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/annotation"
	"istio.io/api/label"
	"istio.io/istio/pkg/util/sets"
)

// defaultProxyUID is the user ID reserved for the injected proxy.
const defaultProxyUID int64 = 1337

// IgnoredNamespaces lists Kubernetes system namespaces that never receive injection.
var IgnoredNamespaces = sets.New(
	"kube-system",
	"kube-public",
	"kube-node-lease",
	"local-path-storage",
)

// SidecarTemplateData is the data object to which the templated
// version of `SidecarInjectionSpec` is applied.
type SidecarTemplateData struct {
	TypeMeta         metav1.TypeMeta
	DeploymentMeta   types.NamespacedName
	ObjectMeta       metav1.ObjectMeta
	Spec             corev1.PodSpec
	ProxyConfig      *ProxyConfig
	MeshConfig       *TemplateMeshConfig
	Values           map[string]any
	NativeSidecars   bool
	ProxyImage       string
	ProxyUID         int64
	ProxyGID         int64
	CompliancePolicy string
}

func injectRequired(ignored []string, config *Config, podSpec *corev1.PodSpec, metadata metav1.ObjectMeta) bool { // nolint: lll
	requestLogger := log.With("pod", metadata.Namespace+"/"+potentialPodName(metadata))
	// Skip host-network pods: the iptables rules would redirect host-level routing.
	if podSpec.HostNetwork {
		return false
	}

	// skip special kubernetes system namespaces
	if slices.Contains(ignored, metadata.Namespace) {
		return false
	}

	var useDefault bool
	var inject bool

	switch mode := metadata.GetLabels()[dataplaneModeLabel]; mode {
	case dataplaneModeSidecar:
		inject = true
	case "":
		useDefault = true
	default:
		// Pods declaring any other dataplane mode (ambient, none, ...) never
		// receive a ztunnel sidecar.
		requestLogger.Debug("skipping injection for declared dataplane mode",
			"selector", dataplaneModeLabel, "value", mode)
		inject = false
	}

	// If an annotation is not explicitly given, check the LabelSelectors, starting with NeverInject
	if useDefault {
		for _, neverSelector := range config.NeverInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&neverSelector)
			if err != nil {
				requestLogger.Warn("invalid never-inject selector", "selector", neverSelector, "error", err)
			} else if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
				requestLogger.Debug("disabling injection because pod labels match never-inject selector")
				inject = false
				useDefault = false
				break
			}
		}
	}

	// If there's no annotation nor a NeverInjectSelector, check the AlwaysInject one
	if useDefault {
		for _, alwaysSelector := range config.AlwaysInjectSelector {
			selector, err := metav1.LabelSelectorAsSelector(&alwaysSelector)
			if err != nil {
				requestLogger.Warn("invalid always-inject selector", "selector", alwaysSelector, "error", err)
			} else if !selector.Empty() && selector.Matches(labels.Set(metadata.Labels)) {
				requestLogger.Debug("enabling injection because pod labels match always-inject selector")
				inject = true
				useDefault = false
				break
			}
		}
	}

	var required bool
	switch config.Policy {
	default: // InjectionPolicyOff
		requestLogger.Error("invalid default injection policy; automatic injection disabled",
			"policy", config.Policy, "allowed", []InjectionPolicy{InjectionPolicyDisabled, InjectionPolicyEnabled})
		required = false
	case InjectionPolicyDisabled:
		if useDefault {
			required = false
		} else {
			required = inject
		}
	case InjectionPolicyEnabled:
		if useDefault {
			required = true
		} else {
			required = inject
		}
	}

	return required
}

// ProxyImage constructs image url in a backwards compatible way.
// values based name => {{ .Values.global.hub }}/{{ .Values.global.proxy.image }}:{{ .Values.global.tag }}
func ProxyImage(values ValuesConfig, imageType string, annotations map[string]string) string {
	imageName := "proxyv2"
	if image := values.stringValue("global", "proxy", "image"); image != "" {
		imageName = image
	}
	tag := ""
	if raw, ok := lookup(values.asMap, "global", "tag"); ok && raw != nil {
		tag = fmt.Sprint(raw)
	}
	if imageType == "" {
		imageType = values.stringValue("global", "variant")
	}
	if it, ok := annotations[proxyImageTypeAnnotation]; ok {
		imageType = it
	}
	hub := values.stringValue("global", "hub")

	return imageURL(hub, imageName, tag, imageType)
}

const (
	// ImageTypeDebug is the suffix of the debug image.
	ImageTypeDebug = "debug"
	// ImageTypeDistroless is the suffix of the distroless image.
	ImageTypeDistroless = "distroless"
	// ImageTypeDefault is the type name of the default image, suffix is elided.
	ImageTypeDefault = "default"
)

// imageURL creates url from parts.
// imageType is appended if not empty
// if imageType is already present in the tag, then it is replaced.
func imageURL(hub, imageName, tag, imageType string) string {
	return hub + "/" + imageName + ":" + updateImageTypeIfPresent(tag, imageType)
}

// KnownImageTypes are image types that istio pubishes.
var KnownImageTypes = []string{ImageTypeDistroless, ImageTypeDebug}

func updateImageTypeIfPresent(tag string, imageType string) string {
	if imageType == "" {
		return tag
	}

	for _, i := range KnownImageTypes {
		if strings.HasSuffix(tag, "-"+i) {
			tag = tag[:len(tag)-(len(i)+1)]
			break
		}
	}

	if imageType == ImageTypeDefault {
		return tag
	}

	return tag + "-" + imageType
}

func extractClusterAndNetwork(params InjectionParameters) (string, string) {
	metadata := &params.pod.ObjectMeta
	cluster := params.valuesConfig.stringValue("global", "multiCluster", "clusterName")
	network := params.valuesConfig.stringValue("global", "network")
	// params may be set from webhook URL, take priority over values yaml
	if params.proxyEnvs["ISTIO_META_CLUSTER_ID"] != "" {
		cluster = params.proxyEnvs["ISTIO_META_CLUSTER_ID"]
	}
	if params.proxyEnvs["ISTIO_META_NETWORK"] != "" {
		network = params.proxyEnvs["ISTIO_META_NETWORK"]
	}
	// explicit label takes highest precedence
	if n, ok := metadata.Labels[label.TopologyNetwork.Name]; ok {
		network = n
	}
	return cluster, network
}

// RunTemplate renders the sidecar template
// Returns the raw string template, as well as the parse pod form
func RunTemplate(params InjectionParameters) (mergedPod *corev1.Pod, templatePod *corev1.Pod, err error) {
	metadata := &params.pod.ObjectMeta
	if err := validateAnnotations(metadata.GetAnnotations()); err != nil {
		log.Error("injection failed due to invalid annotations", "error", err)
		return nil, nil, err
	}

	cluster, network := extractClusterAndNetwork(params)

	// use network in values for template, and proxy env variables
	if cluster != "" {
		params.proxyEnvs["ISTIO_META_CLUSTER_ID"] = cluster
	}
	if network != "" {
		params.proxyEnvs["ISTIO_META_NETWORK"] = network
	}

	strippedPod, err := reinsertOverrides(stripPod(params))
	if err != nil {
		return nil, nil, err
	}

	data := SidecarTemplateData{
		TypeMeta:       params.typeMeta,
		DeploymentMeta: params.deployMeta,
		ObjectMeta:     strippedPod.ObjectMeta,
		Spec:           strippedPod.Spec,
		ProxyConfig:    &params.settings.Proxy,
		MeshConfig: &TemplateMeshConfig{
			ProxyListenPort:        params.settings.ProxyListenPort,
			ProxyInboundListenPort: params.settings.ProxyInboundListenPort,
		},
		Values:         params.valuesConfig.asMap,
		ProxyImage:     ProxyImage(params.valuesConfig, "", strippedPod.Annotations),
		NativeSidecars: params.nativeSidecar,
		ProxyUID:       defaultProxyUID,
		ProxyGID:       defaultProxyUID,
	}
	if params.valuesConfig.asMap == nil {
		return nil, nil, fmt.Errorf("failed to parse values.yaml; check agentiod logs for errors")
	}

	mergedPod = params.pod
	templatePod = &corev1.Pod{}
	for _, templateName := range selectTemplates(params) {
		parsedTemplate, f := params.templates[templateName]
		if !f {
			return nil, nil, fmt.Errorf("requested template %q not found; have %v",
				templateName, strings.Join(knownTemplates(params.templates), ", "))
		}
		bbuf, err := runTemplate(parsedTemplate, data)
		if err != nil {
			return nil, nil, err
		}

		templatePod, err = applyOverlayYAML(templatePod, bbuf.Bytes())
		if err != nil {
			return nil, nil, fmt.Errorf("failed applying injection overlay: %v", err)
		}
		// With native sidecars the template proxy is in initContainers, but user customizations may put it in containers; move it to match.
		native := params.nativeSidecar
		if mergedPod.Annotations[nativeSidecarAnnotation] == "true" {
			native = true
		} else if mergedPod.Annotations[nativeSidecarAnnotation] == "false" {
			native = false
		}
		templateProxy := FindSidecar(templatePod)
		mergedProxy := FindSidecar(mergedPod)
		if native && templateProxy != nil && mergedProxy != nil &&
			FindContainer(templateProxy.Name, templatePod.Spec.InitContainers) != nil &&
			FindContainer(mergedProxy.Name, mergedPod.Spec.Containers) != nil {
			mergedPod = mergedPod.DeepCopy()
			mergedPod.Spec.Containers, mergedPod.Spec.InitContainers = moveContainer(mergedPod.Spec.Containers, mergedPod.Spec.InitContainers, mergedProxy.Name)
		}
		mergedPod, err = applyOverlayYAML(mergedPod, bbuf.Bytes())
		if err != nil {
			return nil, nil, fmt.Errorf("failed parsing generated injected YAML (check sidecar injector configuration): %v", err)
		}
	}

	return mergedPod, templatePod, nil
}

func knownTemplates(t Templates) []string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	return keys
}

// selectTemplates applies explicitly requested templates or the configured defaults.
func selectTemplates(params InjectionParameters) []string {
	if a, f := params.pod.Annotations[injectTemplatesAnnotation]; f {
		names := []string{}
		for tmplName := range strings.SplitSeq(a, ",") {
			name := strings.TrimSpace(tmplName)
			names = append(names, name)
		}
		return resolveAliases(params.aliases, names)
	}
	return resolveAliases(params.aliases, params.defaultTemplate)
}

func resolveAliases(aliases map[string][]string, names []string) []string {
	ret := []string{}
	for _, name := range names {
		if al, f := aliases[name]; f {
			ret = append(ret, al...)
		} else {
			ret = append(ret, name)
		}
	}
	return ret
}

func stripPod(req InjectionParameters) *corev1.Pod {
	pod := req.pod.DeepCopy()
	prevStatus := injectionStatus(pod)
	if prevStatus == nil {
		return req.pod
	}
	// We found a previous status annotation. Possibly we are re-injecting the pod
	// To ensure idempotency, remove our injected containers first
	for _, c := range prevStatus.Containers {
		pod.Spec.Containers = modifyContainers(pod.Spec.Containers, c, Remove)
	}
	for _, c := range prevStatus.InitContainers {
		pod.Spec.InitContainers = modifyContainers(pod.Spec.InitContainers, c, Remove)
	}

	targetPort := strconv.Itoa(req.settings.StatusPort)
	if cur, f := getPrometheusPort(pod); f {
		// We have already set the port, assume user is controlling this or, more likely, re-injected
		// the pod.
		if cur == targetPort {
			clearPrometheusAnnotations(pod)
		}
	}
	delete(pod.Annotations, annotation.SidecarStatus.Name)

	return pod
}

func injectionStatus(pod *corev1.Pod) *SidecarInjectionStatus {
	var statusBytes []byte
	if pod.ObjectMeta.Annotations != nil {
		if value, ok := pod.ObjectMeta.Annotations[annotation.SidecarStatus.Name]; ok {
			statusBytes = []byte(value)
		}
	}
	if statusBytes == nil {
		return nil
	}

	// default case when injected pod has explicit status
	var iStatus SidecarInjectionStatus
	if err := json.Unmarshal(statusBytes, &iStatus); err != nil {
		return nil
	}
	return &iStatus
}

func parseDryTemplate(tmplStr string, funcMap map[string]any) (*template.Template, error) {
	temp := template.New("inject")
	t, err := temp.Funcs(sprig.TxtFuncMap()).Funcs(funcMap).Parse(tmplStr)
	if err != nil {
		log.Error("parse injection template", "error", err, "template", tmplStr)
		return nil, err
	}

	return t, nil
}

func runTemplate(tmpl *template.Template, data SidecarTemplateData) (bytes.Buffer, error) {
	var res bytes.Buffer
	if err := tmpl.Execute(&res, &data); err != nil {
		log.Error("execute injection template", "error", err)
		return bytes.Buffer{}, err
	}

	return res, nil
}

// SidecarInjectionStatus contains basic information about the
// injected sidecar. This includes the names of added containers and
// volumes.
type SidecarInjectionStatus struct {
	InitContainers   []string `json:"initContainers"`
	Containers       []string `json:"containers"`
	Volumes          []string `json:"volumes"`
	ImagePullSecrets []string `json:"imagePullSecrets"`
}

func potentialPodName(metadata metav1.ObjectMeta) string {
	if metadata.Name != "" {
		return metadata.Name
	}
	if metadata.GenerateName != "" {
		return metadata.GenerateName + "***** (actual name not yet known)"
	}
	return ""
}

// overwriteClusterInfo updates cluster name and network from url path
// This is needed when webconfig config runs on a different cluster than webhook
func overwriteClusterInfo(pod *corev1.Pod, params InjectionParameters) {
	c := FindSidecar(pod)
	if c == nil {
		return
	}
	if len(params.proxyEnvs) > 0 {
		log.Debug("updating cluster environment from injection URL", "environment", params.proxyEnvs)
		updateClusterEnvs(c, params.proxyEnvs)
	}
}

func updateClusterEnvs(container *corev1.Container, newKVs map[string]string) {
	envVars := make([]corev1.EnvVar, 0)

	for _, env := range container.Env {
		if _, found := newKVs[env.Name]; !found {
			envVars = append(envVars, env)
		}
	}

	keys := make([]string, 0, len(newKVs))
	for key := range newKVs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		val := newKVs[key]
		envVars = append(envVars, corev1.EnvVar{Name: key, Value: val, ValueFrom: nil})
	}
	container.Env = envVars
}
