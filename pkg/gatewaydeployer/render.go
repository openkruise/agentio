// Copyright Istio Authors
// Modifications Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package gatewaydeployer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/golang/protobuf/jsonpb"
	legacyproto "github.com/golang/protobuf/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	meshv1alpha1 "istio.io/api/mesh/v1alpha1"
	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

type TemplateInput struct {
	*gatewayv1.Gateway
	GatewayClass              string
	DeploymentName            string
	ServiceAccount            string
	Ports                     []corev1.ServicePort
	ServiceType               corev1.ServiceType
	ClusterID                 string
	KubeVersion               int
	NativeSidecars            bool
	ProxyUID                  int64
	ProxyGID                  int64
	CompliancePolicy          string
	InfrastructureLabels      map[string]string
	InfrastructureAnnotations map[string]string
	GatewayNameLabel          string
	IsEastWestGateway         bool
	ControllerLabel           string
	AgentgatewayConfigName    string
	AgentgatewayConfigHash    string
	AgentgatewayConfig        string
	AgentgatewayTrustBundle   string
}

type renderer struct {
	state atomic.Pointer[renderState]
}

type renderState struct {
	values      map[string]any
	proxyConfig *meshv1alpha1.ProxyConfig
	trustDomain string
	templates   map[string]*template.Template
}

func (r *renderer) update(name, content string, values map[string]any, proxyConfig *meshv1alpha1.ProxyConfig) error {
	return r.updateTemplates(map[string]string{name: content}, values, proxyConfig)
}

// Publish templates and values as one snapshot; a malformed template must not
// leave one data plane using a different configuration generation.
func (r *renderer) updateTemplates(
	contents map[string]string,
	values map[string]any,
	proxyConfig *meshv1alpha1.ProxyConfig,
) error {
	templates := make(map[string]*template.Template, len(contents))
	for name, content := range contents {
		t, err := template.New(name).Funcs(templateFuncs()).Parse(content)
		if err != nil {
			return fmt.Errorf("parse %s template: %w", name, err)
		}
		templates[name] = t
	}
	current := r.state.Load()
	r.state.Store(&renderState{
		values:      values,
		proxyConfig: proxyConfig,
		trustDomain: current.trustDomain,
		templates:   templates,
	})
	return nil
}

type derivedInput struct {
	TemplateInput
	ProxyImage  string
	ProxyConfig *meshv1alpha1.ProxyConfig
	TrustDomain string
	Values      map[string]any
}

func newRenderer(
	values func() map[string]any,
	proxyConfig *meshv1alpha1.ProxyConfig,
	trustDomain string,
) (*renderer, error) {
	r := &renderer{}
	r.state.Store(&renderState{
		values:      values(),
		proxyConfig: proxyConfig,
		trustDomain: trustDomain,
		templates:   map[string]*template.Template{},
	})
	return r, nil
}

// globalNetwork reads global.network from the values map.
func (r *renderer) globalNetwork() string {
	values := r.state.Load().values
	global, ok := values["global"].(map[string]any)
	if !ok {
		return ""
	}
	network, _ := global["network"].(string)
	return network
}

func (r *renderer) Render(templateName string, input TemplateInput) ([]string, error) {
	state := r.state.Load()
	t := state.templates[templateName]
	if t == nil {
		return nil, fmt.Errorf("no %q template defined", templateName)
	}
	values := state.values
	proxyConfig := proto.Clone(state.proxyConfig).(*meshv1alpha1.ProxyConfig)
	in := derivedInput{
		TemplateInput: input,
		ProxyImage:    proxyImage(values),
		ProxyConfig:   proxyConfig,
		TrustDomain:   state.trustDomain,
		Values:        values,
	}
	var b bytes.Buffer
	if err := t.Execute(&b, in); err != nil {
		return nil, err
	}
	parts := strings.Split(b.String(), "\n---\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(p), &meta); err != nil {
			return nil, err
		}
		switch meta.Kind {
		case "ConfigMap":
			if templateName == agentgatewayTemplateName && input.AgentgatewayConfig != "" {
				out = append(out, p)
			}
		case "Deployment", "Service", "ServiceAccount", "HorizontalPodAutoscaler", "PodDisruptionBudget":
			out = append(out, p)
		default:
			log.Warn("dropping rendered document of unsupported kind", "kind", meta.Kind, "template", templateName)
		}
	}
	return out, nil
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"quote":   func(v any) string { return fmt.Sprintf("%q", v) },
		"nindent": func(n int, s string) string { return "\n" + sprigIndent(n, s) },
		"indent":  upstreamIndent,
		"default": func(d, v any) any {
			if empty(v) {
				return d
			}
			return v
		},
		"contains":   func(needle, haystack string) bool { return strings.Contains(haystack, needle) },
		"trim":       strings.TrimSpace,
		"toYaml":     toYAML,
		"toJson":     toJSON,
		"toJsonMap":  toJSONMap,
		"annotation": annotationValue,
		"valueOrDefault": func(v, d any) any {
			if v == "" || v == nil {
				return d
			}
			return v
		},
		"protoToJSON": protoToJSON,
		"omit":        omit,
		"omitNil":     omitNil,
		"strdict":     strdict,
	}
}

func sprigIndent(n int, s string) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}

func upstreamIndent(n int, s string) string {
	res := strings.Split(s, "\n")
	for i, line := range res {
		if i > 0 {
			res[i] = fmt.Sprintf(fmt.Sprintf("%% %ds%%s", n), "", line)
		}
	}
	return strings.Join(res, "\n")
}
func toYAML(v any) (string, error) {
	b, err := yaml.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
func toJSONMap(ms ...map[string]string) (string, error) {
	m := map[string]string{}
	for _, mm := range ms {
		maps.Copy(m, mm)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
func strdict(vals ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(vals); i += 2 {
		if i+1 >= len(vals) {
			m[vals[i]] = ""
			continue
		}
		m[vals[i]] = vals[i+1]
	}
	return m
}
func annotationValue(meta metav1.ObjectMeta, name string, def any) string {
	if meta.Annotations != nil {
		if v, ok := meta.Annotations[name]; ok {
			return v
		}
	}
	return fmt.Sprint(def)
}
func omit(m map[string]string, keys ...string) map[string]string {
	out := map[string]string{}
	skip := sets.New[string]()
	for _, k := range keys {
		skip.Insert(k)
	}
	for k, v := range m {
		if !skip.Contains(k) {
			out[k] = v
		}
	}
	return out
}
func omitNil(v any) any {
	res, _ := omitNilInternal(v)
	return res
}
func omitNilInternal(v any) (any, bool) {
	if v == nil {
		return nil, true
	}
	switch v := v.(type) {
	case map[string]any:
		for _, val := range v {
			if _, changed := omitNilInternal(val); changed {
				out := make(map[string]any, len(v))
				for k2, v2 := range v {
					if f := omitNil(v2); f != nil {
						out[k2] = f
					}
				}
				if len(out) == 0 {
					return nil, true
				}
				return out, true
			}
		}
		return v, false
	case []any:
		for i, val := range v {
			if _, changed := omitNilInternal(val); changed {
				out := make([]any, 0, len(v))
				for j := range i {
					out = append(out, v[j])
				}
				for j := i; j < len(v); j++ {
					if f := omitNil(v[j]); f != nil {
						out = append(out, f)
					}
				}
				if len(out) == 0 {
					return nil, true
				}
				return out, true
			}
		}
		return v, false
	default:
		return v, false
	}
}
func protoToJSON(p proto.Message) (string, error) {
	p = cleanProxyConfig(p)
	if p == nil {
		return "{}", nil
	}
	return protoToJSONCanonical(p)
}

func protoToJSONCanonical(msg proto.Message) (string, error) {
	if msg == nil {
		return "", errors.New("unexpected nil message")
	}
	m := jsonpb.Marshaler{}
	return m.MarshalToString(legacyproto.MessageV1(msg))
}

func cleanProxyConfig(msg proto.Message) proto.Message {
	originalProxyConfig, ok := msg.(*meshv1alpha1.ProxyConfig)
	if !ok || originalProxyConfig == nil {
		return msg
	}
	pc := proto.Clone(originalProxyConfig).(*meshv1alpha1.ProxyConfig)
	defaults := defaultProxyConfigDefaults()
	if pc.BinaryPath == defaults.BinaryPath {
		pc.BinaryPath = ""
	}
	if pc.ControlPlaneAuthPolicy == defaults.ControlPlaneAuthPolicy {
		pc.ControlPlaneAuthPolicy = 0
	}
	if x, ok := pc.GetClusterName().(*meshv1alpha1.ProxyConfig_ServiceCluster); ok {
		if dx, ok := defaults.GetClusterName().(*meshv1alpha1.ProxyConfig_ServiceCluster); ok &&
			x.ServiceCluster == dx.ServiceCluster {
			pc.ClusterName = nil
		}
	}
	if proto.Equal(pc.DrainDuration, defaults.DrainDuration) {
		pc.DrainDuration = nil
	}
	if proto.Equal(pc.TerminationDrainDuration, defaults.TerminationDrainDuration) {
		pc.TerminationDrainDuration = nil
	}
	if proto.Equal(pc.EnvoyMetricsService, defaults.EnvoyMetricsService) {
		pc.EnvoyMetricsService = nil
	}
	if proto.Equal(pc.EnvoyAccessLogService, defaults.EnvoyAccessLogService) {
		pc.EnvoyAccessLogService = nil
	}
	if proto.Equal(pc.Tracing, defaults.Tracing) {
		pc.Tracing = nil
	}
	if pc.ProxyAdminPort == defaults.ProxyAdminPort {
		pc.ProxyAdminPort = 0
	}
	if pc.StatNameLength == defaults.StatNameLength {
		pc.StatNameLength = 0
	}
	if pc.StatusPort == defaults.StatusPort {
		pc.StatusPort = 0
	}
	if proto.Equal(pc.Concurrency, defaults.Concurrency) {
		pc.Concurrency = nil
	}
	if len(pc.ProxyMetadata) == 0 {
		pc.ProxyMetadata = nil
	}
	return proto.Message(pc)
}

func defaultProxyConfigDefaults() *meshv1alpha1.ProxyConfig {
	return &meshv1alpha1.ProxyConfig{
		ClusterName:              &meshv1alpha1.ProxyConfig_ServiceCluster{ServiceCluster: "agentio-proxy"},
		DrainDuration:            durationpb.New(45 * time.Second),
		TerminationDrainDuration: durationpb.New(5 * time.Second),
		ProxyAdminPort:           15000,
		ControlPlaneAuthPolicy:   meshv1alpha1.AuthenticationPolicy_MUTUAL_TLS,
		BinaryPath:               "/usr/local/bin/envoy",
		StatNameLength:           189,
		StatusPort:               15020,
	}
}

func empty(v any) bool {
	if v == nil {
		return true
	}
	value := reflect.ValueOf(v)
	for value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return true
		}
		value = value.Elem()
	}
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool:
		return !value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Complex64, reflect.Complex128:
		return value.Complex() == 0
	case reflect.Struct:
		return false
	}
	return value.IsZero()
}

func extractServicePorts(gw gatewayv1.Gateway) []corev1.ServicePort {
	tcp := "tcp"
	ports := []corev1.ServicePort{{Name: "status-port", Port: 15021, AppProtocol: &tcp}}
	seen := sets.New[int32]()
	for i, l := range gw.Spec.Listeners {
		if seen.Contains(l.Port) {
			continue
		}
		seen.Insert(l.Port)
		name := sanitizeListenerNameForPort(string(l.Name))
		if name == "" {
			name = fmt.Sprintf("%s-%d", strings.ToLower(string(l.Protocol)), i)
		}
		app := strings.ToLower(string(l.Protocol))
		ports = append(ports, corev1.ServicePort{Name: name, Port: l.Port, AppProtocol: &app})
	}
	return ports
}
func sanitizeListenerNameForPort(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		valid := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if valid {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if r == '-' {
			if b.Len() > 0 && !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
			continue
		}
		if b.Len() > 0 && !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 63 {
		out = out[:63]
	}
	return strings.TrimRight(out, "-")
}
func extractInfrastructureLabels(gw gatewayv1.Gateway) map[string]string {
	return extractInfrastructureMetadata(gw.Spec.Infrastructure, true, gw)
}
func extractInfrastructureAnnotations(gw gatewayv1.Gateway) map[string]string {
	return extractInfrastructureMetadata(gw.Spec.Infrastructure, false, gw)
}

func extractInfrastructureMetadata(
	infra *gatewayv1.GatewayInfrastructure,
	labels bool,
	gw gatewayv1.Gateway,
) map[string]string {
	out := map[string]string{}
	// Unset fields inherit Gateway metadata even when parametersRef is set.
	if infra != nil && labels && infra.Labels != nil {
		for k, v := range infra.Labels {
			if !strings.HasPrefix(string(k), "gateway.networking.k8s.io/") {
				out[string(k)] = string(v)
			}
		}
		return out
	}
	if infra != nil && !labels && infra.Annotations != nil {
		for k, v := range infra.Annotations {
			if !strings.HasPrefix(string(k), "gateway.networking.k8s.io/") {
				out[string(k)] = string(v)
			}
		}
		return out
	}
	src := gw.Labels
	if !labels {
		src = gw.Annotations
	}
	maps.Copy(out, src)
	return out
}

// proxyImage builds the proxy image exclusively from operator-controlled
// values. Gateway annotations must not influence it: anyone allowed to create
// a Gateway could otherwise pick the image the deployment runs.
func proxyImage(values map[string]any) string {
	g, _ := values["global"].(map[string]any)
	p, _ := g["proxy"].(map[string]any)
	hub := strings.TrimSuffix(fmt.Sprint(g["hub"]), "/")
	tag := ""
	if t, ok := g["tag"]; ok && t != nil {
		tag = fmt.Sprintf("%v", t)
	}
	imageType := ""
	if v, ok := g["variant"]; ok && v != nil {
		imageType = fmt.Sprint(v)
	}
	if v, ok := p["imageType"]; ok {
		imageType = fmt.Sprint(v)
	}
	image := "agentio-gateway"
	if p["image"] != nil && fmt.Sprint(p["image"]) != "" {
		image = fmt.Sprint(p["image"])
	}
	// Upstream injection templates treat any value containing "/" as a full
	// image reference and use it verbatim, skipping hub/tag concatenation.
	if strings.Contains(image, "/") {
		return image
	}
	return hub + "/" + image + ":" + updateImageTypeIfPresent(tag, imageType)
}

func updateImageTypeIfPresent(tag string, imageType string) string {
	if imageType == "" {
		return tag
	}
	for _, i := range []string{"distroless", "debug"} {
		if strings.HasSuffix(tag, "-"+i) {
			tag = tag[:len(tag)-(len(i)+1)]
			break
		}
	}
	if imageType == "default" {
		return tag
	}
	return tag + "-" + imageType
}

func defaultProxyConfig() *meshv1alpha1.ProxyConfig {
	return defaultProxyConfigDefaults()
}
