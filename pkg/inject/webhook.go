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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/openkruise/agentio/pkg/kube/kclient"
)

var (
	runtimeScheme = func() *runtime.Scheme {
		s := runtime.NewScheme()
		_ = corev1.AddToScheme(s)
		_ = admissionv1.AddToScheme(s)
		return s
	}()
	codecs       = serializer.NewCodecFactory(runtimeScheme)
	deserializer = codecs.UniversalDeserializer()

	URLParameterToEnv = map[string]string{
		"cluster": "ISTIO_META_CLUSTER_ID",
		"net":     "ISTIO_META_NETWORK",
	}
)

// maxRequestBody bounds admission request reads.
const maxRequestBody = 10 * 1024 * 1024

const (
	InitContainers = "initContainers"

	Containers = "containers"
)

// NativeSidecarMode controls native sidecar enablement.
type NativeSidecarMode string

const (
	NativeSidecarModeDisabled NativeSidecarMode = "false"
	NativeSidecarModeEnabled  NativeSidecarMode = "true"
	NativeSidecarModeAuto     NativeSidecarMode = "auto"
)

// Webhook implements a mutating webhook for automatic proxy injection.
type Webhook struct {
	mu               sync.RWMutex
	config           *Config
	settings         InjectionSettings
	valuesConfig     ValuesConfig
	discoveryAddress string

	trustConfig       krt.StaticSingleton[clienttrust.Settings]
	enableClientTrust bool
	nodes             kclient.Reader[*corev1.Node]
	nativeSidecarMode NativeSidecarMode
}

// WebhookParameters configures parameters for the ztunnel injection webhook.
type WebhookParameters struct {
	// EnableClientTrust is the process gate shared with the distributor.
	EnableClientTrust bool
	KrtOptions        krt.OptionsBuilder
	// Nodes optionally provides cached Node reads for native-sidecar
	// auto-detection. Nil disables detection: auto behaves as disabled.
	Nodes kclient.Reader[*corev1.Node]

	NativeSidecarMode NativeSidecarMode

	// Mux to register /inject on.
	Mux *http.ServeMux

	// DiscoveryAddress is the process-derived Agentio xDS/CA endpoint used
	// when the injector values do not provide an explicit address.
	DiscoveryAddress string
}

// NewWebhook creates a mutating webhook for automatic ztunnel injection.
// UpdateConfig installs the ztunnel template and its Agentio-native settings;
// until it arrives, requests are rejected so a half-configured injector cannot
// silently admit pods uninjected under failurePolicy Fail.
func NewWebhook(p WebhookParameters) (*Webhook, error) {
	if p.Mux == nil {
		return nil, fmt.Errorf("expected mux to be passed, but was not passed")
	}
	mode := p.NativeSidecarMode
	if mode == "" {
		mode = NativeSidecarModeAuto
	}
	wh := &Webhook{
		enableClientTrust: p.EnableClientTrust,
		nodes:             p.Nodes,
		trustConfig:       krt.NewStatic[clienttrust.Settings](nil, true, p.KrtOptions.WithName("Client_Trust_Config")...),
		nativeSidecarMode: mode,
		discoveryAddress:  p.DiscoveryAddress,
		settings:          defaultInjectionSettings(p.DiscoveryAddress),
	}
	p.Mux.HandleFunc("/inject", wh.serveInject)
	p.Mux.HandleFunc("/inject/", wh.serveInject)
	return wh, nil
}

// UpdateConfig installs a new injection Config and values document.
func (wh *Webhook) UpdateConfig(sidecarConfig *Config, valuesConfig string) error {
	vc, err := NewValuesConfig(valuesConfig)
	if err != nil {
		return fmt.Errorf("failed to create new values config: %v", err)
	}
	settings, err := injectionSettingsFromValues(vc, wh.discoveryAddress)
	if err != nil {
		return fmt.Errorf("failed to create injection settings: %w", err)
	}
	// A ConfigMap update cannot enable injection while its distributor is disabled.
	settings.ClientTrust.Client.Enabled = wh.enableClientTrust && settings.ClientTrust.Client.Enabled
	wh.mu.Lock()
	wh.config = sidecarConfig
	wh.valuesConfig = vc
	wh.settings = settings
	// Publish the same parsed settings for the distributor to observe.
	wh.trustConfig.Set(&settings.ClientTrust)
	wh.mu.Unlock()
	return nil
}

func toAdmissionResponse(err error) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{Result: &metav1.Status{Message: err.Error()}}
}

func (wh *Webhook) inject(ar *admissionv1.AdmissionReview, path string) *admissionv1.AdmissionResponse {
	requestLogger := log.With("path", path)
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		requestLogger.Error("unmarshal admission object", "error", err)
		return toAdmissionResponse(err)
	}
	// Managed fields is sometimes extremely large, leading to excessive CPU time on patch generation
	// It does not impact the injection output at all, so we can just remove it.
	pod.ManagedFields = nil

	// Deal with potential empty fields, e.g., when the pod is created by a deployment
	podName := potentialPodName(pod.ObjectMeta)
	if pod.ObjectMeta.Namespace == "" {
		pod.ObjectMeta.Namespace = req.Namespace
	}

	requestLogger = requestLogger.With("pod", pod.Namespace+"/"+podName)
	requestLogger.Info("processing injection request")

	wh.mu.RLock()
	if wh.config == nil {
		wh.mu.RUnlock()
		requestLogger.Error("injection configuration has not been loaded")
		return toAdmissionResponse(fmt.Errorf("injection config not ready"))
	}
	if !injectRequired(IgnoredNamespaces.UnsortedList(), wh.config, &pod.Spec, pod.ObjectMeta) {
		requestLogger.Info("skipping injection due to policy check")
		wh.mu.RUnlock()
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}
	}

	deploy, typeMeta := GetDeployMetaFromPod(&pod)

	params := InjectionParameters{
		pod:                 &pod,
		deployMeta:          deploy,
		typeMeta:            typeMeta,
		templates:           wh.config.Templates,
		defaultTemplate:     wh.config.DefaultTemplates,
		aliases:             wh.config.Aliases,
		settings:            wh.settings,
		valuesConfig:        wh.valuesConfig,
		injectedAnnotations: wh.config.InjectedAnnotations,
		proxyEnvs:           parseInjectEnvs(path),
	}

	params.nativeSidecar = detectNativeSidecar(wh.nodes, wh.nativeSidecarMode, pod.Spec.NodeName)

	wh.mu.RUnlock()

	result, err := injectPod(params)
	if err != nil {
		requestLogger.Error("pod injection failed", "error", err)
		return toAdmissionResponse(err)
	}

	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{
		Allowed:   true,
		Warnings:  result.Warnings,
		Patch:     result.Patch,
		PatchType: &patchType,
	}
}

func (wh *Webhook) serveInject(w http.ResponseWriter, r *http.Request) {
	requestLogger := log.With("path", r.URL.Path)
	var body []byte
	if r.Body != nil {
		data, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
		if err != nil {
			requestLogger.Error("read admission request body", "error", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body = data
	}
	if len(body) == 0 {
		requestLogger.Error("admission request body is empty")
		http.Error(w, "no body found", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		requestLogger.Error("invalid admission request content type",
			"content_type", contentType, "expected", "application/json")
		http.Error(w, "invalid Content-Type, want `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	path := ""
	if r.URL != nil {
		path = r.URL.Path
	}

	var reviewResponse *admissionv1.AdmissionResponse
	ar := &admissionv1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, ar); err != nil {
		requestLogger.Error("decode admission request body", "error", err)
		reviewResponse = toAdmissionResponse(err)
	} else if ar.Request == nil {
		err := fmt.Errorf("admission review request is missing")
		requestLogger.Error("invalid admission review", "error", err)
		reviewResponse = toAdmissionResponse(err)
	} else {
		reviewResponse = wh.inject(ar, path)
	}

	response := admissionv1.AdmissionReview{TypeMeta: ar.TypeMeta}
	if response.APIVersion == "" {
		response.APIVersion = admissionv1.SchemeGroupVersion.String()
		response.Kind = "AdmissionReview"
	}
	response.Response = reviewResponse
	if response.Response != nil && ar.Request != nil {
		response.Response.UID = ar.Request.UID
	}
	resp, err := json.Marshal(response)
	if err != nil {
		requestLogger.Error("encode admission response", "error", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := w.Write(resp); err != nil {
		requestLogger.Error("write admission response", "error", err)
	}
}

// parseInjectEnvs parse new envs from inject url path. format: /inject/k1/v1/k2/v2
// slash characters in values must be replaced by --slash-- (e.g. /inject/k1/abc--slash--def/k2/v2).
func parseInjectEnvs(path string) map[string]string {
	path = strings.TrimSuffix(path, "/")
	res := func(path string) []string {
		parts := strings.SplitN(path, "/", 3)
		var newRes []string
		if len(parts) == 3 { // If length is less than 3, then the path is simply "/inject".
			if strings.HasPrefix(parts[2], ":ENV:") {
				// Deprecated, not recommended.
				pairs := strings.Split(parts[2], ":ENV:")
				for i := 1; i < len(pairs); i++ { // skip the first part, it is a nil
					pair := strings.SplitN(pairs[i], "=", 2)
					if len(pair[0]) > 0 && len(pair) == 2 {
						newRes = append(newRes, pair...)
					}
				}
				return newRes
			}
			newRes = strings.Split(parts[2], "/")
		}
		for i, value := range newRes {
			if i%2 != 0 {
				// Replace --slash-- with / in values.
				newRes[i] = strings.ReplaceAll(value, "--slash--", "/")
			}
		}
		return newRes
	}(path)
	newEnvs := make(map[string]string)

	for i := 0; i < len(res); i += 2 {
		k := res[i]
		if i == len(res)-1 { // ignore the last key without value
			log.Warn("odd number of injection environment entries; ignoring final key", "key", k)
			break
		}

		env, found := URLParameterToEnv[k]
		if !found {
			env = strings.ToUpper(k) // if not found, use the custom env directly
		}
		if env != "" {
			newEnvs[env] = res[i+1]
		}
	}

	return newEnvs
}

// ClientTrustConfiguration lets the distributor subscribe to validated values updates.
func (wh *Webhook) ClientTrustConfiguration() krt.Singleton[clienttrust.Settings] {
	return wh.trustConfig
}
