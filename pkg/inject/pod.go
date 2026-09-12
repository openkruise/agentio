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
	"maps"
	"regexp"
	"strings"
	"text/template"

	"github.com/openkruise/agentio/pkg/clienttrust"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/api/annotation"
	"istio.io/api/label"
	"istio.io/istio/pkg/slices"
)

// ParsedContainers holds the unmarshalled containers and initContainers
type ParsedContainers struct {
	Containers     []corev1.Container `json:"containers,omitempty"`
	InitContainers []corev1.Container `json:"initContainers,omitempty"`
}

// AllContainers returns regular containers followed by init containers in a new slice.
func (p ParsedContainers) AllContainers() []corev1.Container {
	return append(slices.Clone(p.Containers), p.InitContainers...)
}

// InjectionParameters holds the Pod, templates, and settings for one injection.
type InjectionParameters struct {
	pod                 *corev1.Pod
	deployMeta          types.NamespacedName
	nativeSidecar       bool
	typeMeta            metav1.TypeMeta
	templates           map[string]*template.Template
	defaultTemplate     []string
	aliases             map[string][]string
	settings            InjectionSettings
	valuesConfig        ValuesConfig
	proxyEnvs           map[string]string
	injectedAnnotations map[string]string
}

func checkPreconditions(params InjectionParameters) {
	spec := params.pod.Spec
	metadata := params.pod.ObjectMeta
	// If DNSPolicy is not ClusterFirst, the sidecar may not able to connect to the control plane.
	if spec.DNSPolicy != "" && spec.DNSPolicy != corev1.DNSClusterFirst {
		podName := potentialPodName(metadata)
		log.Warn("pod DNS policy may prevent the proxy from connecting to the control plane",
			"pod", metadata.Namespace+"/"+podName, "dns_policy", spec.DNSPolicy,
			"recommended_dns_policy", corev1.DNSClusterFirst)
	}
}

func getInjectionStatus(podSpec corev1.PodSpec) string {
	stat := &SidecarInjectionStatus{}
	for _, c := range podSpec.InitContainers {
		stat.InitContainers = append(stat.InitContainers, c.Name)
	}
	for _, c := range podSpec.Containers {
		stat.Containers = append(stat.Containers, c.Name)
	}
	for _, c := range podSpec.Volumes {
		stat.Volumes = append(stat.Volumes, c.Name)
	}
	for _, c := range podSpec.ImagePullSecrets {
		stat.ImagePullSecrets = append(stat.ImagePullSecrets, c.Name)
	}
	statusAnnotationValue, err := json.Marshal(stat)
	if err != nil {
		return "{}"
	}
	return string(statusAnnotationValue)
}

// InjectionResult contains the admission patch and its diagnostics.
type InjectionResult struct {
	Patch    []byte
	Warnings []string
}

func isClientTrustExcludedContainer(name string) bool {
	return isProxyContainerName(name) || name == InitContainerName || name == ValidationContainerName || name == "istio-init" || name == "istio-validation"
}

// injectPod is the core of the injection logic. This takes a pod and injection
// template, as well as some inputs to the injection template, and produces a
// JSON patch.
func injectPod(req InjectionParameters) (InjectionResult, error) {
	checkPreconditions(req)

	// The patch will be built relative to the initial pod, capture its current state
	originalPodSpec, err := json.Marshal(req.pod)
	if err != nil {
		return InjectionResult{}, err
	}

	// Run the injection template, giving us a partial pod spec
	mergedPod, injectedPodData, err := RunTemplate(req)
	if err != nil {
		return InjectionResult{}, fmt.Errorf("failed to run injection template: %w", err)
	}

	mergedPod, err = reapplyOverwrittenContainers(mergedPod, req.pod, injectedPodData, &req.settings.Proxy)
	if err != nil {
		return InjectionResult{}, fmt.Errorf("failed to re apply container: %w", err)
	}

	// Apply some additional transformations to the pod
	if err := postProcessPod(mergedPod, *injectedPodData, req); err != nil {
		return InjectionResult{}, fmt.Errorf("failed to process pod: %w", err)
	}

	var warnings []string
	// Only ztunnel supports client trust injection. Template aliases are already expanded.
	if slices.Contains(selectTemplates(req), "ztunnel") {
		var trustErr error
		warnings, trustErr = clienttrust.Apply(req.pod, mergedPod, req.settings.ClientTrust, isClientTrustExcludedContainer)
		if trustErr != nil {
			return InjectionResult{}, fmt.Errorf("client trust injection: %w", trustErr)
		}
	}
	patch, err := createPatch(mergedPod, originalPodSpec)
	if err != nil {
		return InjectionResult{}, fmt.Errorf("failed to create patch: %w", err)
	}

	log.Debug("generated admission response", "patch", string(patch))
	return InjectionResult{Patch: patch, Warnings: warnings}, nil
}

// reapplyOverwrittenContainers enables users to provide container level overrides for settings in the injection template
// * originalPod: the pod before injection. If needed, we will apply some configurations from this pod on top of the final pod
// * templatePod: the rendered injection template. This is needed only to see what containers we injected
// * finalPod: the current result of injection, roughly equivalent to the merging of originalPod and templatePod
// There are essentially three cases we cover here:
//  1. There is no overlap in containers in original and template pod. We will do nothing.
//  2. There is an overlap (both define the proxy), but that is because the pod is being re-injected.
//     In this case we do nothing, since we want to apply the new settings
//  3. There is an overlap. We will re-apply the original container.
//
// Where "overlap" is a container defined in both the original and template pod. Typically, this would mean
// the user has defined a proxy container in their own pod spec.
func reapplyOverwrittenContainers(finalPod *corev1.Pod, originalPod *corev1.Pod, templatePod *corev1.Pod,
	proxyConfig *ProxyConfig,
) (*corev1.Pod, error) {
	overrides := ParsedContainers{}
	existingOverrides := ParsedContainers{}
	if annotationOverrides, f := originalPod.Annotations[annotation.ProxyOverrides.Name]; f {
		if err := json.Unmarshal([]byte(annotationOverrides), &existingOverrides); err != nil {
			return nil, err
		}
	}
	parsedInjectedStatus := ParsedContainers{}
	status, alreadyInjected := originalPod.Annotations[annotation.SidecarStatus.Name]
	if alreadyInjected {
		parsedInjectedStatus = parseStatus(status)
	}
	for _, c := range templatePod.Spec.Containers {
		// sidecarStatus annotation is added on the pod by webhook. We should use new container template
		// instead of restoring what may be previously injected. Doing this ensures we are correctly calculating
		// env variables like ISTIO_META_APP_CONTAINERS and ISTIO_META_POD_PORTS.
		if match := FindContainer(c.Name, parsedInjectedStatus.Containers); match != nil {
			continue
		}
		match := FindContainer(c.Name, existingOverrides.Containers)
		if match == nil {
			match = FindContainer(c.Name, originalPod.Spec.Containers)
		}
		if match == nil {
			continue
		}
		overlay := *match.DeepCopy()
		if overlay.Image == AutoImage {
			overlay.Image = ""
		}

		overrides.Containers = append(overrides.Containers, overlay)
		newMergedPod, err := applyContainer(finalPod, overlay)
		if err != nil {
			return nil, fmt.Errorf("failed to apply sidecar container: %w", err)
		}
		finalPod = newMergedPod
	}
	for _, c := range templatePod.Spec.InitContainers {
		if match := FindContainer(c.Name, parsedInjectedStatus.InitContainers); match != nil {
			continue
		}
		match := FindContainer(c.Name, existingOverrides.InitContainers)
		if match == nil {
			match = FindContainerFromPod(c.Name, originalPod)
		}
		if match == nil {
			continue
		}
		overlay := *match.DeepCopy()
		if overlay.Image == AutoImage {
			overlay.Image = ""
		}

		overrides.InitContainers = append(overrides.InitContainers, overlay)
		newMergedPod, err := applyInitContainer(finalPod, overlay)
		if err != nil {
			return nil, fmt.Errorf("failed to apply sidecar init container: %w", err)
		}
		finalPod = newMergedPod
	}

	if err := recordContainerOverrides(finalPod, overrides, alreadyInjected); err != nil {
		return nil, err
	}

	adjustInitContainerUser(finalPod, originalPod, proxyConfig)

	return finalPod, nil
}

func recordContainerOverrides(finalPod *corev1.Pod, overrides ParsedContainers, alreadyInjected bool) error {
	if !alreadyInjected && (len(overrides.Containers) > 0 || len(overrides.InitContainers) > 0) {
		// We found any overrides. Put them in the pod annotation so we can re-apply them on re-injection
		js, err := json.Marshal(overrides)
		if err != nil {
			return err
		}
		if finalPod.Annotations == nil {
			finalPod.Annotations = map[string]string{}
		}
		finalPod.Annotations[annotation.ProxyOverrides.Name] = string(js)
	}

	return nil
}

// adjustInitContainerUser adjusts the RunAsUser/Group fields and iptables parameter "-u <uid>"
// in the init/validation container so that they match the value of SecurityContext.RunAsUser/Group
// when it is present in the custom proxy container supplied by the user.
func adjustInitContainerUser(finalPod *corev1.Pod, originalPod *corev1.Pod, proxyConfig *ProxyConfig) {
	userContainer := FindSidecar(originalPod)
	if userContainer == nil {
		// If the user does not override the proxy container, there is nothing to do.
		return
	}

	if userContainer.SecurityContext == nil || (userContainer.SecurityContext.RunAsUser == nil && userContainer.SecurityContext.RunAsGroup == nil) {
		// if user doesn't override SecurityContext.RunAsUser/Group, there's nothing to do
		return
	}

	// Locate the agentio-init or agentio-validation container
	var initContainer *corev1.Container
	for _, name := range []string{InitContainerName, ValidationContainerName} {
		if container := FindContainer(name, finalPod.Spec.InitContainers); container != nil {
			initContainer = container
			break
		}
	}
	if initContainer == nil {
		// should not happen
		log.Warn("could not find either agentio-init or agentio-validation container")
		return
	}

	// Overriding RunAsUser is not allowed in TPROXY mode, it must always run with uid=0
	tproxy := false
	if proxyConfig.InterceptionMode == "TPROXY" {
		tproxy = true
	} else if mode, found := finalPod.Annotations[annotation.SidecarInterceptionMode.Name]; found && mode == "TPROXY" {
		tproxy = true
	}

	// RunAsUser cannot be overridden (ie, must remain 0) in TPROXY mode
	if tproxy && userContainer.SecurityContext.RunAsUser != nil {
		sidecar := FindSidecar(finalPod)
		if sidecar == nil {
			// Should not happen
			log.Warn("could not find the proxy container")
			return
		}
		*sidecar.SecurityContext.RunAsUser = 0
	}

	if !tproxy {
		alignValidationUser(initContainer, userContainer.SecurityContext)
	}

	// Find the "-u <uid>" parameter in the init container and replace it with the userid from SecurityContext.RunAsUser
	// but only if it's not 0. iptables --uid-owner argument must not be 0.
	if userContainer.SecurityContext.RunAsUser == nil || *userContainer.SecurityContext.RunAsUser == 0 {
		return
	}
	for i := range initContainer.Args {
		if initContainer.Args[i] == "-u" {
			initContainer.Args[i+1] = fmt.Sprintf("%d", *userContainer.SecurityContext.RunAsUser)
			return
		}
	}
}

// parseStatus extracts containers from injected SidecarStatus annotation
func parseStatus(status string) ParsedContainers {
	parsedContainers := ParsedContainers{}
	var unMarshalledStatus map[string]any
	if err := json.Unmarshal([]byte(status), &unMarshalledStatus); err != nil {
		log.Error("unmarshal sidecar status annotation",
			"annotation", annotation.SidecarStatus.Name, "error", err)
		return parsedContainers
	}
	parser := func(key string, obj map[string]any) []corev1.Container {
		out := make([]corev1.Container, 0)
		if value, exist := obj[key]; exist && value != nil {
			for _, v := range value.([]any) {
				out = append(out, corev1.Container{Name: v.(string)})
			}
		}
		return out
	}
	parsedContainers.Containers = parser(Containers, unMarshalledStatus)
	parsedContainers.InitContainers = parser(InitContainers, unMarshalledStatus)

	return parsedContainers
}

// reinsertOverrides applies the containers listed in OverrideAnnotation to a pod. This is to achieve
// idempotency by handling an edge case where an injection template is modifying a container already
// present in the pod spec. In these cases, the logic to strip injected containers would remove the
// original injected parts as well, leading to the templating logic being different (for example,
// reading the .Spec.Containers field would be empty).
func reinsertOverrides(pod *corev1.Pod) (*corev1.Pod, error) {
	type podOverrides struct {
		Containers     []corev1.Container `json:"containers,omitempty"`
		InitContainers []corev1.Container `json:"initContainers,omitempty"`
	}

	existingOverrides := podOverrides{}
	if annotationOverrides, f := pod.Annotations[annotation.ProxyOverrides.Name]; f {
		if err := json.Unmarshal([]byte(annotationOverrides), &existingOverrides); err != nil {
			return nil, err
		}
	}

	pod = pod.DeepCopy()
	for _, c := range existingOverrides.Containers {
		match := FindContainer(c.Name, pod.Spec.Containers)
		if match != nil {
			continue
		}
		pod.Spec.Containers = append(pod.Spec.Containers, c)
	}

	for _, c := range existingOverrides.InitContainers {
		match := FindContainer(c.Name, pod.Spec.InitContainers)
		if match != nil {
			continue
		}
		pod.Spec.InitContainers = append(pod.Spec.InitContainers, c)
	}

	return pod, nil
}

// postProcessPod applies additionally transformations to the pod after merging with the injected template
// This is generally things that cannot reasonably be added to the template
func postProcessPod(pod *corev1.Pod, injectedPod corev1.Pod, req InjectionParameters) error {
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}

	overwriteClusterInfo(pod, req)

	if err := applyPrometheusMerge(pod, req.settings); err != nil {
		return err
	}

	if err := applyRewrite(pod, req); err != nil {
		return err
	}

	applyMetadata(pod, injectedPod, req)

	if err := reorderPod(pod, req); err != nil {
		return err
	}

	return nil
}

func applyMetadata(pod *corev1.Pod, injectedPodData corev1.Pod, req InjectionParameters) {
	if nw, ok := req.proxyEnvs["ISTIO_META_NETWORK"]; ok {
		pod.Labels[label.TopologyNetwork.Name] = nw
	}
	// Add all additional injected annotations. These are overridden if needed
	pod.Annotations[annotation.SidecarStatus.Name] = getInjectionStatus(injectedPodData.Spec)

	// Deprecated; should be set directly in the template instead
	maps.Copy(pod.Annotations, req.injectedAnnotations)
}

func applyRewrite(pod *corev1.Pod, req InjectionParameters) error {
	sidecar := FindSidecar(pod)
	if sidecar == nil {
		return nil
	}

	rewrite := ShouldRewriteAppHTTPProbers(pod.Annotations, req.valuesConfig.boolValue("sidecarInjectorWebhook", "rewriteAppHTTPProbe"))
	// We don't have to escape json encoding here when using golang libraries.
	if rewrite {
		if prober := DumpAppProbers(pod, int32(req.settings.StatusPort)); prober != "" {
			// If sidecar.istio.io/status is not present then append instead of merge.
			_, previouslyInjected := pod.Annotations[annotation.SidecarStatus.Name]
			sidecar.Env = mergeOrAppendProbers(previouslyInjected, sidecar.Env, prober)
		}
		patchRewriteProbe(pod.Annotations, pod, int32(req.settings.StatusPort))
	}
	return nil
}

// mergeOrAppendProbers ensures that if sidecar has existing ISTIO_KUBE_APP_PROBERS,
// then probers should be merged.
func mergeOrAppendProbers(previouslyInjected bool, envVars []corev1.EnvVar, newProbers string) []corev1.EnvVar {
	if !previouslyInjected {
		return append(envVars, corev1.EnvVar{Name: KubeAppProberEnvName, Value: newProbers})
	}
	for idx, env := range envVars {
		if env.Name == KubeAppProberEnvName {
			var existingKubeAppProber KubeAppProbers
			err := json.Unmarshal([]byte(env.Value), &existingKubeAppProber)
			if err != nil {
				log.Error("unmarshal existing kube app probers", "error", err)
				return envVars
			}
			var newKubeAppProber KubeAppProbers
			err = json.Unmarshal([]byte(newProbers), &newKubeAppProber)
			if err != nil {
				log.Error("unmarshal new kube app probers", "error", err)
				return envVars
			}
			// merge old and new probers.
			maps.Copy(newKubeAppProber, existingKubeAppProber)
			marshalledKubeAppProber, err := json.Marshal(newKubeAppProber)
			if err != nil {
				log.Error("serialize merged app prober configuration", "error", err)
				return envVars
			}
			// replace old env var with new value.
			envVars[idx] = corev1.EnvVar{Name: KubeAppProberEnvName, Value: string(marshalledKubeAppProber)}
			return envVars
		}
	}
	return append(envVars, corev1.EnvVar{Name: KubeAppProberEnvName, Value: newProbers})
}

// cronJobNameRegexp matches "-<8-10 digit timestamp>" suffixes on Job names.
var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

// GetDeployMetaFromPod heuristically derives deployment metadata from the pod spec.
func GetDeployMetaFromPod(pod *corev1.Pod) (types.NamespacedName, metav1.TypeMeta) {
	if pod == nil {
		return types.NamespacedName{}, metav1.TypeMeta{}
	}
	// try to capture more useful namespace/name info for deployments, etc.
	deployMeta := types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}

	typeMetadata := metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}
	if len(pod.GenerateName) > 0 {
		// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
		var controllerRef metav1.OwnerReference
		controllerFound := false
		for _, ref := range pod.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller {
				controllerRef = ref
				controllerFound = true
				break
			}
		}
		if controllerFound {
			typeMetadata.APIVersion = controllerRef.APIVersion
			typeMetadata.Kind = controllerRef.Kind

			// heuristic for deployment detection
			deployMeta.Name = controllerRef.Name
			if typeMetadata.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else if typeMetadata.Kind == "ReplicaSet" && pod.Labels["rollouts-pod-template-hash"] != "" &&
				strings.HasSuffix(controllerRef.Name, pod.Labels["rollouts-pod-template-hash"]) {
				// Heuristic for ArgoCD Rollout
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["rollouts-pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Rollout"
				typeMetadata.APIVersion = "v1alpha1"
			} else if typeMetadata.Kind == "ReplicationController" && pod.Labels["deploymentconfig"] != "" {
				// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
				// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
				deployMeta.Name = pod.Labels["deploymentconfig"]
				typeMetadata.Kind = "DeploymentConfig"
			} else if typeMetadata.Kind == "Job" {
				// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
				// trim the suffix and set kind to cron job.
				if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
					deployMeta.Name = jn[1]
					typeMetadata.Kind = "CronJob"
					// heuristically set cron job api version to v1 as it cannot be derived from pod metadata.
					typeMetadata.APIVersion = "batch/v1"
				}
			}
		}
	}

	if deployMeta.Name == "" {
		// if we haven't been able to extract a deployment name, then just give it the pod name
		deployMeta.Name = pod.Name
	}

	return deployMeta, typeMetadata
}

func alignValidationUser(initContainer *corev1.Container, securityContext *corev1.SecurityContext) {
	// Make sure the validation container runs with the same uid/gid as the proxy (init container is untouched, it must run with 0)
	if initContainer.Name == ValidationContainerName {
		if initContainer.SecurityContext == nil {
			initContainer.SecurityContext = &corev1.SecurityContext{}
		}
		if securityContext.RunAsUser != nil {
			initContainer.SecurityContext.RunAsUser = securityContext.RunAsUser
		}
		if securityContext.RunAsGroup != nil {
			initContainer.SecurityContext.RunAsGroup = securityContext.RunAsGroup
		}
	}
}
