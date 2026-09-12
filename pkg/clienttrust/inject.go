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

package clienttrust

import (
	"fmt"
	"path"
	"reflect"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"

	"istio.io/istio/pkg/util/sets"
)

// Apply augments selected original business containers in an already injected Pod.
// It never changes the original Pod or the configuration snapshot.
func Apply(original, pod *corev1.Pod, s Settings, excluded func(string) bool) ([]string, error) {
	enabled, err := s.Client.EnabledFor(original.Annotations)
	if err != nil || !enabled {
		return nil, err
	}
	selected, warnings, err := selectContainers(original, s.Client.Containers, excluded)
	if err != nil || len(selected) == 0 {
		return warnings, err
	}
	mounts, managed, err := installVolumes(pod, s)
	if err != nil {
		return nil, err
	}
	variables := s.Client.variables()
	for _, containers := range [][]corev1.Container{pod.Spec.Containers, pod.Spec.InitContainers} {
		for i := range containers {
			container := &containers[i]
			if !selected.Contains(container.Name) {
				continue
			}
			if err := installMounts(container, mounts); err != nil {
				return nil, err
			}
			warnings = append(warnings, installEnv(container, variables, s.Client.EnvConflictPolicy)...)
		}
	}
	if managed {
		markManaged(pod, s.Bundle.Target.ConfigMapName)
	}
	// Admission warnings are diagnostics, not a copy of all application configuration.
	if len(warnings) > 20 {
		warnings = append(warnings[:20], "client trust: additional environment conflicts omitted")
	}
	return warnings, nil
}

func selectContainers(pod *corev1.Pod, c Containers, excluded func(string) bool) (sets.Set[string], []string, error) {
	include, err := Patterns(pod.Annotations, IncludeAnnotation, c.Include)
	if err != nil {
		return nil, nil, err
	}
	exclude, err := Patterns(pod.Annotations, ExcludeAnnotation, c.Exclude)
	if err != nil {
		return nil, nil, err
	}
	candidates := slices.Clone(pod.Spec.Containers)
	if c.IncludeInitContainers {
		candidates = append(candidates, pod.Spec.InitContainers...)
	}
	selected := sets.New[string]()
	matched := 0
	for _, container := range candidates {
		if excluded(container.Name) {
			continue
		}
		if len(include) > 0 && !Matches(include, container.Name) {
			continue
		}
		matched++
		if !Matches(exclude, container.Name) {
			selected.Insert(container.Name)
		}
	}
	if len(include) > 0 && matched == 0 {
		return nil, []string{"client trust: include patterns matched no business containers; no CA configuration injected"}, nil
	}
	return selected, nil, nil
}

func (c Config) variables() []corev1.EnvVar {
	result := make([]corev1.EnvVar, 0, len(c.Env)+1)
	result = append(result, corev1.EnvVar{Name: BundleEnvName, Value: c.Files.CABundle})
	for _, name := range c.Env {
		if name == BundleEnvName {
			continue
		}
		result = append(result, corev1.EnvVar{Name: name, Value: c.Files.CABundle})
	}
	return result
}

func installVolumes(pod *corev1.Pod, s Settings) ([]corev1.VolumeMount, bool, error) {
	mounts := make([]corev1.VolumeMount, 0, len(s.Client.Mounts))
	managed := false
	for _, m := range s.Client.Mounts {
		name := "agentio-client-ca-" + m.Name
		desired := corev1.Volume{Name: name, VolumeSource: corev1.VolumeSource{ConfigMap: m.ConfigMap, Secret: m.Secret}}
		index := slices.IndexFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == name })
		if index < 0 {
			pod.Spec.Volumes = append(pod.Spec.Volumes, *desired.DeepCopy())
		} else if !equivalentVolume(pod.Spec.Volumes[index], desired) {
			return nil, false, fmt.Errorf("client trust volume %s conflicts with existing volume", name)
		}
		mounts = append(mounts, corev1.VolumeMount{Name: name, MountPath: m.MountPath, ReadOnly: true})
		if m.ConfigMap != nil && m.ConfigMap.Name == s.Bundle.Target.ConfigMapName {
			for _, item := range m.ConfigMap.Items {
				if item.Key == s.Bundle.Target.Key {
					managed = true
				}
			}
		}
	}
	return mounts, managed, nil
}

func installMounts(container *corev1.Container, mounts []corev1.VolumeMount) error {
	for _, mount := range mounts {
		found := false
		for _, existing := range container.VolumeMounts {
			if existing.MountPath == mount.MountPath || existing.Name == mount.Name {
				if !reflect.DeepEqual(existing, mount) {
					return fmt.Errorf("client trust mount %s conflicts in container %s", mount.MountPath, container.Name)
				}
				found = true
			} else if overlaps(existing.MountPath, mount.MountPath) {
				return fmt.Errorf("client trust mount %s overlaps %s in container %s", mount.MountPath, existing.MountPath, container.Name)
			}
		}
		if !found {
			container.VolumeMounts = append(container.VolumeMounts, mount)
		}
	}
	return nil
}

func installEnv(container *corev1.Container, variables []corev1.EnvVar, policy string) []string {
	var warnings []string
	for _, desired := range variables {
		index := slices.IndexFunc(container.Env, func(e corev1.EnvVar) bool { return e.Name == desired.Name })
		switch {
		case index < 0:
			container.Env = append(container.Env, *desired.DeepCopy())
		case reflect.DeepEqual(container.Env[index], desired):
		case policy == "Overwrite":
			container.Env[index] = *desired.DeepCopy()
		default:
			warnings = append(warnings, fmt.Sprintf("client trust: preserved existing %s in container %s", desired.Name, container.Name))
		}
	}
	return warnings
}

func markManaged(pod *corev1.Pod, name string) {
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels[ManagedLabel] = "true"
	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[BundleAnnotation] = name
}
func overlaps(a, b string) bool {
	a = path.Clean(a)
	b = path.Clean(b)
	return a == "/" || b == "/" || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// API defaulting must not turn an equivalent previously injected volume into a conflict.
func equivalentVolume(a, b corev1.Volume) bool {
	normalize := func(v corev1.Volume) corev1.Volume {
		copy := v.DeepCopy()
		mode := int32(0644)
		optional := false
		if copy.ConfigMap != nil {
			if copy.ConfigMap.DefaultMode == nil {
				copy.ConfigMap.DefaultMode = &mode
			}
			if copy.ConfigMap.Optional == nil {
				copy.ConfigMap.Optional = &optional
			}
		}
		if copy.Secret != nil {
			if copy.Secret.DefaultMode == nil {
				copy.Secret.DefaultMode = &mode
			}
			if copy.Secret.Optional == nil {
				copy.Secret.Optional = &optional
			}
		}
		return *copy
	}
	return reflect.DeepEqual(normalize(a), normalize(b))
}
