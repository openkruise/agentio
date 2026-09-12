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

// Package clienttrust defines client CA configuration shared by admission and distribution.
package clienttrust

import (
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"

	"istio.io/istio/pkg/util/sets"
)

// Keys and paths used for client trust injection and discovery.
const (
	EnableAnnotation  = "sidecar.agentio.kruise.io/client-trust"
	IncludeAnnotation = "sidecar.agentio.kruise.io/client-trust-containers"
	ExcludeAnnotation = "sidecar.agentio.kruise.io/client-trust-exclude-containers"
	ManagedLabel      = "client-trust.agentio.kruise.io/managed"
	BundleAnnotation  = "client-trust.agentio.kruise.io/bundle"
	OwnerAnnotation   = "client-trust.agentio.kruise.io/owner"
	DigestAnnotation  = "client-trust.agentio.kruise.io/sha256"
	PackageAnnotation = "client-trust.agentio.kruise.io/package"
	DefaultMountPath  = "/etc/agentio/client-ca"
	BundleEnvName     = "AGENTIO_TRUST_BUNDLE"
)

// Config selects business containers and their client trust configuration.
type Config struct {
	Enabled           bool       `json:"enabled,omitempty"`
	Containers        Containers `json:"containers,omitempty"`
	Mounts            []Mount    `json:"mounts,omitempty"`
	Files             Files      `json:"files,omitempty"`
	Env               []string   `json:"env"`
	EnvConflictPolicy string     `json:"envConflictPolicy,omitempty"`
}

// Containers selects original business containers by name patterns.
type Containers struct {
	Include               []string `json:"include,omitempty"`
	Exclude               []string `json:"exclude,omitempty"`
	IncludeInitContainers bool     `json:"includeInitContainers,omitempty"`
}

// Mount describes a required, read-only certificate source in the Pod namespace.
type Mount struct {
	Name      string                        `json:"name"`
	MountPath string                        `json:"mountPath"`
	ConfigMap *corev1.ConfigMapVolumeSource `json:"configMap,omitempty"`
	Secret    *corev1.SecretVolumeSource    `json:"secret,omitempty"`
}

// Files supplies the mounted bundle path injected into every configured environment variable.
type Files struct {
	CABundle string `json:"caBundle,omitempty"`
}

// Reference identifies one public-certificate key in a namespaced source.
type Reference struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Key       string `json:"key"`
}

// Source is exactly one input to the managed CA union.
type Source struct {
	DefaultCAs  bool       `json:"defaultCAs,omitempty"`
	AgentioMITM bool       `json:"agentioMITM,omitempty"`
	ConfigMap   *Reference `json:"configMap,omitempty"`
	Secret      *Reference `json:"secret,omitempty"`
}

// Target names the managed ConfigMap and its bundle key.
type Target struct {
	ConfigMapName string `json:"configMapName"`
	Key           string `json:"key"`
}

// Bundle configures the sources and output of CA distribution.
type Bundle struct {
	Sources []Source `json:"sources"`
	Target  Target   `json:"target"`
}

// Settings is the immutable configuration shared by admission and distribution.
// Consumers must not mutate it or any nested settings.
type Settings struct {
	Client Config `json:"clientTrust"`
	Bundle Bundle `json:"clientTrustBundle"`
}

// ResourceName identifies the shared configuration singleton.
func (Settings) ResourceName() string { return "client-trust-configuration" }

// Equals compares complete validated configuration revisions.
func (s Settings) Equals(other Settings) bool { return reflect.DeepEqual(s, other) }

// Defaults returns the default managed bundle and environment variable names.
func Defaults() Settings {
	return Settings{
		Client: Config{
			Env:               []string{"SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "CURL_CA_BUNDLE"},
			EnvConflictPolicy: "Preserve",
		},
		Bundle: Bundle{
			Sources: []Source{{DefaultCAs: true}, {AgentioMITM: true}},
			Target:  Target{ConfigMapName: "agentio-client-ca", Key: "ca-bundle.pem"},
		},
	}
}

// Parse reads only the two owned sections, rejecting typos within them. Unrelated injector values remain opaque.
func Parse(values map[string]any) (Settings, error) {
	s := Defaults()
	for key, dst := range map[string]any{"clientTrust": &s.Client, "clientTrustBundle": &s.Bundle} {
		if raw, ok := values[key]; ok {
			// JSON decoders reuse slice element storage; clear defaults before replacing
			// source lists so omitted union fields cannot leak from a default element.
			if key == "clientTrustBundle" {
				if object, ok := raw.(map[string]any); ok {
					if _, present := object["sources"]; present {
						s.Bundle.Sources = nil
					}
				}
			}

			b, err := json.Marshal(raw)
			if err != nil {
				return s, err
			}
			if string(b) == "null" {
				return s, fmt.Errorf("%s must be an object", key)
			}
			if err := yaml.UnmarshalStrict(b, dst); err != nil {
				return s, fmt.Errorf("%s: %w", key, err)
			}
		}
	}
	if s.Client.Mounts == nil {
		s.Client.Mounts = []Mount{{
			Name:      "bundle",
			MountPath: DefaultMountPath,
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{Name: s.Bundle.Target.ConfigMapName},
				Items: []corev1.KeyToPath{{
					Key:  s.Bundle.Target.Key,
					Path: s.Bundle.Target.Key,
				}},
			},
		}}
		if s.Client.Files.CABundle == "" {
			s.Client.Files.CABundle = path.Join(DefaultMountPath, s.Bundle.Target.Key)
		}
	}
	return s, s.Validate()
}

// Validate checks bundle sources, mounts and environment names.
func (s Settings) Validate() error {
	c := s.Client
	if c.EnvConflictPolicy != "Preserve" && c.EnvConflictPolicy != "Overwrite" {
		return fmt.Errorf("envConflictPolicy must be Preserve or Overwrite")
	}
	if err := ValidatePatterns(c.Containers.Include); err != nil {
		return err
	}
	if err := ValidatePatterns(c.Containers.Exclude); err != nil {
		return err
	}
	if err := s.Bundle.validate(); err != nil {
		return err
	}
	files, err := validateMounts(c.Mounts)
	if err != nil {
		return err
	}
	if !files.Contains(c.Files.CABundle) {
		return fmt.Errorf("AGENTIO_TRUST_BUNDLE requires files.caBundle pointing to a mounted file")
	}
	return validateEnv(c.Env)
}

func (b Bundle) validate() error {
	if len(validation.IsDNS1123Subdomain(b.Target.ConfigMapName)) > 0 || len(validation.IsConfigMapKey(b.Target.Key)) > 0 || strings.Contains(b.Target.Key, "/") {
		return fmt.Errorf("invalid clientTrustBundle target")
	}
	if len(b.Sources) == 0 {
		return fmt.Errorf("clientTrustBundle requires sources")
	}
	for _, source := range b.Sources {
		if err := source.validate(b.Target); err != nil {
			return err
		}
	}
	return nil
}

func (s Source) validate(target Target) error {
	count := 0
	if s.DefaultCAs {
		count++
	}
	if s.AgentioMITM {
		count++
	}
	for _, ref := range []*Reference{s.ConfigMap, s.Secret} {
		if ref == nil {
			continue
		}
		count++
		if len(validation.IsDNS1123Label(ref.Namespace)) > 0 || len(validation.IsDNS1123Subdomain(ref.Name)) > 0 || len(validation.IsConfigMapKey(ref.Key)) > 0 {
			return fmt.Errorf("source namespace/name/key are required and must be valid")
		}
	}
	if count != 1 {
		return fmt.Errorf("each CA source must select exactly one type")
	}
	if s.ConfigMap != nil && s.ConfigMap.Name == target.ConfigMapName {
		return fmt.Errorf("bundle source cannot reference its own target")
	}
	return nil
}

func validateMounts(mounts []Mount) (sets.Set[string], error) {
	names := sets.New[string]()
	files := sets.New[string]()
	for i, mount := range mounts {
		if len(validation.IsDNS1123Label("agentio-client-ca-"+mount.Name)) > 0 {
			return nil, fmt.Errorf("invalid CA mount name %q", mount.Name)
		}
		if names.Contains(mount.Name) {
			return nil, fmt.Errorf("duplicate CA mount name %q", mount.Name)
		}
		if !cleanAbsolute(mount.MountPath) || mount.MountPath == "/" {
			return nil, fmt.Errorf("invalid CA mount path %q", mount.MountPath)
		}
		for _, previous := range mounts[:i] {
			if previous.MountPath == mount.MountPath || overlaps(previous.MountPath, mount.MountPath) {
				return nil, fmt.Errorf("CA mount %s overlaps %s", mount.MountPath, previous.MountPath)
			}
		}
		names.Insert(mount.Name)
		items, err := mount.items()
		if err != nil {
			return nil, err
		}
		if err = validateItems(items); err != nil {
			return nil, err
		}
		for _, item := range items {
			files.Insert(path.Join(mount.MountPath, item.Path))
		}
	}
	return files, nil
}

func (m Mount) items() ([]corev1.KeyToPath, error) {
	if (m.ConfigMap == nil) == (m.Secret == nil) {
		return nil, fmt.Errorf("CA mount %s must select exactly one source", m.Name)
	}
	var name string
	var items []corev1.KeyToPath
	var optional *bool
	var mode *int32
	if m.ConfigMap != nil {
		name = m.ConfigMap.Name
		items = m.ConfigMap.Items
		optional = m.ConfigMap.Optional
		mode = m.ConfigMap.DefaultMode
	}
	if m.Secret != nil {
		name = m.Secret.SecretName
		items = m.Secret.Items
		optional = m.Secret.Optional
		mode = m.Secret.DefaultMode
	}
	if optional != nil && *optional {
		return nil, fmt.Errorf("CA mounts cannot be optional")
	}
	if mode != nil && (*mode < 0 || *mode > 0777) {
		return nil, fmt.Errorf("invalid CA default file mode")
	}
	if len(validation.IsDNS1123Subdomain(name)) > 0 || len(items) == 0 {
		return nil, fmt.Errorf("CA mount %s requires name and explicit items", m.Name)
	}
	return items, nil
}

func validateItems(items []corev1.KeyToPath) error {
	seen := sets.New[string]()
	for _, item := range items {
		if len(validation.IsConfigMapKey(item.Key)) > 0 {
			return fmt.Errorf("invalid CA data key %q", item.Key)
		}
		if item.Path == "" || item.Path == "." || path.IsAbs(item.Path) {
			return fmt.Errorf("CA file path %q must name a relative file", item.Path)
		}
		if path.Clean(item.Path) != item.Path || strings.HasPrefix(item.Path, "..") {
			return fmt.Errorf("invalid CA file path %q", item.Path)
		}
		for previous := range seen {
			if previous == item.Path || overlaps(previous, item.Path) {
				return fmt.Errorf("CA file path %q overlaps %q", item.Path, previous)
			}
		}
		if item.Mode != nil && (*item.Mode < 0 || *item.Mode > 0777) {
			return fmt.Errorf("invalid CA file mode")
		}
		seen.Insert(item.Path)
	}
	return nil
}

func validateEnv(env []string) error {
	seen := sets.New[string]()
	for _, name := range env {
		if len(validation.IsEnvVarName(name)) > 0 || seen.Contains(name) {
			return fmt.Errorf("invalid or duplicate client trust env %q", name)
		}
		seen.Insert(name)
	}
	return nil
}

func cleanAbsolute(s string) bool { return path.IsAbs(s) && path.Clean(s) == s }

// ValidatePatterns restricts the selector grammar to container names and *.
func ValidatePatterns(patterns []string) error {
	for _, p := range patterns {
		if p == "" {
			return fmt.Errorf("empty container pattern")
		}
		for _, ch := range p {
			if !(ch == '*' || ch == '-' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
				return fmt.Errorf("invalid container pattern %q: only names and * are supported", p)
			}
		}
	}
	return nil
}

// Patterns resolves a comma-separated Pod annotation over the global list.
func Patterns(annotations map[string]string, key string, fallback []string) ([]string, error) {
	raw, ok := annotations[key]
	if !ok {
		return fallback, nil
	}
	if strings.TrimSpace(raw) == "" {
		return []string{}, nil
	}
	parts := strings.Split(raw, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts, ValidatePatterns(parts)
}

// Matches tests complete container names against any pattern.
func Matches(patterns []string, name string) bool {
	for _, p := range patterns {
		ok, err := path.Match(p, name)
		if err == nil && ok {
			return true
		}
	}
	return false
}

// EnabledFor allows Pod opt-out while preserving the global feature gate.
func (c Config) EnabledFor(annotations map[string]string) (bool, error) {
	if v, ok := annotations[EnableAnnotation]; ok {
		if v != "true" && v != "false" {
			return false, fmt.Errorf("%s must be true or false", EnableAnnotation)
		}
		return c.Enabled && v == "true", nil
	}
	return c.Enabled, nil
}
