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
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

const integrationNamespaceTemplate = `{{- define "agentio.namespace" -}}
{{- default "sandbox-system" .Values.agentio.global.namespace -}}
{{- end -}}
`

// CRDs stay installed while the optional control plane is disabled. The keep
// annotation also preserves policy objects if the manager release is removed.
func buildManagerSupport(source, templates, files string) error {
	crds := filepath.Join(source, "crds")
	entries, err := os.ReadDir(crds)
	if os.IsNotExist(err) {
		return nil
	} // Minimal charts used by exporter tests.
	if err != nil {
		return err
	}
	target := filepath.Join(files, "crds")
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsupported CRD path %s", entry.Name())
		}
		content, err := os.ReadFile(filepath.Join(crds, entry.Name()))
		if err != nil {
			return err
		}
		var object map[string]any
		if err := yaml.Unmarshal(content, &object); err != nil {
			return err
		}
		if object["kind"] != "CustomResourceDefinition" {
			return fmt.Errorf("expected CRD in %s", entry.Name())
		}
		metadata, ok := object["metadata"].(map[string]any)
		if !ok {
			return fmt.Errorf("missing CRD metadata in %s", entry.Name())
		}
		annotations, ok := metadata["annotations"].(map[string]any)
		if !ok {
			annotations = map[string]any{}
			metadata["annotations"] = annotations
		}
		annotations["helm.sh/resource-policy"] = "keep"
		content, err = yaml.Marshal(object)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(target, entry.Name()), content, 0o644); err != nil {
			return err
		}
	}
	resources := map[string]string{
		"crds.yaml": `{{- range $path, $_ := .Files.Glob "files/agentio/crds/*.yaml" }}
---
{{ $.Files.Get $path }}
{{- end }}
`,
		"_namespace.tpl": integrationNamespaceTemplate,
		"namespace.yaml": `{{- if and .Values.agentio.enabled .Values.agentio.global.createNamespace (ne (include "agentio.namespace" .) .Release.Namespace) }}
apiVersion: v1
kind: Namespace
metadata:
  name: {{ include "agentio.namespace" . }}
  annotations:
    helm.sh/resource-policy: keep
{{- end }}
`,
	}
	for name, content := range resources {
		if err := os.WriteFile(filepath.Join(templates, name), []byte(warning+content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// addIntegrationEgressDefault keeps the default gateway reference aligned with
// Helm name/namespace overrides and leaves explicit routing rules authoritative.
func addIntegrationEgressDefault(templates string) error {
	path := filepath.Join(templates, "agentiod", "configmaps.yaml")
	content, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	} // Minimal exporter fixtures have no control plane.
	if err != nil {
		return err
	}
	if bytes.Contains(content, []byte("BEGIN INTEGRATION EGRESS DEFAULT")) {
		return nil
	}
	marker := []byte(`{{- $config := mergeOverwrite`)
	if bytes.Count(content, marker) != 1 {
		return fmt.Errorf("expected one Agentio config merge in %s", path)
	}
	return os.WriteFile(
		path,
		bytes.Replace(content, marker, append([]byte(integrationEgressDefault), marker...), 1),
		0o644,
	)
}

const integrationEgressDefault = `{{/* BEGIN INTEGRATION EGRESS DEFAULT */}}
{{- if and .Values.agentio.egressGateway.enabled (not (hasKey (.Values.agentio.agentiod.config.values | default dict) "egressPolicies")) -}}
{{- $service := printf "%s.%s.svc.%s" (include "agentio.gateway.fullname" .) (include "agentio.namespace" .) .Values.agentio.global.clusterDomain -}}
{{- $_ := set $defaults "egressPolicies" (list (dict "policy" "GATEWAY" "gateway" (dict "service" $service))) -}}
{{- end -}}
{{/* END INTEGRATION EGRESS DEFAULT */}}
`
