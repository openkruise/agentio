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
	"regexp"
	"strings"

	yamlv3 "go.yaml.in/yaml/v3"
)

// integrationImageTag rejects development bundles before changing either chart.
func integrationImageTag(bundle string) (string, error) {
	content, err := os.ReadFile(filepath.Join(bundle, "sandbox-manager", "values.yaml"))
	if err != nil {
		return "", err
	}
	var values struct {
		Agentio struct {
			Global struct {
				Tag string `yaml:"tag"`
			} `yaml:"global"`
		} `yaml:"agentio"`
	}
	if err := yamlv3.Unmarshal(content, &values); err != nil {
		return "", err
	}
	tag := values.Agentio.Global.Tag
	core := `(0|[1-9][0-9]*)`
	identifier := `(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)`
	pattern := `^` + core + `\.` + core + `\.` + core + `(-` + identifier + `(\.` + identifier + `)*)?$`
	if !regexp.MustCompile(pattern).MatchString(tag) {
		return "", fmt.Errorf("integration requires a fixed release version in agentio.global.tag, got %q", tag)
	}
	return tag, nil
}

// adaptImageRegistry maps released image defaults to the parent charts' registry
// contract. It runs after copying the bundle, so existing releases work without
// republishing them. Image and namespace defaults and their rendering helpers are adapted;
// repositories and workload templates stay intact. Defaults use the release tag.
func adaptImageRegistry(target string, controller bool, tag string) error {
	valuesPath := filepath.Join(target, "values.yaml")
	content, err := os.ReadFile(valuesPath)
	if err != nil {
		return err
	}
	var document yamlv3.Node
	if err := yamlv3.Unmarshal(content, &document); err != nil {
		return err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yamlv3.MappingNode {
		return fmt.Errorf("chart values must be a mapping")
	}
	agentio := yamlMappingValue(document.Content[0], "agentio")
	components := []string{
		"agentiod",
		"egressGateway",
		"egressGateway.porter",
		"epe",
	}
	begin, end := valuesBegin, valuesEnd
	helperDir := filepath.Join(target, "templates", "agentio")
	global := yamlMappingValue(agentio, "global")
	hub := ""
	if node := yamlMappingValue(global, "hub"); node != nil {
		hub = node.Value
	}
	if controller {
		components = []string{"trafficProxy"}
		begin, end = controllerValuesBegin, controllerValuesEnd
		helperDir = filepath.Join(target, "templates")
	}
	adapted := false
	for _, component := range components {
		keys := []string{"image"}
		if controller {
			keys = append(keys, "initImage")
		}
		for _, key := range keys {
			componentValues := agentio
			for segment := range strings.SplitSeq(component, ".") {
				componentValues = yamlMappingValue(componentValues, segment)
			}
			image := yamlMappingValue(componentValues, key)
			if image == nil {
				continue
			}
			if err := adaptImageValues(image, hub, tag); err != nil {
				return err
			}
			if controller {
				err = adaptControllerImage(target, key)
			} else {
				err = adaptManagerImage(helperDir, component)
			}
			if err != nil {
				return err
			}
			adapted = true
		}
	}
	if !adapted {
		return nil
	}
	if !controller {
		if global == nil {
			return fmt.Errorf("manager image configuration requires agentio.global")
		}
		removeYAMLMappingKeys(global, "hub", "registry")
		global.Content = append(global.Content,
			&yamlv3.Node{Kind: yamlv3.ScalarNode, Value: "registry"},
			&yamlv3.Node{Kind: yamlv3.ScalarNode, Tag: "!!str", Value: ""})
	}
	if err := adaptIntegrationNamespace(target, agentio, controller); err != nil {
		return err
	}
	if err := writeRegistryValues(valuesPath, content, agentio, begin, end); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(helperDir, "_agentio-registry.tpl"), []byte(warning+registryImageHelper), 0o644)
}

// Apply current integration defaults even when importing an older release bundle.
func adaptIntegrationNamespace(target string, agentio *yamlv3.Node, controller bool) error {
	parent, key := "global", "namespace"
	if controller {
		parent, key = "trafficProxy", "controlPlaneNamespace"
	}
	if namespace := yamlMappingValue(yamlMappingValue(agentio, parent), key); namespace != nil {
		namespace.Value = "sandbox-system"
	}
	if controller {
		return nil
	}
	setIntegrationGatewayModes(agentio)
	templates := filepath.Join(target, "templates", "agentio")
	if err := addIntegrationEgressDefault(templates); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(templates, "_namespace.tpl"), []byte(warning+integrationNamespaceTemplate), 0o644)
}

func writeRegistryValues(path string, content []byte, agentio *yamlv3.Node, begin, end string) error {
	root := &yamlv3.Node{
		Kind: yamlv3.MappingNode,
		Content: []*yamlv3.Node{
			{Kind: yamlv3.ScalarNode, Value: "agentio"}, agentio,
		},
	}
	var block bytes.Buffer
	fmt.Fprintln(&block, begin)
	encoder := yamlv3.NewEncoder(&block)
	encoder.SetIndent(2)
	if err := encoder.Encode(root); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	fmt.Fprintln(&block, end)
	next, err := replaceMarkedBlock(content, block.Bytes(), begin, end, "registry image values")
	if err != nil {
		return err
	}
	return os.WriteFile(path, next, 0o644)
}

func adaptImageValues(image *yamlv3.Node, hub, tag string) error {
	values := chartImageValues{}
	if image.Kind == yamlv3.ScalarNode {
		values.Repository, _, _ = strings.Cut(image.Value, "@")
		if colon := strings.LastIndex(values.Repository, ":"); colon > strings.LastIndex(values.Repository, "/") {
			values.Repository = values.Repository[:colon]
		}
	} else if err := image.Decode(&values); err != nil {
		return err
	}
	if values.Repository == "" {
		values.Repository = strings.TrimSuffix(hub, "/") + "/" + values.Name
	}
	// Docker Hub defaults inherit the parent's registry. References to an
	// explicitly chosen host keep that host, just like other chart images.
	return image.Encode(map[string]string{
		"registry":   "",
		"repository": strings.TrimPrefix(values.Repository, "docker.io/"),
		"tag":        tag,
		"digest":     "",
	})
}

func adaptManagerImage(templates, component string) error {
	name := component
	if name == "egressGateway" {
		name = "gateway"
	}
	helper := "agentio." + name + ".image"
	if component == "egressGateway.porter" {
		helper = "agentio.gateway.porterImage"
	}
	path := filepath.Join(templates, "_helpers.tpl")
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pattern := regexp.MustCompile(`\{\{-?\s*define\s+"` + regexp.QuoteMeta(helper) + `"`)
	match := pattern.FindIndex(content)
	if match == nil {
		return fmt.Errorf("missing image helper %q", helper)
	}
	end, err := matchingDefinitionEnd(content, match[0])
	if err != nil {
		return err
	}
	replacement := fmt.Sprintf(`{{- define %q -}}
{{- include "agentio.registryImage" (dict "root" . "image" .Values.agentio.%s.image "globalRegistry" .Values.agentio.global.registry "defaultTag" .Values.agentio.global.tag) -}}
{{- end -}}`, helper, component)
	next := append(append([]byte(nil), content[:match[0]]...), []byte(replacement)...)
	next = append(next, content[end:]...)
	return os.WriteFile(path, next, 0o644)
}

func adaptControllerImage(target, key string) error {
	path, content, err := findSandboxInjectionConfigTemplate(filepath.Join(target, "templates"))
	if err != nil {
		return err
	}
	old := "{{ .Values.agentio.trafficProxy." + key + " | quote }}"
	if bytes.Count(content, []byte(old)) != 1 {
		return fmt.Errorf("expected one traffic-proxy %s reference", key)
	}
	replacement := fmt.Sprintf(
		`{{ include "agentio.registryImage" (dict "root" . "image" .Values.agentio.trafficProxy.%s) | quote }}`,
		key,
	)
	return os.WriteFile(path, bytes.Replace(content, []byte(old), []byte(replacement), 1), 0o644)
}

const registryImageHelper = `{{/* Per-image registry > Agentio registry > chart registry > Docker Hub.
Qualified repositories retain their host. Digests take precedence over tags. */}}
{{- define "agentio.registryImage" -}}
{{- $parentImage := .root.Values.image | default dict -}}
{{- $registry := .image.registry | default .globalRegistry | default $parentImage.registry | default "docker.io" -}}
{{- $repository := required "Agentio image.repository is required" .image.repository -}}
{{- $host := first (splitList "/" $repository) -}}
{{- if not (or (contains "." $host) (contains ":" $host) (eq $host "localhost")) -}}
{{- $repository = printf "%s/%s" (trimSuffix "/" $registry) $repository -}}
{{- end -}}
{{- if .image.digest -}}
{{- printf "%s@%s" $repository .image.digest -}}
{{- else -}}
{{- printf "%s:%s" $repository (required "Agentio image.tag is required without a digest" (.image.tag | default .defaultTag)) -}}
{{- end -}}
{{- end -}}
`

func setIntegrationGatewayModes(root *yamlv3.Node) {
	if enabled := yamlMappingValue(yamlMappingValue(root, "egressGateway"), "enabled"); enabled != nil {
		enabled.Value = "true"
	}
	for component, value := range map[string]string{"egressGateway": "static", "epe": "managed"} {
		if mode := yamlMappingValue(yamlMappingValue(root, component), "mode"); mode != nil {
			mode.Value = value
		}
	}
}
