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

package ca

import (
	"fmt"
	"reflect"
	"time"

	"istio.io/istio/pkg/ptr"
	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/pkg/clienttrust"
	"github.com/openkruise/agentio/pkg/krt"
)

type clientTrustBundle struct {
	Target  clienttrust.Target
	PEM     string
	Version string
}

func (clientTrustBundle) ResourceName() string                  { return "client-trust-bundle" }
func (b clientTrustBundle) Equals(other clientTrustBundle) bool { return b == other }

type clientTrustBundleResult struct {
	Bundle   clientTrustBundle
	Error    string
	Warnings []string
}

func (clientTrustBundleResult) ResourceName() string { return "client-trust-bundle-result" }
func (b clientTrustBundleResult) Equals(other clientTrustBundleResult) bool {
	return reflect.DeepEqual(b, other)
}

type clientTrustTarget struct {
	Namespace string
	Bundle    clientTrustBundle
}

func (t clientTrustTarget) ResourceName() string {
	return t.Namespace + "/" + t.Bundle.Target.ConfigMapName
}
func (t clientTrustTarget) Equals(other clientTrustTarget) bool { return t == other }

func (d *ClientTrustDistributor) build(
	ctx krt.HandlerContext,
	bundle clienttrust.Bundle,
	configMaps krt.Collection[*corev1.ConfigMap],
) *clientTrustBundleResult {
	result := &clientTrustBundleResult{Bundle: clientTrustBundle{Target: bundle.Target, Version: "custom"}}
	var sources [][]byte
	for i, source := range bundle.Sources {
		data, err := d.readSource(ctx, source, configMaps)
		if err != nil {
			result.Error = fmt.Sprintf("CA source %d: %v", i, err)
			return result
		}
		sources = append(sources, data)
		if source.DefaultCAs {
			result.Bundle.Version = clienttrust.PackageVersion(d.packageData)
		}
	}
	data, warnings, err := clienttrust.Merge(sources, time.Now())
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Bundle.PEM = string(data)
	result.Warnings = warnings
	return result
}

func (d *ClientTrustDistributor) readSource(
	ctx krt.HandlerContext,
	source clienttrust.Source,
	configMaps krt.Collection[*corev1.ConfigMap],
) ([]byte, error) {
	switch {
	case source.DefaultCAs:
		if d.packageError != nil {
			return nil, fmt.Errorf("default CA package: %w", d.packageError)
		}
		return []byte(d.packageData.Bundle), nil
	case source.AgentioMITM:
		if d.options.MITMTrustBundle == nil {
			return nil, fmt.Errorf("MITM signer does not expose a public trust bundle")
		}
		bundle := krt.FetchOne(ctx, d.options.MITMTrustBundle.AsCollection())
		if bundle == nil {
			return nil, fmt.Errorf("MITM trust bundle is unavailable")
		}
		return []byte(bundle.PEM), nil
	case source.ConfigMap != nil:
		ref := source.ConfigMap
		key := ref.Namespace + "/" + ref.Name
		cm := ptr.Flatten(krt.FetchOne(ctx, configMaps, krt.FilterKey(key)))
		if cm == nil {
			return nil, fmt.Errorf("ConfigMap %s is unavailable", key)
		}
		if value, ok := cm.Data[ref.Key]; ok {
			return []byte(value), nil
		}
		return nil, fmt.Errorf("ConfigMap %s has no data key %s", key, ref.Key)
	case source.Secret != nil:
		ref := source.Secret
		key := ref.Namespace + "/" + ref.Name
		secret := ptr.Flatten(krt.FetchOne(ctx, d.options.Secrets, krt.FilterKey(key)))
		if secret == nil {
			return nil, fmt.Errorf("Secret %s is unavailable", key)
		}
		if value, ok := secret.Data[ref.Key]; ok {
			return value, nil
		}
		return nil, fmt.Errorf("Secret %s has no data key %s", key, ref.Key)
	default:
		return nil, fmt.Errorf("unknown CA source")
	}
}
