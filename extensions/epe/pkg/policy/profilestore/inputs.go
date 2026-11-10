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

package profilestore

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/openkruise/agentio/extensions/epe/pkg/policy/securityprofile"
	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
)

// NewSourceCollection feeds admitted profiles through the same dependency and
// publication path as informer profiles.
func NewSourceCollection(
	source krt.Collection[securityprofile.Profile],
	configMaps krt.Collection[*corev1.ConfigMap],
	opts ...krt.CollectionOption,
) *Collection {
	return &Collection{
		Source: registry.Source[securityprofile.Profile]{
			Collection: inputCollection(source, configMaps, opts...),
			Registry: registry.TrackSources(
				source,
				"profile-source-keys",
				func(p securityprofile.Profile) []model.ResourceKey {
					return []model.ResourceKey{profileNotificationKey(p.Meta)}
				},
				func(p securityprofile.Profile) model.SourceIdentity { return p.Meta.SourceIdentity },
			),
		},
	}
}

func inputCollection(
	source krt.Collection[securityprofile.Profile],
	configMaps krt.Collection[*corev1.ConfigMap],
	opts ...krt.CollectionOption,
) krt.Collection[securityprofile.Profile] {
	return krt.NewCollection(source, func(ctx krt.HandlerContext, p securityprofile.Profile) *securityprofile.Profile {
		if p.CompileError != "" || p.Spec == nil {
			return &p
		}
		inputs, unavailable, err := resolveInputs(ctx, configMaps, p.Meta, p.Spec.Inputs)
		if err != nil {
			p.CompileError = fmt.Sprintf("resolve inputs: %v", err)
			return &p
		}
		p.Inputs, p.InputsError = inputs, unavailable
		return &p
	}, opts...)
}

func profileNotificationKey(meta securityprofile.Meta) model.ResourceKey {
	if meta.Match == securityprofile.MatchSandbox {
		return sandboxProfileKey(meta.Namespace, meta.Name)
	}
	return model.ResourceKey{TypeURL: model.SecurityProfileType, Name: "selector/" + meta.Namespace + "/" + meta.Name}
}
