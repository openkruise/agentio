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

package kruise

import (
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/registry"
)

func newSandboxSources(
	objects krt.Collection[*agentsv1alpha1.Sandbox],
) *registry.SourceRegistry {
	identity := func(sandbox *agentsv1alpha1.Sandbox) model.SourceIdentity {
		return model.SourceIdentity{UID: string(sandbox.UID)}
	}
	keys := func(sandbox *agentsv1alpha1.Sandbox) []model.ResourceKey {
		if !isPolicySubject(sandbox) {
			return nil
		}
		uid, found := sandboxUID(sandbox)
		if !found {
			return nil
		}
		return []model.ResourceKey{
			{TypeURL: model.SandboxType, Name: uid},
			{TypeURL: model.SandboxType, Name: sandbox.Namespace + "/" + sandbox.Name},
		}
	}
	return registry.TrackSources(objects, "sandbox-source-keys", keys, identity)
}
