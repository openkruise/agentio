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

package agentio

import (
	"testing"

	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	agentsfake "github.com/openkruise/agents-api/client/clientset/versioned/fake"
	"istio.io/istio/pkg/config/schema/kubeclient"
	"istio.io/istio/pkg/kube"
	"istio.io/istio/pkg/kube/kclient/clienttest"
	"istio.io/istio/pkg/kube/krt"
	"istio.io/istio/pkg/test"
	"istio.io/istio/pkg/test/util/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The write function passed to kubeclient.Register is what makes
// GetWriteClient resolve for a type absent from the generated switch in
// pkg/config/schema/kubeclient/resources.gen.go:54. It consults the typemap
// registration first (resources.gen.go:47-53). Without it kclient cannot
// produce a Patcher and the status controller has no way to write.
func TestSecurityProfileWriteClientIsRegistered(t *testing.T) {
	registerSecurityProfileType(agentsfake.NewSimpleClientset())

	c := kube.NewFakeClient()
	w := kubeclient.GetWriteClient[*agentsv1alpha1.SecurityProfile](c, "default")
	assert.Equal(t, w != nil, true)
}

func TestNewSecurityProfilesCollection(t *testing.T) {
	agentsCS := agentsfake.NewSimpleClientset(&agentsv1alpha1.SecurityProfile{
		ObjectMeta: metav1.ObjectMeta{Name: "sp-a", Namespace: "ns-a"},
	})
	registerSecurityProfileType(agentsCS)

	c := kube.NewFakeClient()
	clienttest.MakeCRD(t, c, securityProfileGVR)
	stop := test.NewStop(t)
	opts := krt.NewOptionsBuilder(stop, "test", krt.GlobalDebugHandler)
	col := newSecurityProfilesCollection(c, stop, opts)
	c.RunAndWait(stop)

	assert.EventuallyEqual(t, func() int { return len(col.List()) }, 1)
}
