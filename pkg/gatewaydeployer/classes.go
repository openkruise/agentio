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

package gatewaydeployer

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/openkruise/agentio/pkg/kube/kclient"
)

type classInfo struct {
	controller         string
	controllerLabel    string
	description        string
	templateName       string
	defaultServiceType corev1.ServiceType
	disableNameSuffix  bool
	addressType        gatewayv1.AddressType
}

// builtinClasses is keyed by GatewayClass name. controllerLabel is the dash
// form of the controller name, rendered as a literal pod label by the
// egress-gateway template.
var builtinClasses = map[string]classInfo{
	"agentio-agentgateway": {
		controller:         "agentio.kruise.io/agentgateway-controller",
		controllerLabel:    "agentio.kruise.io-agentgateway-controller",
		description:        "Agentio agentgateway with file configuration",
		templateName:       agentgatewayTemplateName,
		defaultServiceType: corev1.ServiceTypeClusterIP,
		disableNameSuffix:  true,
		addressType:        gatewayv1.HostnameAddressType,
	},
	"agentio-egress": {
		controller:         "agentio.kruise.io/egress-gateway-controller",
		controllerLabel:    "agentio.kruise.io-egress-gateway-controller",
		description:        "Agentio sandbox egress gateway",
		templateName:       "egress-gateway",
		defaultServiceType: corev1.ServiceTypeClusterIP,
		disableNameSuffix:  true,
		// Like the release-0.1 waypoint class, report IPs and hostnames so
		// consumers across Istio versions can choose the address they support.
		addressType: "",
	},
}

var classInfos = func() map[gatewayv1.GatewayController]classInfo {
	out := make(map[gatewayv1.GatewayController]classInfo, len(builtinClasses))
	for _, c := range builtinClasses {
		out[gatewayv1.GatewayController(c.controller)] = c
	}
	return out
}()

// classFor resolves the classInfo for a Gateway: by the GatewayClass object's
// spec.controllerName when the class exists, else by the builtin name table.
func classFor(gw *gatewayv1.Gateway, classes kclient.Informer[*gatewayv1.GatewayClass]) (classInfo, bool) {
	if gc := classes.Get(string(gw.Spec.GatewayClassName), ""); gc != nil {
		ci, ok := classInfos[gc.Spec.ControllerName]
		return ci, ok
	}
	ci, ok := builtinClasses[string(gw.Spec.GatewayClassName)]
	return ci, ok
}

// getDefaultName suffixes the Deployment name with the Gateway's own spec.gatewayClassName unless disabled.
func getDefaultName(name string, gatewayClassName string, disableNameSuffix bool) string {
	if disableNameSuffix {
		return name
	}
	return fmt.Sprintf("%v-%v", name, gatewayClassName)
}
