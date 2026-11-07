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

package features

import "istio.io/istio/pkg/env"

// ValidationWebhookConfigName enables admission and names its CA bundle target.
var ValidationWebhookConfigName = env.Register(
	"AGENTIO_VALIDATION_WEBHOOK_CONFIG_NAME",
	"",
	"Serve /validate and synchronize the caBundle of this ValidatingWebhookConfiguration; empty disables validation admission.",
).Get()

func Validate() error {
	validators := [...]func() error{
		validateXDS,
		validateNetworking,
		validateCARotation,
		validateMITM,
		validateWorkloadCertificates,
		validateControlPlane,
		validateGatewayDeployer,
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}
