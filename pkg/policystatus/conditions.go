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

package policystatus

import (
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	conditionAccepted     = agentsv1alpha1.SecurityProfileConditionAccepted
	conditionResolvedRefs = agentsv1alpha1.SecurityProfileConditionResolvedRefs
	conditionProgrammed   = agentsv1alpha1.SecurityProfileConditionProgrammed
)

const (
	reasonAccepted             = conditionAccepted
	reasonResolvedRefs         = conditionResolvedRefs
	reasonProgrammed           = conditionProgrammed
	reasonInvalidConfiguration = "InvalidConfiguration"
	reasonNotChecked           = "NotChecked"
	reasonCacheNotSynced       = "CacheNotSynced"
	reasonConfigMapNotFound    = "ConfigMapNotFound"
	reasonInvalidReference     = "InvalidReference"
	reasonOutsideWatchScope    = "OutsideWatchScope"
	reasonSecretNotFound       = "SecretNotFound"
	reasonServiceNotFound      = "ServiceNotFound"
	reasonDNSResolutionPending = "DNSResolutionPending"
)

const (
	messageAccepted             = "Configuration is valid"
	messageResolvedRefs         = "Reference checks passed"
	messageProgrammed           = "Configuration is ready for distribution"
	messageReferencesNotChecked = "Reference checks require a valid configuration"
	messageReferencesPending    = "Reference checks are pending"
	messageConfigMapNotFound    = "Input %q: ConfigMap %s not found"
	messageSecretNotVerified    = "Rule %q: Secret %s/%s could not be verified"
	messageSecretNotFound       = "Rule %q: Secret %s not found"
	messageServiceNotFound      = "%s: Service %s not found"
	messageDNSResolutionPending = "%s: No IP addresses are available for %s"
)

func condition(typ string, status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{Type: typ,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation}
}
