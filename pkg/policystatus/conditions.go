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
)

const (
	messageAccepted     = "Configuration is valid"
	messageResolvedRefs = "Reference checks passed"
	messageProgrammed   = "Configuration is ready for distribution"
)

func condition(typ string, status metav1.ConditionStatus, reason, message string, generation int64) metav1.Condition {
	return metav1.Condition{Type: typ,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: generation}
}
