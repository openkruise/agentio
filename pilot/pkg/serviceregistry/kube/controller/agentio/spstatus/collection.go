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

package spstatus

import (
	agentsv1alpha1 "github.com/openkruise/agents-api/agents/v1alpha1"
	corev1 "k8s.io/api/core/v1"

	"istio.io/istio/pkg/kube/krt"
)

// ProfileStatus pairs the live SecurityProfile with the status we want it to
// have. krt.ObjectWithStatus already models exactly that and supplies
// ResourceName and Equals (pkg/kube/krt/status.go:95-114), so the writer can
// compare live against desired without re-reading the apiserver.
type ProfileStatus = krt.ObjectWithStatus[*agentsv1alpha1.SecurityProfile, agentsv1alpha1.SecurityProfileStatus]

// NewCollection derives the desired status for every SecurityProfile.
//
// This is a plain krt.NewCollection rather than krt.NewStatusCollection:
// that helper exists so a status can be produced by the same transformation
// that produces xDS output, guaranteeing the two cannot drift. agentiod does
// not translate SecurityProfile into anything, so there is no output to pair
// with and the helper's second return value would always be empty.
//
// Secrets is fetched through ctx, which makes it a tracked dependency: a
// Secret appearing or disappearing recomputes the affected profiles.
func NewCollection(
	profiles krt.Collection[*agentsv1alpha1.SecurityProfile],
	secrets krt.Collection[*corev1.Secret],
	opts krt.OptionsBuilder,
) krt.Collection[ProfileStatus] {
	return krt.NewCollection(profiles, func(ctx krt.HandlerContext, sp *agentsv1alpha1.SecurityProfile) *ProfileStatus {
		if sp == nil {
			return nil
		}
		specErrs := ValidateSpec(&sp.Spec)
		refErrs := ResolveRefs(ctx, sp, secrets)
		return &ProfileStatus{
			Obj:    sp,
			Status: BuildStatus(sp, specErrs, refErrs),
		}
	}, opts.WithName("SecurityProfileStatus")...)
}
