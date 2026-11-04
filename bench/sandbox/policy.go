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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	securityapi "istio.io/api/security/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
)

func (r *runner) policy(ctx context.Context) (any, error) {
	if r.PolicyKind != "security" && r.PolicyKind != "traffic" {
		return nil, fmt.Errorf("policy-kind must be security or traffic")
	}
	conn, roots, err := r.credentials(ctx)
	if err != nil {
		return nil, err
	}
	defer closeResource(conn)
	cert, err := r.issue(ctx, securityapi.NewIstioCertificateServiceClient(conn), r.Offset)
	if err != nil {
		return nil, err
	}
	tlsConfig := gatewayTLS(roots, cert, "spiffe://cluster.local/ns/"+r.System+"/sa/egress-gateway")
	var timings []any
	for _, blocked := range []bool{true, false, true, false} {
		actions := map[string]any{"bypass": true}
		if blocked {
			actions = map[string]any{"block": map[string]any{"statusCode": 451, "body": "sandbox-scale-denied"}}
		}
		object := map[string]any{
			"apiVersion": "agents.kruise.io/v1alpha1",
			"kind":       "GlobalSecurityProfile",
			"metadata":   map[string]any{"name": r.Prefix + "-policy"},
			"spec": map[string]any{
				"priority": 10,
				"selector": map[string]any{
					"matchLabels": map[string]string{
						"bench.agentio.io/run": r.Prefix,
						"revision":             fmt.Sprint(r.Revision),
					},
				},
				"rules": []any{
					map[string]any{
						"name": "policy-probe",
						"match": []any{
							map[string]any{
								"domains": []string{"*"},
								"paths":   []any{map[string]any{"type": "Exact", "value": "/bench-policy"}},
							},
						},
						"actions": actions,
					},
				},
			},
		}
		resource := "globalsecurityprofiles"
		if r.PolicyKind == "traffic" {
			action := "allow"
			if blocked {
				action = "reject"
			}
			object = map[string]any{
				"apiVersion": "agents.kruise.io/v1alpha1",
				"kind":       "GlobalTrafficPolicy",
				"metadata":   map[string]any{"name": r.Prefix + "-policy"},
				"spec": map[string]any{
					"priority": 1,
					"selector": map[string]any{
						"matchLabels": map[string]string{
							"bench.agentio.io/label-00": fmt.Sprintf("value-%d-0", r.Offset),
						},
					},
					"egress": map[string]any{"rules": []any{
						map[string]any{
							"action": action,
							"to":     []any{map[string]any{"cidr": "0.0.0.0/0"}},
							"ports":  []any{map[string]any{"protocol": "TCP", "port": 8080}},
						},
						map[string]any{
							"action": "allow",
							"to":     []any{map[string]any{"cidr": "0.0.0.0/0"}, map[string]any{"cidr": "::/0"}},
						},
					}},
				},
			}
			resource = "globaltrafficpolicies"
		}
		data, err := json.Marshal(object)
		if err != nil {
			return nil, err
		}
		started := time.Now()
		_, err = r.dynamic.Resource(schema.GroupVersionResource{Group: "agents.kruise.io", Version: "v1alpha1", Resource: resource}).
			Patch(ctx, r.Prefix+"-policy", types.ApplyPatchType, data, metav1.PatchOptions{FieldManager: "sandbox-scale-bench", FieldValidation: "Strict"})
		if err != nil {
			return nil, err
		}
		for gateway := range strings.SplitSeq(r.Gateway, ",") {
			probe := *r
			probe.Gateway = gateway
			probe.Path = "/bench-policy"
			probe.ExpectedStatus = 200
			probe.ExpectedBody = "sandbox-scale-ok\n"
			if blocked {
				probe.ExpectedStatus = 451
				probe.ExpectedBody = "sandbox-scale-denied"
				if r.PolicyKind == "traffic" {
					probe.ExpectedStatus = 403
				}
			}
			consecutive := 0
			var last error
			err = wait.PollUntilContextTimeout(
				ctx,
				20*time.Millisecond,
				30*time.Second,
				true,
				func(ctx context.Context) (bool, error) {
					attempt, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()
					last = probe.request(attempt, tlsConfig, r.Offset)
					if last != nil {
						consecutive = 0
					} else {
						consecutive++
					}
					return consecutive >= 10, nil
				},
			)
			if err != nil {
				return nil, fmt.Errorf(
					"policy blocked=%t gateway=%s did not converge: %w; last=%w",
					blocked,
					gateway,
					err,
					last,
				)
			}
			timings = append(
				timings,
				map[string]any{"blocked": blocked, "gateway": gateway, "seconds": time.Since(started).Seconds()},
			)
		}
	}
	return timings, nil
}
