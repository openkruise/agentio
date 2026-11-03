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

import (
	"fmt"
	"math"
	"runtime"
	"time"

	"istio.io/istio/pkg/env"
	"k8s.io/apimachinery/pkg/api/resource"
)

var (
	KRTDebounceAfter = env.Register(
		"AGENTIO_KRT_DEBOUNCE",
		200*time.Millisecond,
		"Quiet period before platform TrafficPolicy and SecurityProfile events are distributed; Sandbox inputs and their embedded policies are not debounced.",
	).Get()
	KRTDebounceMax = env.Register(
		"AGENTIO_KRT_DEBOUNCE_MAX",
		time.Second,
		"Maximum wait for policy event distribution during continuous policy updates.",
	).Get()
	PushDebounceAfter = env.Register(
		"AGENTIO_PUSH_DEBOUNCE",
		time.Duration(0),
		"Optional quiet period before all compiled resource changes are published; zero disables push debounce.",
	).Get()
	PushDebounceMax = env.Register(
		"AGENTIO_PUSH_DEBOUNCE_MAX",
		time.Second,
		"Maximum wait when push debounce is enabled; must be at least AGENTIO_PUSH_DEBOUNCE.",
	).Get()
	ClientQueueSize = env.Register(
		"AGENTIO_CLIENT_QUEUE_SIZE",
		100,
		"Maximum requests queued per xDS client before the stream is considered stuck.",
	).Get()
	MaxServerConnectionAge, maxServerConnectionAgeErr = time.ParseDuration(env.Register(
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"30m",
		"Maximum lifetime of a server-side gRPC connection before a graceful close. Zero disables periodic connection expiry.",
	).Get())
	PushConcurrency = env.Register(
		"AGENTIO_PUSH_CONCURRENCY",
		defaultPushConcurrency(),
		"Concurrency limit for background pushes and for streams awaiting xDS acknowledgements, with independent initial-response, established-request, and background-response pools. "+
			"Defaults to min(15 + 5 * GOMAXPROCS, 100).",
	).Get()
	XDSCPUBudget = env.Register(
		"AGENTIO_XDS_CPU_BUDGET",
		"",
		"CPU budget for automatic new xDS stream admission, as a positive Kubernetes quantity (for example 500m or 2). "+
			"The chart uses the CPU limit, falling back to the CPU request. Empty uses min(NumCPU, GOMAXPROCS); "+
			"an explicit budget is also bounded by that runtime CPU count.",
	).Get()
	XDSCPUCores, xdsCPUBudgetErr = xdsCPUCores(XDSCPUBudget, min(runtime.NumCPU(), runtime.GOMAXPROCS(0)))
	RequestRateLimit             = effectiveRequestRateLimit(env.Register(
		"AGENTIO_MAX_REQUESTS_PER_SECOND",
		0.0,
		"Maximum new xDS streams accepted per second across the process; does not throttle ACKs or server pushes. "+
			"Zero automatically selects min(250 * effective CPU budget, 1000); see AGENTIO_XDS_CPU_BUDGET.",
	).Get())
)

func validateXDS() error {
	if xdsCPUBudgetErr != nil {
		return xdsCPUBudgetErr
	}
	if maxServerConnectionAgeErr != nil {
		return fmt.Errorf("parse max server connection age: %w", maxServerConnectionAgeErr)
	}
	if MaxServerConnectionAge < 0 {
		return fmt.Errorf("max server connection age must not be negative")
	}
	if KRTDebounceAfter <= 0 {
		return fmt.Errorf("KRT debounce quiet period must be positive")
	}
	if KRTDebounceMax < KRTDebounceAfter {
		return fmt.Errorf("KRT debounce maximum wait must be at least the quiet period")
	}
	if PushDebounceAfter < 0 {
		return fmt.Errorf("push debounce quiet period must not be negative")
	}
	if PushDebounceMax < PushDebounceAfter {
		return fmt.Errorf("push debounce maximum wait must be at least the quiet period")
	}
	if PushConcurrency <= 0 {
		return fmt.Errorf("push concurrency must be positive")
	}
	if RequestRateLimit <= 0 || math.IsNaN(RequestRateLimit) || math.IsInf(RequestRateLimit, 0) {
		return fmt.Errorf("request rate limit must be finite and positive")
	}
	if ClientQueueSize <= 0 {
		return fmt.Errorf("client queue size must be positive")
	}
	return nil
}

func defaultPushConcurrency() int {
	limit := 15 + 5*runtime.GOMAXPROCS(0)
	if limit > 100 {
		return 100
	}
	return limit
}

func effectiveRequestRateLimit(configured float64) float64 {
	if configured <= 0 || math.IsNaN(configured) || math.IsInf(configured, 0) {
		return min(250*XDSCPUCores, 1000)
	}
	return configured
}

func xdsCPUCores(configured string, runtimeCPUs int) (float64, error) {
	if configured == "" {
		return float64(runtimeCPUs), nil
	}
	budget, err := resource.ParseQuantity(configured)
	if err != nil {
		return 0, fmt.Errorf("parse AGENTIO_XDS_CPU_BUDGET: %w", err)
	}
	cores := budget.AsApproximateFloat64()
	if cores <= 0 || math.IsNaN(cores) || math.IsInf(cores, 0) {
		return 0, fmt.Errorf("AGENTIO_XDS_CPU_BUDGET must be finite and positive")
	}
	return min(cores, float64(runtimeCPUs)), nil
}
