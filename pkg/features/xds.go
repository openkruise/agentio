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
	"strconv"
	"strings"
	"time"

	"istio.io/istio/pkg/env"
	"k8s.io/apimachinery/pkg/api/resource"
)

var (
	// XDSClientClasses limits ADS admission by authenticated client class.
	XDSClientClasses = env.Register(
		"AGENTIO_XDS_CLIENT_CLASSES",
		"",
		"Comma-separated authenticated ADS client classes accepted by this process: shared-ztunnel,dedicated-ztunnel,egress-gateway,agentio-egress,epe. Empty accepts all classes. Does not restrict certificate issuance.",
	).Get()
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
		"Maximum incoming requests buffered per xDS stream before reads apply backpressure.",
	).Get()
	MaxServerConnectionAge, maxServerConnectionAgeErr = time.ParseDuration(env.Register(
		"AGENTIO_KEEPALIVE_MAX_SERVER_CONNECTION_AGE",
		"30m",
		"Maximum lifetime of a server-side gRPC connection before a graceful close. Zero disables periodic connection expiry.",
	).Get())
	PushConcurrency = env.Register(
		"AGENTIO_PUSH_CONCURRENCY",
		defaultPushConcurrency(),
		"Concurrency limit for initializing streams, background pushes, and streams awaiting xDS acknowledgements, with independent admission, initial-response, established-request, and background-response pools. "+
			"Defaults to min(15 + 5 * GOMAXPROCS, 100).",
	).Get()
	XDSMaxPodStreams, xdsMaxPodStreamsErr = strconv.Atoi(
		env.Register("AGENTIO_XDS_MAX_POD_STREAMS", "0", "Maximum live dedicated Pod ADS streams per process. Zero disables the limit; full replicas reject new Pod streams without closing established streams or consuming gateway/EPE capacity.").
			Get(),
	)
	XDSInitialAdmissionTimeout, xdsInitialAdmissionTimeoutErr = time.ParseDuration(env.Register(
		"AGENTIO_XDS_INITIAL_ADMISSION_TIMEOUT",
		"1s",
		"Maximum wait for a new stream initialization slot before authentication; must be positive.",
	).Get())
	XDSRateLimitTimeout, xdsRateLimitTimeoutErr = time.ParseDuration(env.Register(
		"AGENTIO_XDS_RATE_LIMIT_TIMEOUT",
		"1s",
		"Maximum wait for new-stream rate admission before authentication; must be positive.",
	).Get())
	XDSSendTimeout, xdsSendTimeoutErr = time.ParseDuration(env.Register(
		"AGENTIO_XDS_SEND_TIMEOUT",
		"5s",
		"Maximum duration of one xDS response send before closing the stream; must be positive.",
	).Get())
	XDSACKTimeout, xdsACKTimeoutErr = time.ParseDuration(env.Register(
		"AGENTIO_XDS_ACK_TIMEOUT",
		"5s",
		"Maximum time an xDS response may remain unacknowledged before closing the stream; must be positive.",
	).Get())
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
	for _, class := range AllowedXDSClientClasses() {
		switch class {
		case "shared-ztunnel", "dedicated-ztunnel", "egress-gateway", "agentio-egress", "epe":
		default:
			return fmt.Errorf("invalid AGENTIO_XDS_CLIENT_CLASSES entry %q", class)
		}
	}
	if xdsMaxPodStreamsErr != nil {
		return fmt.Errorf("parse AGENTIO_XDS_MAX_POD_STREAMS: %w", xdsMaxPodStreamsErr)
	}
	if XDSMaxPodStreams < 0 {
		return fmt.Errorf("AGENTIO_XDS_MAX_POD_STREAMS must not be negative")
	}
	for _, timeout := range []struct {
		name  string
		value time.Duration
		err   error
	}{
		{"AGENTIO_XDS_INITIAL_ADMISSION_TIMEOUT", XDSInitialAdmissionTimeout, xdsInitialAdmissionTimeoutErr},
		{"AGENTIO_XDS_RATE_LIMIT_TIMEOUT", XDSRateLimitTimeout, xdsRateLimitTimeoutErr},
		{"AGENTIO_XDS_SEND_TIMEOUT", XDSSendTimeout, xdsSendTimeoutErr},
		{"AGENTIO_XDS_ACK_TIMEOUT", XDSACKTimeout, xdsACKTimeoutErr},
	} {
		if timeout.err != nil {
			return fmt.Errorf("parse %s: %w", timeout.name, timeout.err)
		}
		if timeout.value <= 0 {
			return fmt.Errorf("%s must be positive", timeout.name)
		}
	}
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

// AllowedXDSClientClasses returns the configured classes; nil accepts all classes.
func AllowedXDSClientClasses() []string {
	if XDSClientClasses == "" {
		return nil
	}
	var classes []string
	for class := range strings.SplitSeq(XDSClientClasses, ",") {
		classes = append(classes, strings.TrimSpace(class))
	}
	return classes
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
