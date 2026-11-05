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

package metrics

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func scrape(t testing.TB, registry *Registry) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	registry.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	return recorder.Body.String()
}

func requireLine(t testing.TB, body, line string) {
	t.Helper()
	for candidate := range strings.SplitSeq(body, "\n") {
		if strings.TrimSpace(candidate) == line {
			return
		}
	}
	t.Fatalf("missing line %q in:\n%s", line, body)
}

func histogramBucketBounds(body, name string) []string {
	prefix := name + `_bucket{le="`
	var result []string
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		bound, _, found := strings.Cut(strings.TrimPrefix(line, prefix), `"}`)
		if found {
			result = append(result, bound)
		}
	}
	return result
}

// The compile duration is a histogram: observations land in every bucket at or
// above their value, and the count and sum agree with what was recorded.
func TestCompileDurationIsAHistogram(t *testing.T) {
	registry := NewRegistry()
	registry.RecordCompile(2*time.Millisecond, nil, 10)
	registry.RecordCompile(300*time.Millisecond, nil, 10)

	body := scrape(t, registry)
	requireLine(t, body, "# TYPE agentio_compile_duration_seconds histogram")
	// 2ms falls in the 0.005 bucket; 300ms does not.
	requireLine(t, body, `agentio_compile_duration_seconds_bucket{le="0.005"} 1`)
	requireLine(t, body, `agentio_compile_duration_seconds_bucket{le="0.5"} 2`)
	requireLine(t, body, `agentio_compile_duration_seconds_bucket{le="+Inf"} 2`)
	requireLine(t, body, "agentio_compile_duration_seconds_count{} 2")
	requireLine(t, body, "agentio_compile_total 2")
}

// A failed compile increments the failure counter and does not overwrite the
// resource gauge with a count from a snapshot that was never published.
func TestFailedCompileDoesNotUpdateResourceGauge(t *testing.T) {
	registry := NewRegistry()
	registry.RecordCompile(time.Millisecond, nil, 42)
	registry.RecordCompile(time.Millisecond, fmt.Errorf("boom"), 0)

	body := scrape(t, registry)
	requireLine(t, body, "agentio_compile_failures_total 1")
	requireLine(t, body, "agentio_snapshot_resources 42")
}

// Resource counts are reported per type, using the closed label set.
func TestSnapshotCompositionUsesBoundedTypeLabels(t *testing.T) {
	registry := NewRegistry()
	registry.SetSnapshotResourcesByType(map[string]int{
		"type.googleapis.com/istio.workload.Address":  3,
		"type.googleapis.com/istio.workload.Workload": 3,
		"type.googleapis.com/some.unknown.Type":       7,
	})

	body := scrape(t, registry)
	requireLine(t, body, `agentio_snapshot_resources_by_type{type="address"} 3`)
	requireLine(t, body, `agentio_snapshot_resources_by_type{type="workload"} 3`)
	// An unrecognised type must not create a series of its own.
	requireLine(t, body, `agentio_snapshot_resources_by_type{type="other"} 7`)
	// Every member of the closed set remains queryable even when absent from the
	// latest snapshot. This makes direct zero-value alerts deterministic.
	requireLine(t, body, `agentio_snapshot_resources_by_type{type="authorization"} 0`)
	requireLine(t, body, `agentio_snapshot_resources_by_type{type="secret"} 0`)
	if strings.Contains(body, "some.unknown.Type") {
		t.Fatal("an unrecognised type URL leaked into a label value")
	}
}

// Connection classes are a closed server-owned set. Once registered, their
// series remain queryable at zero after the final stream disconnects.
func TestConnectionsByClassRemainAtZero(t *testing.T) {
	registry := NewRegistry()
	registry.EnsureXDSConnectionClass("egress-gateway")
	registry.EnsureXDSConnectionClass("shared-ztunnel")
	registry.AddXDSConnectionForClass("egress-gateway", 1)
	registry.AddXDSConnectionForClass("egress-gateway", 1)
	registry.AddXDSConnectionForClass("shared-ztunnel", 1)

	body := scrape(t, registry)
	requireLine(t, body, `agentio_xds_connections_by_class{class="egress-gateway"} 2`)
	requireLine(t, body, `agentio_xds_connections_by_class{class="shared-ztunnel"} 1`)

	registry.AddXDSConnectionForClass("shared-ztunnel", -1)
	body = scrape(t, registry)
	requireLine(t, body, `agentio_xds_connections_by_class{class="shared-ztunnel"} 0`)
}

func TestUnregisteredConnectionClassIsReleasedAtZero(t *testing.T) {
	registry := NewRegistry()
	registry.AddXDSConnectionForClass("temporary-class", 1)
	registry.AddXDSConnectionForClass("temporary-class", -1)
	if body := scrape(t, registry); strings.Contains(body, `class="temporary-class"`) {
		t.Fatalf("an unregistered zero-valued class is still reported:\n%s", body)
	}
}

func TestMetricHelpDescribesPublicationAndLastKnownGoodSemantics(t *testing.T) {
	body := scrape(t, NewRegistry())
	requireLine(t, body, "# HELP agentio_compile_total Total snapshot publication attempts.")
	requireLine(t, body, "# HELP agentio_compile_failures_total Total failed snapshot publication attempts.")
	requireLine(t, body, "# HELP agentio_compile_duration_seconds Time spent on one snapshot publication attempt.")
	requireLine(t, body, "# HELP agentio_publish_duration_seconds Time from a changed snapshot publication attempt through subscriber notification.")
	requireLine(t, body, "# HELP agentio_compile_failing_objects Inputs whose latest compilation failed; published output may be omitted or retain its last-known-good value.")
}

// Version labels come from client-reported strings, so anything that is not a
// short numeric major.minor must fold into "unknown" before it becomes a series.
func TestVersionLabelBoundsClientInput(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"1.24.2", "1.24"},
		{"v1.24.2", "1.24"},
		{"1.30", "1.30"},
		{"1.24.2-dev+sha.abc123", "1.24"},
		{"", "unknown"},
		{"nightly", "unknown"},
		{"1.", "unknown"},
		{".24", "unknown"},
		{"12345.0", "unknown"},
		{"1.x", "unknown"},
		{`1."injected`, "unknown"},
	}
	for _, tc := range tests {
		if got := versionLabel(tc.version); got != tc.want {
			t.Errorf("versionLabel(%q) = %q, want %q", tc.version, got, tc.want)
		}
	}
	// Idempotence pairs an increment with its deferred decrement.
	for _, tc := range tests {
		if got := versionLabel(tc.want); got != tc.want {
			t.Errorf("versionLabel(%q) = %q, want it to be idempotent", tc.want, got)
		}
	}
}

func TestConnectionsByVersionAreReleased(t *testing.T) {
	registry := NewRegistry()
	label := registry.AddXDSConnectionForVersion("1.24.2", 1)
	registry.AddXDSConnectionForVersion("1.24.9", 1)
	registry.AddXDSConnectionForVersion("garbage", 1)

	body := scrape(t, registry)
	requireLine(t, body, `agentio_xds_connections_by_version{version="1.24"} 2`)
	requireLine(t, body, `agentio_xds_connections_by_version{version="unknown"} 1`)

	registry.AddXDSConnectionForVersion(label, -1)
	registry.AddXDSConnectionForVersion("1.24.9", -1)
	body = scrape(t, registry)
	if strings.Contains(body, `version="1.24"`) {
		t.Fatalf("a version with no connections is still reported:\n%s", body)
	}
}

func TestPushMetricsRecordLatencyAndSize(t *testing.T) {
	registry := NewRegistry()
	registry.RecordXDSPush(3*time.Millisecond, 120, 12_000)

	body := scrape(t, registry)
	requireLine(t, body, "agentio_xds_pushes_total 1")
	requireLine(t, body, `agentio_xds_push_duration_seconds_bucket{le="0.005"} 1`)
	// 120 resources fall in the 500 bucket but not the 100 one.
	requireLine(t, body, `agentio_xds_push_resources_bucket{le="100"} 0`)
	requireLine(t, body, `agentio_xds_push_resources_bucket{le="500"} 1`)
}

func TestPushFailureMetricsExposeClosedStageAndTypeLabels(t *testing.T) {
	registry := NewRegistry()
	registry.RecordXDSPushFailure(XDSPushFailureGenerate, "type.googleapis.com/istio.workload.Address")
	registry.RecordXDSPushFailure(XDSPushFailureValidate, "type.googleapis.com/example.Unknown")
	body := scrape(t, registry)
	requireLine(t, body, "# TYPE agentio_xds_push_failures_total counter")
	requireLine(t, body, `agentio_xds_push_failures_total{stage="generate",type="address"} 1`)
	requireLine(t, body, `agentio_xds_push_failures_total{stage="validate",type="other"} 1`)
	requireLine(t, body, `agentio_xds_push_failures_total{stage="send",type="address"} 0`)
	if strings.Contains(body, "example.Unknown") {
		t.Fatal("an unrecognised failure type URL leaked into a label value")
	}
}

func TestAgentioDashboardCompatibilityHistograms(t *testing.T) {
	registry := NewRegistry()
	registry.RecordXDSPush(3*time.Millisecond, 120, 12_000)
	registry.RecordLegacyXDSPush(3*time.Millisecond, 12_000)
	registry.RecordXDSQueue(200 * time.Millisecond)
	registry.RecordXDSConvergence(250 * time.Millisecond)

	body := scrape(t, registry)
	requireLine(t, body, "agentio_xds_push_duration_seconds_count{} 1")
	requireLine(t, body, "pilot_xds_push_time_count{} 1")
	requireLine(t, body, "agentio_xds_push_duration_seconds_sum{} 0.003")
	requireLine(t, body, "pilot_xds_push_time_sum{} 0.003")
	requireLine(t, body, "agentio_xds_push_size_bytes_count{} 1")
	requireLine(t, body, "pilot_xds_config_size_bytes_count{} 1")
	requireLine(t, body, `pilot_xds_config_size_bytes_bucket{le="10000"} 0`)
	requireLine(t, body, `pilot_xds_config_size_bytes_bucket{le="1e+06"} 1`)
	requireLine(t, body, "agentio_xds_queue_duration_seconds_count{} 1")
	requireLine(t, body, "pilot_proxy_queue_time_count{} 1")
	requireLine(t, body, "agentio_xds_convergence_duration_seconds_count{} 1")
	requireLine(t, body, "pilot_proxy_convergence_time_count{} 1")
}

func TestLegacyCompatibilityHistogramsUseAgentioBuckets(t *testing.T) {
	body := scrape(t, NewRegistry())
	for _, tc := range []struct {
		name string
		want []string
	}{
		{
			name: "pilot_xds_push_time",
			want: []string{"0.01", "0.1", "1", "3", "5", "10", "20", "30", "+Inf"},
		},
		{
			name: "pilot_xds_config_size_bytes",
			want: []string{"1", "10000", "1e+06", "4e+06", "1e+07", "4e+07", "+Inf"},
		},
		{
			name: "pilot_proxy_queue_time",
			want: []string{"0.1", "0.5", "1", "3", "5", "10", "20", "30", "+Inf"},
		},
		{
			name: "pilot_proxy_convergence_time",
			want: []string{"0.1", "0.5", "1", "3", "5", "10", "20", "30", "+Inf"},
		},
	} {
		if got := histogramBucketBounds(body, tc.name); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s bucket bounds = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCanonicalPushDoesNotImplicitlyRecordLegacyCompatibilityHistograms(t *testing.T) {
	registry := NewRegistry()
	registry.RecordXDSPush(3*time.Millisecond, 2, 12_000)

	body := scrape(t, registry)
	requireLine(t, body, "agentio_xds_push_duration_seconds_count{} 1")
	requireLine(t, body, "pilot_xds_push_time_count{} 0")
	requireLine(t, body, "pilot_xds_config_size_bytes_count{} 0")
}

// A label value containing a quote or backslash must be escaped, or the exposition
// format is corrupted and the whole scrape is rejected.
func TestLabelValuesAreEscaped(t *testing.T) {
	registry := NewRegistry()
	registry.AddXDSConnectionForClass(`we"ird\class`, 1)
	body := scrape(t, registry)
	requireLine(t, body, `agentio_xds_connections_by_class{class="we\"ird\\class"} 1`)
}

// Observations arrive from many goroutines: the histogram's sum is updated with a
// compare-and-swap loop, so this would surface a lost update.
func TestHistogramIsSafeUnderConcurrentObservation(t *testing.T) {
	registry := NewRegistry()
	const goroutines, each = 8, 200
	var group sync.WaitGroup
	for range goroutines {
		group.Go(func() {
			for range each {
				registry.RecordXDSPush(time.Millisecond, 1, 1)
			}
		})
	}
	group.Wait()

	body := scrape(t, registry)
	requireLine(t, body, fmt.Sprintf("agentio_xds_pushes_total %d", goroutines*each))
	requireLine(t, body, fmt.Sprintf(`agentio_xds_push_duration_seconds_bucket{le="+Inf"} %d`, goroutines*each))
	requireLine(t, body, fmt.Sprintf("agentio_xds_push_duration_seconds_count{} %d", goroutines*each))
}

func TestCALeaderAndOnDemandGauges(t *testing.T) {
	registry := NewRegistry()
	registry.SetCALeader(true)
	registry.SetOnDemandCerts(9)
	registry.SetCompileFailingObjects(2)
	registry.RecordXDSNACK()
	registry.RecordXDSDeniedResource()
	registry.RecordXDSRequestRejection()

	body := scrape(t, registry)
	requireLine(t, body, "agentio_ca_leader 1")
	requireLine(t, body, "agentio_on_demand_certificates 9")
	requireLine(t, body, "agentio_compile_failing_objects 2")
	requireLine(t, body, "agentio_xds_nacks_total 1")
	requireLine(t, body, "agentio_xds_denied_resources_total 1")
	requireLine(t, body, "agentio_xds_request_rejections_total 1")

	registry.SetCALeader(false)
	requireLine(t, scrape(t, registry), "agentio_ca_leader 0")
}
