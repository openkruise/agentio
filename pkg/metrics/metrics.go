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

// Package metrics exposes the control plane's Prometheus endpoint.
// All label values come from closed sets.
package metrics

import (
	"fmt"
	"maps"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"istio.io/istio/pkg/util/sets"
)

// knownTypes is the closed set of xDS types this control plane serves. Anything
// unrecognised folds into "other" rather than creating a new series.
var knownTypes = map[string]string{
	"type.googleapis.com/istio.workload.Address":                           "address",
	"type.googleapis.com/istio.workload.Workload":                          "workload",
	"type.googleapis.com/istio.security.Authorization":                     "authorization",
	"type.googleapis.com/agentio.extensions.SniTrafficPolicy":              "sni_traffic_policy",
	"type.googleapis.com/envoy.config.cluster.v3.Cluster":                  "cluster",
	"type.googleapis.com/envoy.config.listener.v3.Listener":                "listener",
	"type.googleapis.com/envoy.config.route.v3.RouteConfiguration":         "route",
	"type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment":   "endpoint",
	"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret": "secret",
	"type.googleapis.com/envoy.config.core.v3.TypedExtensionConfig":        "extension_config",
	"type.googleapis.com/istio.mesh.v1alpha1.ProxyConfig":                  "proxy_config",
}

// TypeLabel maps a type URL to its metric label.
func TypeLabel(typeURL string) string {
	if label, found := knownTypes[typeURL]; found {
		return label
	}
	return "other"
}

// XDSPushFailureStage is a closed classification of response failures.
type XDSPushFailureStage uint8

const (
	XDSPushFailureGenerate XDSPushFailureStage = iota
	XDSPushFailureValidate
	XDSPushFailureSend
	xdsPushFailureStageCount
)

var (
	xdsPushFailureStageLabels = [...]string{"generate", "validate", "send"}
	resourceTypeLabels        = buildResourceTypeLabels()
)

func buildResourceTypeLabels() []string {
	labels := make([]string, 0, len(knownTypes)+1)
	seen := sets.NewWithLength[string](len(knownTypes) + 1)
	for _, label := range knownTypes {
		if seen.Contains(label) {
			continue
		}
		seen.Insert(label)
		labels = append(labels, label)
	}
	labels = append(labels, "other")
	sort.Strings(labels)
	return labels
}

func emptyResourceTypeCounts() map[string]int64 {
	counts := make(map[string]int64, len(knownTypes)+1)
	for _, label := range resourceTypeLabels {
		counts[label] = 0
	}
	return counts
}

func newXDSPushFailureCounters() [xdsPushFailureStageCount]map[string]*atomic.Uint64 {
	var counters [xdsPushFailureStageCount]map[string]*atomic.Uint64
	for stage := range counters {
		counters[stage] = make(map[string]*atomic.Uint64, len(knownTypes)+1)
		for _, label := range resourceTypeLabels {
			counters[stage][label] = &atomic.Uint64{}
		}
	}
	return counters
}

type Registry struct {
	compileTotal      atomic.Uint64
	compileFailures   atomic.Uint64
	snapshotResources atomic.Int64
	xdsConnections    atomic.Int64
	xdsACKs           atomic.Uint64
	xdsNACKs          atomic.Uint64
	xdsStaleNonces    atomic.Uint64
	xdsPushes         atomic.Uint64
	xdsRequestRejects atomic.Uint64
	xdsDeniedResource atomic.Uint64
	caLeader          atomic.Int64
	onDemandCerts     atomic.Int64
	failingObjects    atomic.Int64
	krtTransforms     atomic.Uint64
	krtSlowTransforms atomic.Uint64
	pushFailures      [xdsPushFailureStageCount]map[string]*atomic.Uint64

	compileDuration     *histogram
	publishDuration     *histogram
	pushDuration        *histogram
	pushSize            *histogram
	pushBytes           *histogram
	queueDuration       *histogram
	convergenceDuration *histogram
	legacyPushDuration  *histogram
	legacyPushBytes     *histogram
	legacyQueueDuration *histogram
	legacyConvergence   *histogram

	mu                 sync.RWMutex
	resourcesByType    map[string]int64
	connectionsByClass map[string]int64
	persistentClasses  sets.Set[string]
	// Labels fold to "unknown" unless short numeric major.minor; entries are deleted at zero, bounding cardinality.
	connectionsByVersion map[string]int64
}

var Default = NewRegistry()

func NewRegistry() *Registry {
	return &Registry{
		compileDuration: newHistogram(
			"agentio_compile_duration_seconds", "Time spent on one snapshot publication attempt.", latencyBuckets),
		publishDuration: newHistogram(
			"agentio_publish_duration_seconds", "Time from a changed snapshot publication attempt through subscriber notification.", latencyBuckets),
		pushDuration: newHistogram(
			"agentio_xds_push_duration_seconds", "Time to build and send one xDS response.", latencyBuckets),
		pushSize: newHistogram(
			"agentio_xds_push_resources", "Resources carried by one xDS response.", sizeBuckets),
		pushBytes: newHistogram(
			"agentio_xds_push_size_bytes", "Serialized Any payload bytes carried by one xDS response.", byteSizeBuckets),
		queueDuration: newHistogram(
			"agentio_xds_queue_duration_seconds", "Time an xDS connection update waits for push capacity.", latencyBuckets),
		convergenceDuration: newHistogram(
			"agentio_xds_convergence_duration_seconds", "Time from connection update enqueue to successful send-side completion.", latencyBuckets),
		legacyPushDuration: newHistogram(
			"pilot_xds_push_time", "Total time in seconds Agentiod takes to generate and send one xDS response.", legacyPushLatencyBuckets),
		legacyPushBytes: newHistogram(
			"pilot_xds_config_size_bytes", "Distribution of configuration payload sizes pushed to clients.", byteSizeBuckets),
		legacyQueueDuration: newHistogram(
			"pilot_proxy_queue_time", "Time in seconds a proxy update waits in the push queue.", legacyProxyLatencyBuckets),
		legacyConvergence: newHistogram(
			"pilot_proxy_convergence_time", "Delay in seconds from proxy update enqueue to send-side completion.", legacyProxyLatencyBuckets),
		pushFailures:         newXDSPushFailureCounters(),
		resourcesByType:      emptyResourceTypeCounts(),
		connectionsByClass:   map[string]int64{},
		persistentClasses:    sets.New[string](),
		connectionsByVersion: map[string]int64{},
	}
}

// RecordCompile times a snapshot assembly and records its resource count on success.
func (r *Registry) RecordCompile(duration time.Duration, err error, resources int) {
	r.compileTotal.Add(1)
	r.compileDuration.observe(duration.Seconds())
	if err != nil {
		r.compileFailures.Add(1)
		return
	}
	r.snapshotResources.Store(int64(resources))
}

// RecordPublish times the store publish that follows a compile.
func (r *Registry) RecordPublish(duration time.Duration) {
	r.publishDuration.observe(duration.Seconds())
}

// SetSnapshotResourcesByType records the snapshot's composition, so growth can be
// attributed to a type rather than only observed in total.
func (r *Registry) SetSnapshotResourcesByType(counts map[string]int) {
	updated := emptyResourceTypeCounts()
	for typeURL, count := range counts {
		updated[TypeLabel(typeURL)] += int64(count)
	}
	r.mu.Lock()
	r.resourcesByType = updated
	r.mu.Unlock()
}

// RecordXDSPush records the duration, resource count, and bytes of one xDS response.
func (r *Registry) RecordXDSPush(duration time.Duration, resources, sizeBytes int) {
	r.xdsPushes.Add(1)
	r.pushDuration.observe(duration.Seconds())
	r.pushSize.observe(float64(resources))
	r.pushBytes.observe(float64(sizeBytes))
}

// RecordLegacyXDSPush records Agentio-compatible generation metrics. It is
// intentionally separate from RecordXDSPush because a generated and validated
// response belongs in the legacy histograms even when transport send fails.
func (r *Registry) RecordLegacyXDSPush(duration time.Duration, sizeBytes int) {
	r.legacyPushDuration.observe(duration.Seconds())
	r.legacyPushBytes.observe(float64(sizeBytes))
}

// RecordXDSPushFailure increments one member of the fixed stage/type matrix.
func (r *Registry) RecordXDSPushFailure(stage XDSPushFailureStage, typeURL string) {
	if stage >= xdsPushFailureStageCount {
		return
	}
	r.pushFailures[stage][TypeLabel(typeURL)].Add(1)
}

func (r *Registry) RecordXDSQueue(duration time.Duration) {
	r.queueDuration.observe(duration.Seconds())
	r.legacyQueueDuration.observe(duration.Seconds())
}

func (r *Registry) RecordXDSConvergence(duration time.Duration) {
	r.convergenceDuration.observe(duration.Seconds())
	r.legacyConvergence.observe(duration.Seconds())
}

func (r *Registry) AddXDSConnection(delta int64) { r.xdsConnections.Add(delta) }

// EnsureXDSConnectionClass registers a server-owned client class so its gauge
// remains queryable even when no stream of that class is connected.
func (r *Registry) EnsureXDSConnectionClass(class string) {
	class = connectionClassLabel(class)
	r.mu.Lock()
	r.persistentClasses.Insert(class)
	if _, found := r.connectionsByClass[class]; !found {
		r.connectionsByClass[class] = 0
	}
	r.mu.Unlock()
}

// AddXDSConnectionForClass tracks connections per client class, which is how a
// whole fleet of proxies failing to connect becomes visible.
func (r *Registry) AddXDSConnectionForClass(class string, delta int64) {
	class = connectionClassLabel(class)
	r.mu.Lock()
	r.connectionsByClass[class] += delta
	if r.connectionsByClass[class] <= 0 {
		if r.persistentClasses.Contains(class) {
			r.connectionsByClass[class] = 0
		} else {
			delete(r.connectionsByClass, class)
		}
	}
	r.mu.Unlock()
}

func connectionClassLabel(class string) string {
	if class == "" {
		return "unknown"
	}
	return class
}

// AddXDSConnectionForVersion tracks connections per client-reported data-plane
// version. It returns the label actually used so a disconnect can decrement the
// same series it incremented.
func (r *Registry) AddXDSConnectionForVersion(version string, delta int64) string {
	label := versionLabel(version)
	r.mu.Lock()
	r.connectionsByVersion[label] += delta
	if r.connectionsByVersion[label] <= 0 {
		delete(r.connectionsByVersion, label)
	}
	r.mu.Unlock()
	return label
}

// versionLabel reduces a self-reported build string to "major.minor" with at
// most four digits per component, or "unknown". It is a pure function and
// idempotent, so increments and decrements for the same input always pair.
func versionLabel(version string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	major, rest, found := strings.Cut(version, ".")
	if !found || !versionComponent(major) {
		return "unknown"
	}
	minor := rest
	for _, boundary := range []string{".", "-", "+"} {
		if head, _, cut := strings.Cut(minor, boundary); cut {
			minor = head
		}
	}
	if !versionComponent(minor) {
		return "unknown"
	}
	return major + "." + minor
}

func versionComponent(value string) bool {
	if len(value) == 0 || len(value) > 4 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// RecordXDSACK counts an ACK matching the latest response for its stream and type.
func (r *Registry) RecordXDSACK() { r.xdsACKs.Add(1) }

// RecordXDSStaleNonce counts ACK/NACK requests with a nonempty nonce that does
// not match the latest successfully sent response for the stream and type.
func (r *Registry) RecordXDSStaleNonce() { r.xdsStaleNonces.Add(1) }

func (r *Registry) RecordXDSNACK() { r.xdsNACKs.Add(1) }

// RecordKRTTransform counts one krt transform execution; slow marks executions past the threshold.
func (r *Registry) RecordKRTTransform(slow bool) {
	r.krtTransforms.Add(1)
	if slow {
		r.krtSlowTransforms.Add(1)
	}
}

// RecordXDSRequestRejection counts process-wide admission denials. It has no
// labels, so reconnect storms cannot grow metric cardinality.
func (r *Registry) RecordXDSRequestRejection() { r.xdsRequestRejects.Add(1) }

// RecordXDSDeniedResource counts resources omitted from a response because the
// subscribing client may not have them.
func (r *Registry) RecordXDSDeniedResource() { r.xdsDeniedResource.Add(1) }

func (r *Registry) SetCALeader(leader bool) {
	if leader {
		r.caLeader.Store(1)
	} else {
		r.caLeader.Store(0)
	}
}

func (r *Registry) SetOnDemandCerts(count int) { r.onDemandCerts.Store(int64(count)) }

// SetCompileFailingObjects reports how many inputs currently fail to compile.
// Depending on the projection, output may be omitted or retain its last-known-good value.
func (r *Registry) SetCompileFailingObjects(count int) { r.failingObjects.Store(int64(count)) }

func (r *Registry) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4")

	scalars := []struct {
		name, help, kind string
		value            any
	}{
		{"agentio_compile_total", "Total snapshot publication attempts.", "counter", r.compileTotal.Load()},
		{"agentio_compile_failures_total", "Total failed snapshot publication attempts.", "counter", r.compileFailures.Load()},
		{"agentio_compile_failing_objects", "Inputs whose latest compilation failed; published output may be omitted or retain its last-known-good value.", "gauge", r.failingObjects.Load()},
		{"agentio_snapshot_resources", "Resources in the current xDS snapshot.", "gauge", r.snapshotResources.Load()},
		{"agentio_xds_connections", "Active Delta ADS connections.", "gauge", r.xdsConnections.Load()},
		{"agentio_xds_pushes_total", "Total xDS responses sent.", "counter", r.xdsPushes.Load()},
		{"agentio_xds_acks_total", "Received ACKs matching the latest response for the stream and resource type.", "counter", r.xdsACKs.Load()},
		{"agentio_xds_stale_nonces_total", "ACK/NACK requests whose nonempty nonce does not match the latest response for the stream and resource type.", "counter", r.xdsStaleNonces.Load()},
		{"agentio_xds_nacks_total", "Total xDS NACKs.", "counter", r.xdsNACKs.Load()},
		{"agentio_xds_request_rejections_total", "New xDS streams rejected by request admission.", "counter", r.xdsRequestRejects.Load()},
		{"agentio_xds_denied_resources_total", "Resources omitted from responses because the client may not receive them.", "counter", r.xdsDeniedResource.Load()},
		{"agentio_ca_leader", "Whether this replica owns the CA rotation lease.", "gauge", r.caLeader.Load()},
		{"agentio_on_demand_certificates", "Certificates in the on-demand SDS cache.", "gauge", r.onDemandCerts.Load()},
		{"agentio_krt_transforms_total", "Total krt collection transform executions.", "counter", r.krtTransforms.Load()},
		{"agentio_krt_slow_transforms_total", "krt transform executions that exceeded the slow-transform threshold.", "counter", r.krtSlowTransforms.Load()},
	}
	for _, metric := range scalars {
		fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s %s\n%s %v\n",
			metric.name, metric.help, metric.name, metric.kind, metric.name, metric.value)
	}

	r.mu.RLock()
	resourcesByType := copyCounts(r.resourcesByType)
	connectionsByClass := copyCounts(r.connectionsByClass)
	connectionsByVersion := copyCounts(r.connectionsByVersion)
	r.mu.RUnlock()

	writeLabelled(response, "agentio_snapshot_resources_by_type",
		"Resources in the current snapshot, by xDS type.", "type", resourcesByType)
	writeLabelled(response, "agentio_xds_connections_by_class",
		"Active Delta ADS connections, by client class.", "class", connectionsByClass)
	writeLabelled(response, "agentio_xds_connections_by_version",
		"Active Delta ADS connections, by client-reported data-plane version.", "version", connectionsByVersion)
	r.writeXDSPushFailures(response)

	r.compileDuration.write(response, "")
	r.publishDuration.write(response, "")
	r.pushDuration.write(response, "")
	r.pushSize.write(response, "")
	r.pushBytes.write(response, "")
	r.queueDuration.write(response, "")
	r.convergenceDuration.write(response, "")

	// Legacy pilot_* families retain Agentio's exact observation and bucket contracts.
	r.legacyPushDuration.write(response, "")
	r.legacyPushBytes.write(response, "")
	r.legacyQueueDuration.write(response, "")
	r.legacyConvergence.write(response, "")
}

func (r *Registry) writeXDSPushFailures(response http.ResponseWriter) {
	const name = "agentio_xds_push_failures_total"
	fmt.Fprintf(response, "# HELP %s Failed xDS response attempts, by stage and xDS type.\n# TYPE %s counter\n", name, name)
	for stage, stageLabel := range xdsPushFailureStageLabels {
		for _, typeLabel := range resourceTypeLabels {
			fmt.Fprintf(response, "%s{stage=\"%s\",type=\"%s\"} %d\n",
				name, stageLabel, typeLabel, r.pushFailures[stage][typeLabel].Load())
		}
	}
}

func copyCounts(source map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(source))
	maps.Copy(result, source)
	return result
}

func writeLabelled(response http.ResponseWriter, name, help, label string, values map[string]int64) {
	fmt.Fprintf(response, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(response, "%s{%s=\"%s\"} %d\n", name, label, escapeLabelValue(key), values[key])
	}
}

func escapeLabelValue(value string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(value)
}
