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

package xds

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"

	"github.com/openkruise/agentio/internal/testutil"
	"github.com/openkruise/agentio/pkg/security/mitm"
)

type compatibilityWireCounts struct {
	resources  atomic.Int64
	nacks      atomic.Int64
	responses  atomic.Int64
	restored   atomic.Int64
	overlapped atomic.Int64
}
type compatibilityWireStream struct {
	grpc.ServerStream
	counts *compatibilityWireCounts
}

func (s *compatibilityWireStream) SendMsg(value any) error {
	err := s.ServerStream.SendMsg(value)
	if err == nil {
		if response, ok := value.(*discoveryv3.DeltaDiscoveryResponse); ok {
			s.counts.responses.Add(1)
			for _, resource := range response.Resources {
				if strings.HasPrefix(resource.Name, "load-") {
					s.counts.resources.Add(1)
				}
			}
		}
	}
	return err
}
func (s *compatibilityWireStream) RecvMsg(value any) error {
	err := s.ServerStream.RecvMsg(value)
	if err == nil {
		if request, ok := value.(*discoveryv3.DeltaDiscoveryRequest); ok {
			if request.ErrorDetail != nil {
				s.counts.nacks.Add(1)
			}
			for name := range request.InitialResourceVersions {
				if strings.HasPrefix(name, "load-") {
					s.counts.restored.Add(1)
				}
			}
			for _, name := range request.ResourceNamesSubscribe {
				if _, held := request.InitialResourceVersions[name]; held && strings.HasPrefix(name, "load-") {
					s.counts.overlapped.Add(1)
				}
			}
		}
	}
	return err
}

type compatibilityCountingSigner struct {
	mitm.DomainCertificateSigner
	calls atomic.Int64
}

func (s *compatibilityCountingSigner) SignDNS(
	ctx context.Context,
	name string,
	lifetime time.Duration,
) (mitm.SignedCertificate, error) {
	s.calls.Add(1)
	return s.DomainCertificateSigner.SignDNS(ctx, name, lifetime)
}

// Run after the compatibility checks, sharing their real Envoy and ADS transport.
// Opt in separately because this deliberately allocates tens of thousands of TLS contexts.
func runEnvoyCertificateLoad(
	t *testing.T,
	provider *compatibilityCertificates,
	wire *compatibilityWireCounts,
	newSigner func() *mitm.MITMSigner,
	restartADS func(),
	dial func(string, uint16, []uint16) (*tls.Conn, error),
	adminFile string,
	envoyPID int,
) {
	raw := os.Getenv("AGENTIO_TEST_SDS_CERTIFICATES")
	if raw == "" {
		return
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 1 {
		t.Fatalf("invalid certificate count %q", raw)
	}
	// Two-minute usable TTL: the whole cold population should fit before expiry.
	// The final phase waits for that actual deadline and checks Envoy removes everything.
	installIssuer := func() (*compatibilityCountingSigner, context.CancelFunc) {
		signer := newSigner()
		counted := &compatibilityCountingSigner{DomainCertificateSigner: signer}
		ctx, cancel := context.WithCancel(t.Context())
		issuer, err := mitm.NewOnDemandIssuer(
			ctx,
			mitm.DomainSignerSource{Signer: counted, State: signer.State()},
			allowCompatibilityGateway{},
			mitm.OnDemandOptions{
				LeafLifetime:    3 * time.Minute,
				RenewBefore:     time.Minute,
				CacheMaxEntries: count + 100,
				SignConcurrency: 8,
			},
		)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		provider.current.Store(issuer)
		return counted, cancel
	}
	counted, cancelIssuer := installIssuer()
	defer func() { cancelIssuer() }()
	restartADS()
	adminBytes, err := os.ReadFile(adminFile)
	if err != nil {
		t.Fatal(err)
	}
	admin := "http://" + strings.TrimSpace(string(adminBytes))
	httpClient := &http.Client{Timeout: 15 * time.Second}
	secretCount := func() int {
		response, err := httpClient.Get(admin + "/config_dump?resource=dynamic_active_secrets&mask=name")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := response.Body.Close(); err != nil {
				t.Error(err)
			}
		}()
		if response.StatusCode != 200 {
			t.Fatalf("secret count HTTP %d", response.StatusCode)
		}
		var dump struct {
			Configs []struct {
				Name string `json:"name"`
			} `json:"configs"`
		}
		if err := json.NewDecoder(response.Body).Decode(&dump); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, secret := range dump.Configs {
			if strings.HasPrefix(secret.Name, "load-") {
				n++
			}
		}
		return n
	}
	cpuSeconds := func() float64 {
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	}
	reportMemory := func(phase string) {
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		t.Logf(
			"MEM phase=%s go_heap_mib=%.1f go_objects=%d goroutines=%d",
			phase,
			float64(mem.HeapAlloc)/(1<<20),
			mem.HeapObjects,
			runtime.NumGoroutine(),
		)
		for _, pid := range []int{os.Getpid(), envoyPID} {
			data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			if err != nil {
				t.Fatal(err)
			}
			for line := range strings.SplitSeq(string(data), "\n") {
				if strings.HasPrefix(line, "VmRSS:") || strings.HasPrefix(line, "VmHWM:") {
					t.Logf("MEM pid=%d %s", pid, line)
				}
			}
		}
	}
	var latestDeadline atomic.Int64
	populate := func(phase string) {
		t.Helper()
		samples := make([]time.Duration, count)
		var next atomic.Int64
		var failures atomic.Int64
		var first sync.Once
		start, cpuStart := time.Now(), cpuSeconds()
		before := counted.calls.Load()
		var wg sync.WaitGroup
		for range 32 {
			wg.Go(func() {
				for {
					n := int(next.Add(1) - 1)
					if n >= count {
						return
					}
					begin := time.Now()
					conn, err := dial(fmt.Sprintf("load-%05d.example.com", n), tls.VersionTLS13, nil)
					samples[n] = time.Since(begin)
					if err != nil {
						failures.Add(1)
						first.Do(func() { t.Errorf("%s handshake: %v", phase, err) })
						continue
					}
					deadline := conn.ConnectionState().PeerCertificates[0].NotAfter.Add(-time.Minute).UnixNano()
					for old := latestDeadline.Load(); deadline > old && !latestDeadline.CompareAndSwap(old, deadline); old = latestDeadline.Load() {
					}
					closeCompatibilityConnection(t, conn)
				}
			})
		}
		wg.Wait()
		elapsed := time.Since(start)
		slices.Sort(samples)
		t.Logf(
			"LOAD phase=%s domains=%d failures=%d wall=%s rate=%.1f/s p50=%s p95=%s p99=%s max=%s sign_calls=%d cpu_seconds=%.2f",
			phase,
			count,
			failures.Load(),
			elapsed,
			float64(count)/elapsed.Seconds(),
			samples[count/2],
			samples[count*95/100],
			samples[count*99/100],
			samples[count-1],
			counted.calls.Load()-before,
			cpuSeconds()-cpuStart,
		)
		if failures.Load() != 0 {
			t.FailNow()
		}
		if active := secretCount(); active != count {
			t.Fatalf("%s active secrets=%d, want %d (population may have exceeded TTL)", phase, active, count)
		}
		reportMemory(phase)
	}
	populate("initial-cold")
	// Envoy restores both subscriptions and versions; neither a warm nor a cold
	// control plane should resend these certificate bodies or reset their TTLs.
	start, cpuStart, sentBefore, signBefore := time.Now(), cpuSeconds(), wire.resources.Load(), counted.calls.Load()
	restoredBefore, overlapBefore, responsesBefore := wire.restored.Load(), wire.overlapped.Load(), wire.responses.Load()
	restartADS()
	testutil.WaitFor(t, 90*time.Second, func() bool {
		return wire.restored.Load()-restoredBefore >= int64(count) && wire.responses.Load() > responsesBefore
	}, "warm reconciliation")
	if wire.overlapped.Load()-overlapBefore < int64(count) {
		t.Fatal("Envoy did not restore subscriptions alongside versions")
	}
	t.Logf(
		"REPLAY phase=warm domains=%d wall=%s sign_calls=%d cpu_seconds=%.2f",
		count,
		time.Since(start),
		counted.calls.Load()-signBefore,
		cpuSeconds()-cpuStart,
	)
	if counted.calls.Load() != signBefore || wire.resources.Load() != sentBefore {
		t.Fatal("warm reconnect signed or resent held certificates")
	}
	populate("warm-handshakes")
	// Replace the issuer AND signer, retaining the CA but losing the certificate cache.
	cancelIssuer()
	counted, cancelIssuer = installIssuer()
	start, cpuStart, sentBefore = time.Now(), cpuSeconds(), wire.resources.Load()
	restoredBefore, overlapBefore, responsesBefore = wire.restored.Load(), wire.overlapped.Load(), wire.responses.Load()
	restartADS()
	// Submit genuine new demand while cold replay is in flight.
	freshStart := time.Now()
	fresh, err := dial("fresh-during-replay.example.com", tls.VersionTLS13, nil)
	if err != nil {
		t.Fatalf("fresh demand during cold replay: %v", err)
	}
	closeCompatibilityConnection(t, fresh)
	t.Logf("REPLAY fresh_demand_latency=%s", time.Since(freshStart))
	testutil.WaitFor(t, 90*time.Second, func() bool {
		return wire.restored.Load()-restoredBefore >= int64(count) && wire.responses.Load() > responsesBefore
	}, "cold reconciliation")
	if wire.overlapped.Load()-overlapBefore < int64(count) || wire.resources.Load() != sentBefore {
		t.Fatal("cold reconnect failed zero-payload restoration")
	}
	if counted.calls.Load() != 1 {
		t.Fatalf("cold reconnect signed %d certificates, want only the fresh domain", counted.calls.Load())
	}
	t.Logf(
		"REPLAY phase=cold domains=%d wall=%s sign_calls=%d cpu_seconds=%.2f",
		count,
		time.Since(start),
		counted.calls.Load(),
		cpuSeconds()-cpuStart,
	)
	populate("after-cold-replay")
	if counted.calls.Load() != 1 || wire.resources.Load() != sentBefore {
		t.Fatal("held certificates were reissued during post-reconnect handshakes")
	}
	if wire.nacks.Load() != 0 {
		t.Fatalf("Envoy NACKs=%d", wire.nacks.Load())
	}
	// Wait until the last delivered usable deadline without touching these names,
	// so renewed demand cannot hide TTL removal.
	deadline := time.Unix(0, latestDeadline.Load())
	if delay := time.Until(deadline.Add(-3 * time.Second)); delay > 0 {
		t.Logf("EXPIRY waiting=%s for %d actual Envoy secrets", delay, count)
		time.Sleep(delay)
	}
	// To test expiry without generating replacements, keep the current stream;
	// the functional test separately reconnects at its short TTL boundary.
	testutil.WaitFor(t, 90*time.Second, func() bool { return secretCount() == 0 }, "all Envoy resources expire")
	runtime.GC()
	reportMemory("after-expiry")
	t.Logf("EXPIRY active_secrets=0 domains=%d", count)
	populate("after-expiry-cold")
}
