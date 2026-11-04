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
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/structpb"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openkruise/agentio/bench/xds/fakeclient"
	"github.com/openkruise/agentio/pkg/model"
)

type watchStats struct {
	mu         sync.Mutex
	Connected  int
	Responses  int
	Reconnects int
	LastError  string
	Resources  map[int]map[string]map[string]string
}

type watchCredentials struct {
	pod              *corev1.Pod
	token            *authenticationv1.TokenRequest
	receivedResponse bool
}

func (r *runner) watch(ctx context.Context) (any, error) {
	if r.Action == "watch-sidecar" && r.ConnectionRate <= 0 {
		return nil, fmt.Errorf("connection-rate must be positive")
	}
	cm, err := r.kube.CoreV1().ConfigMaps(r.System).Get(ctx, "sandbox-scale-ca-root-cert", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cm.Data["root-cert.pem"])) {
		return nil, fmt.Errorf("empty roots")
	}
	if r.Action != "watch-sidecar" {
		_, err = r.kube.CoreV1().
			ServiceAccounts(r.System).
			Create(ctx, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "ztunnel"}}, metav1.CreateOptions{})
		if err != nil && !apierrors.IsAlreadyExists(err) {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, r.Duration)
	defer cancel()
	stats := &watchStats{Resources: map[int]map[string]map[string]string{}}
	prepare := *r
	prepare.Count = (r.Count + 99) / 100
	prepare.Offset = 0
	if r.Action == "watch-sidecar" {
		prepare.Count = r.Count
	} else if err := prepare.parallel(ctx, func(ctx context.Context, i int) error {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("node-proxy-%04d", i),
				Namespace: r.System,
				Labels:    map[string]string{"bench.agentio.io/run": r.Prefix},
			},
			Spec: corev1.PodSpec{
				NodeName:           r.node(i * 100),
				ServiceAccountName: "ztunnel",
				Containers:         []corev1.Container{{Name: "ztunnel", Image: "registry.k8s.io/pause:3.10"}},
				Tolerations: []corev1.Toleration{
					{
						Key:      "kwok.x-k8s.io/node",
						Operator: corev1.TolerationOpExists,
						Effect:   corev1.TaintEffectNoSchedule,
					},
				},
			},
		}
		_, e := r.kube.CoreV1().Pods(r.System).Create(ctx, pod, metav1.CreateOptions{})
		if apierrors.IsAlreadyExists(e) {
			return nil
		}
		return e
	}); err != nil {
		return nil, err
	}
	var workers sync.WaitGroup
	admission := rate.NewLimiter(rate.Limit(r.ConnectionRate), 1)
	for i := range prepare.Count {
		workers.Go(func() {
			if r.Action == "watch-sidecar" {
				if err := admission.Wait(ctx); err != nil {
					return
				}
				i += r.Offset
			}
			r.watchNode(ctx, i, roots, stats)
		})
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() {
		cancel()
		workers.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return r.watchSnapshot(stats), nil
		case <-ticker.C:
			value := r.watchSnapshot(stats)
			data, e := json.Marshal(value)
			if e != nil {
				return nil, e
			}
			fmt.Println(string(data))
			if r.Output != "" {
				if e = os.WriteFile(r.Output+".tmp", append(data, '\n'), 0600); e != nil {
					cancel()
					return nil, e
				}
				if e = os.Rename(r.Output+".tmp", r.Output+".live"); e != nil {
					return nil, e
				}
			}
		}
	}
}

func (r *runner) watchSnapshot(stats *watchStats) any {
	stats.mu.Lock()
	defer stats.mu.Unlock()
	counts := map[string]int{}
	versions := map[string]int{}
	ready := 0
	for _, types := range stats.Resources {
		if len(types) == 3 {
			ready++
		}
		for typ, resources := range types {
			counts[typ] += len(resources)
			if typ == model.TrafficPolicyType {
				for _, version := range resources {
					versions[version]++
				}
			}
		}
	}
	return map[string]any{
		"time":            time.Now(),
		"connected":       stats.Connected,
		"ready":           ready,
		"responses":       stats.Responses,
		"reconnects":      stats.Reconnects,
		"resources":       counts,
		"policy_versions": versions,
		"last_error":      stats.LastError,
	}
}

func (r *runner) watchNode(ctx context.Context, i int, roots *x509.CertPool, stats *watchStats) {
	credentials := &watchCredentials{}
	backoff := 10 * time.Millisecond
	for ctx.Err() == nil {
		credentials.receivedResponse = false
		err := r.watchStream(ctx, i, roots, stats, credentials)
		if ctx.Err() != nil {
			return
		}
		stats.mu.Lock()
		stats.Reconnects++
		stats.LastError = err.Error()
		stats.mu.Unlock()
		if credentials.receivedResponse {
			backoff = 10 * time.Millisecond
		}
		backoff = min(2*backoff, 15*time.Second)
		// Cache the projected token across reconnects; spread admission retries.
		delay := time.Duration(float64(backoff) * (0.8 + 0.4*rand.Float64()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

func (r *runner) watchStream(ctx context.Context, i int, roots *x509.CertPool, stats *watchStats, credentials *watchCredentials) error {
	name := fmt.Sprintf("node-proxy-%04d", i)
	namespace, account, node := r.System, "ztunnel", r.node(i*100)
	if r.Action == "watch-sidecar" {
		name, namespace, account, node = resourceName(i), r.namespace(i), "sandbox", r.node(i)
	}
	if credentials.pod == nil {
		pod, err := r.kube.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		credentials.pod = pod
	}
	pod := credentials.pod
	if credentials.token == nil || time.Until(credentials.token.Status.ExpirationTimestamp.Time) < 5*time.Minute {
		token, err := r.kube.CoreV1().
			ServiceAccounts(namespace).
			CreateToken(ctx, account, &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"agentio-ca"}, BoundObjectRef: &authenticationv1.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: name, UID: pod.UID}}}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		credentials.token = token
	}
	nodeMeta, err := structpb.NewStruct(
		map[string]any{"POD_NAMESPACE": namespace, "POD_NAME": name, "NODE_NAME": node, "POD_UID": string(pod.UID)},
	)
	if err != nil {
		return err
	}
	client, err := fakeclient.Open(
		ctx,
		fakeclient.Config{
			Target: r.CA,
			Node: &core.Node{
				Id:       "ztunnel~" + pod.Status.PodIP + "~" + name + "." + namespace + "~" + namespace + ".svc.cluster.local",
				Metadata: nodeMeta,
			},
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    roots,
				ServerName: cmp.Or(r.CAServerName, "agentiod."+r.System+".svc"),
			},
			Token: func(context.Context) (string, error) { return credentials.token.Status.Token, nil },
		},
	)
	if err != nil {
		return err
	}
	defer closeResource(client)
	stats.mu.Lock()
	stats.Connected++
	stats.Resources[i] = map[string]map[string]string{}
	stats.mu.Unlock()
	defer func() {
		stats.mu.Lock()
		stats.Connected--
		delete(stats.Resources, i)
		stats.mu.Unlock()
	}()
	for _, typ := range []string{model.AddressType, model.SandboxType, model.TrafficPolicyType} {
		if err := client.Subscribe(typ, "*"); err != nil {
			return err
		}
	}
	if r.ReadDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(r.ReadDelay):
		}
	}
	for {
		response, err := client.Recv()
		if err != nil {
			return err
		}
		credentials.receivedResponse = true
		stats.mu.Lock()
		types := stats.Resources[i]
		resources := types[response.TypeUrl]
		if resources == nil {
			resources = map[string]string{}
			types[response.TypeUrl] = resources
		}
		for _, resource := range response.Resources {
			resources[resource.Name] = resource.Version
		}
		for _, name := range response.RemovedResources {
			delete(resources, name)
		}
		stats.Responses++
		stats.mu.Unlock()
		if r.Acknowledge {
			if err := client.ACK(response); err != nil {
				return err
			}
		}
	}
}
