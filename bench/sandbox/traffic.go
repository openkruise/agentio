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
	"bufio"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	securityapi "istio.io/api/security/v1alpha1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/openkruise/agentio/bench/load"
)

func (r *runner) issue(
	ctx context.Context,
	ca securityapi.IstioCertificateServiceClient,
	i int,
) (tls.Certificate, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ns := r.namespace(i)
	pod, err := r.kube.CoreV1().Pods(ns).Get(ctx, resourceName(i), metav1.GetOptions{})
	if err != nil {
		return tls.Certificate{}, err
	}
	token, err := r.kube.CoreV1().
		ServiceAccounts(ns).
		CreateToken(ctx, "sandbox", &authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{Audiences: []string{"agentio-ca"}, BoundObjectRef: &authenticationv1.BoundObjectReference{APIVersion: "v1", Kind: "Pod", Name: pod.Name, UID: pod.UID}}}, metav1.CreateOptions{})
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	response, err := ca.CreateCertificate(
		metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token.Status.Token),
		&securityapi.IstioCertificateRequest{
			Csr:              string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})),
			ValidityDuration: 3600,
		},
	)
	if err != nil {
		return tls.Certificate{}, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(
		[]byte(strings.Join(response.CertChain, "\n")),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}),
	)
}

func gatewayTLS(roots *x509.CertPool, cert tls.Certificate, principal string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"h2"},
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			intermediates := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				intermediates.AddCert(c)
			}
			if _, err := cs.PeerCertificates[0].Verify(
				x509.VerifyOptions{
					Roots:         roots,
					Intermediates: intermediates,
					KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				},
			); err != nil {
				return err
			}
			for _, uri := range cs.PeerCertificates[0].URIs {
				if uri.String() == principal {
					return nil
				}
			}
			return fmt.Errorf("gateway certificate does not identify %s", principal)
		},
	}
}

func (r *runner) traffic(ctx context.Context) (any, error) {
	if r.Active < 1 || r.Active > r.Count || r.CA == "" || r.Gateway == "" || r.Target == "" {
		return nil, fmt.Errorf("valid active count, CA, gateway and target are required")
	}
	if r.TrafficRateFile != "" && !r.ReuseConnections {
		return nil, fmt.Errorf("traffic-rate-file requires reuse-connections")
	}
	conn, roots, err := r.credentials(ctx)
	if err != nil {
		return nil, err
	}
	defer closeResource(conn)
	ca := securityapi.NewIstioCertificateServiceClient(conn)
	certs := make([]tls.Certificate, r.Active)
	var transports []*http2.Transport
	if r.ReuseConnections {
		transports = make([]*http2.Transport, r.Active)
		defer func() {
			for _, transport := range transports {
				if transport != nil {
					transport.CloseIdleConnections()
				}
			}
		}()
	}
	prep := time.Now()
	prepare := *r
	prepare.Count = r.Active
	prepare.Offset = 0
	if err := prepare.parallel(ctx, func(ctx context.Context, j int) error {
		var e error
		certs[j], e = r.issue(ctx, ca, r.Offset+j*r.Count/r.Active)
		if e == nil && r.ReuseConnections {
			transports[j] = r.gatewayTransport(gatewayTLS(roots, certs[j], "spiffe://cluster.local/ns/"+r.System+"/sa/egress-gateway"))
		}
		return e
	}); err != nil {
		return nil, err
	}
	prepSeconds := time.Since(prep).Seconds()
	fmt.Fprintf(os.Stderr, "TRAFFIC_READY identities=%d preparation_seconds=%.3f\n", r.Active, prepSeconds)
	if r.StartFile != "" {
		if err := wait.PollUntilContextCancel(ctx, 100*time.Millisecond, true, func(context.Context) (bool, error) {
			_, err := os.Stat(r.StartFile)
			if os.IsNotExist(err) {
				return false, nil
			}
			return err == nil, err
		}); err != nil {
			return nil, err
		}
	}
	targets := strings.Split(r.Target, ",")
	runBatch := func(rate, requests int, duration time.Duration) (load.Result, error) {
		return load.Run(
			ctx,
			load.Config{
				Requests:    requests,
				Identities:  r.Active,
				Concurrency: r.Workers,
				Rate:        rate,
				Duration:    duration,
			},
			func(ctx context.Context, j int) error {
				requestCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				defer cancel()
				i := r.Offset + j*r.Count/r.Active
				probe := *r
				probe.Target = targets[j%len(targets)]
				if r.ReuseConnections {
					return probe.requestOn(requestCtx, transports[j].RoundTrip, i)
				}
				return probe.request(
					requestCtx,
					gatewayTLS(roots, certs[j], "spiffe://cluster.local/ns/"+r.System+"/sa/egress-gateway"),
					i,
				)
			},
		)
	}
	if r.TrafficRateFile != "" {
		return r.continuousTraffic(ctx, runBatch)
	}
	result, err := runBatch(r.Rate, r.Requests, r.Duration)
	if err == nil && (result.Errors > 0 || result.Operations != r.Requests) {
		err = fmt.Errorf(
			"traffic completed %d/%d with %d errors: %s",
			result.Operations,
			r.Requests,
			result.Errors,
			result.FirstError,
		)
	}
	return map[string]any{
		"load":                            result,
		"certificate_preparation_seconds": prepSeconds,
		"targets":                         targets,
		"gateway":                         r.Gateway,
	}, err
}

func (r *runner) continuousTraffic(ctx context.Context, runBatch func(int, int, time.Duration) (load.Result, error)) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, r.Duration)
	defer cancel()
	batches, operations, failures := 0, 0, 0
	for {
		data, err := os.ReadFile(r.TrafficRateFile)
		if err != nil {
			return nil, err
		}
		rate, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || rate < -1 {
			return nil, fmt.Errorf("invalid traffic QPS %q", data)
		}
		if rate == -1 {
			return map[string]int{"batches": batches, "operations": operations, "errors": failures}, nil
		}
		if rate == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		result, err := runBatch(rate, rate*10, 30*time.Second)
		batches++
		operations += result.Operations
		failures += result.Errors
		event := map[string]any{"action": "traffic-progress", "time": time.Now(), "result": result, "planned_requests": rate * 10}
		if err != nil {
			event["error"] = err.Error()
		}
		if encodeErr := json.NewEncoder(os.Stdout).Encode(event); encodeErr != nil {
			return nil, encodeErr
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// An overloaded batch is evidence; keep the clients alive for the next rate step.
		if err != nil && !errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
	}
}

func (r *runner) gatewayTransport(config *tls.Config) *http2.Transport {
	return &http2.Transport{
		TLSClientConfig: config,
		DialTLSContext: func(ctx context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
			dialer := tls.Dialer{Config: config, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
			return dialer.DialContext(ctx, "tcp", r.Gateway)
		},
	}
}

func (r *runner) request(ctx context.Context, config *tls.Config, i int) error {
	dialer := tls.Dialer{Config: config, NetDialer: &net.Dialer{Timeout: 5 * time.Second}}
	conn, err := dialer.DialContext(ctx, "tcp", r.Gateway)
	if err != nil {
		return err
	}
	defer closeResource(conn)
	transport := &http2.Transport{}
	client, err := transport.NewClientConn(conn)
	if err != nil {
		return err
	}
	return r.requestOn(ctx, client.RoundTrip, i)
}

func (r *runner) requestOn(ctx context.Context, roundTrip func(*http.Request) (*http.Response, error), i int) error {
	reader, writer := io.Pipe()
	defer closeResource(reader)
	defer closeResource(writer)
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Scheme: "https", Host: r.Target},
		Host:   r.Target,
		Header: http.Header{"X-Agentio-Sandbox-Uid": []string{"kruise:" + resourceName(i)}},
		Body:   reader,
	}
	response, err := roundTrip(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer closeResource(response.Body)
	if response.StatusCode != http.StatusOK {
		return connectError{response.StatusCode}
	}
	writeDone := make(chan error, 1)
	go func() {
		_, e := fmt.Fprintf(writer, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", r.Path, r.Target)
		writeDone <- e
	}()
	inner, err := http.ReadResponse(bufio.NewReader(response.Body), nil)
	if err != nil {
		return err
	}
	defer closeResource(inner.Body)
	body, err := io.ReadAll(io.LimitReader(inner.Body, 4096))
	if err != nil {
		return err
	}
	if err = <-writeDone; err != nil {
		return err
	}
	if r.PolicyKind == "traffic" && r.ExpectedStatus == http.StatusForbidden && inner.StatusCode == r.ExpectedStatus {
		var reply struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if err := json.Unmarshal(body, &reply); err != nil {
			return err
		}
		if reply.Code == "epe_egress_denied" && reply.Message == "Outbound destination is denied by policy." {
			return nil
		}
	}
	if inner.StatusCode != r.ExpectedStatus || string(body) != r.ExpectedBody {
		return fmt.Errorf("backend status=%d body=%q", inner.StatusCode, body)
	}
	return nil
}

func backend() error {
	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.WriteString(w, "sandbox-scale-ok\n"); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}),
	}
	return server.ListenAndServe()
}

func closeResource(c io.Closer) {
	if err := c.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "close resource:", err)
	}
}

func (r *runner) credentials(ctx context.Context) (*grpc.ClientConn, *x509.CertPool, error) {
	cm, err := r.kube.CoreV1().ConfigMaps(r.System).Get(ctx, "sandbox-scale-ca-root-cert", metav1.GetOptions{})
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(cm.Data["root-cert.pem"])) {
		return nil, nil, fmt.Errorf("empty CA roots")
	}
	conn, err := grpc.NewClient(
		r.CA,
		grpc.WithTransportCredentials(
			credentials.NewTLS(
				&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: cmp.Or(r.CAServerName, "agentiod."+r.System+".svc")},
			),
		),
	)
	if err != nil {
		return nil, nil, err
	}

	return conn, roots, nil
}

type connectError struct{ status int }

func (e connectError) Error() string { return fmt.Sprintf("CONNECT status %d", e.status) }
