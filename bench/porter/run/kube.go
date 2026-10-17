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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

func newRunner(c config) (*runner, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = c.Kubeconfig
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: c.Context}).
		ClientConfig()
	if err != nil {
		return nil, err
	}
	cfg.UserAgent = "agentio-porter-bench"
	cfg.Timeout = 30 * time.Second
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &runner{cfg: c, kube: client, rest: cfg}, nil
}

func (r *runner) exec(ctx context.Context, pod string, args []string, stdout, stderr io.Writer) error {
	req := r.kube.CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(pod).
		Namespace(r.cfg.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{Container: "load", Command: args, Stdout: true, Stderr: true}, scheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(r.rest, "POST", req.URL())
	if err != nil {
		return err
	}
	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: stdout, Stderr: stderr})
}

func (r *runner) get(ctx context.Context, url, pod string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var out, stderr bytes.Buffer
	err := r.exec(ctx, pod, []string{"/bench", "get", url}, &out, &stderr)
	if err != nil {
		return nil, fmt.Errorf("GET %s via %s: %w: %s", url, pod, err, stderr.String())
	}
	return out.Bytes(), nil
}

func tlsData(controlPlanes int) (map[string][]byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	start := time.Now().Add(-time.Minute)
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "porter-perf-ca"},
		NotBefore:             start,
		NotAfter:              start.Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ads"},
		NotBefore:             start,
		NotAfter:              ca.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"ads"},
	}
	for i := range controlPlanes {
		leaf.DNSNames = append(leaf.DNSNames, fmt.Sprintf("ads-%d", i))
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	token := make([]byte, 24)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return map[string][]byte{
		"ca.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		"server.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem":    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"token":      []byte(hex.EncodeToString(token)),
	}, nil
}

func (r *runner) create(ctx context.Context) error {
	ns, err := r.kube.CoreV1().
		Namespaces().
		Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: r.cfg.Namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "porter-perf"}}}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	r.namespaceUID = ns.UID
	data, err := tlsData(r.cfg.ControlPlanes)
	if err != nil {
		return err
	}
	if _, err = r.kube.CoreV1().
		Secrets(r.cfg.Namespace).
		Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "benchmark-tls"}, Data: data}, metav1.CreateOptions{}); err != nil {
		return err
	}
	names := []string{"ads", "watchers"}
	for i := range r.cfg.ControlPlanes {
		names = append(names, fmt.Sprintf("ads-%d", i))
	}
	for _, name := range names {
		selector := map[string]string{"instance": name}
		port := int32(8080)
		if name == "ads" {
			selector = map[string]string{"app": "ads"}
		}
		if name == "watchers" {
			port = 8081
		}
		ports := []corev1.ServicePort{{Name: "http", Port: port}}
		if strings.HasPrefix(name, "ads") {
			ports = append(ports, corev1.ServicePort{Name: "grpc", Port: 15012})
		}
		_, err := r.kube.CoreV1().Services(r.cfg.Namespace).Create(ctx, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       corev1.ServiceSpec{Selector: selector, Ports: ports},
		}, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *runner) container(
	name string,
	args []string,
	cpu int,
	memory, image, executable string,
	env map[string]string,
) corev1.Container {
	if image == "" {
		image = r.cfg.BenchImage
	}
	values := []corev1.EnvVar{{Name: "GOMAXPROCS", Value: strconv.Itoa(cpu)}}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, corev1.EnvVar{Name: key, Value: env[key]})
	}
	return corev1.Container{
		Name:            name,
		Image:           image,
		ImagePullPolicy: corev1.PullPolicy(r.cfg.PullPolicy),
		Command:         []string{executable},
		Args:            args,
		Env:             values,
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("250m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse(strconv.Itoa(cpu)),
				corev1.ResourceMemory: resource.MustParse(memory),
			},
		},
		VolumeMounts: []corev1.VolumeMount{{Name: "tls", MountPath: "/tls", ReadOnly: true}},
	}
}

func (r *runner) pod(
	ctx context.Context,
	name string,
	containers []corev1.Container,
	shared bool,
	labels map[string]string,
) error {
	pod, err := r.kube.CoreV1().Pods(r.cfg.Namespace).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: new(false),
			ShareProcessNamespace:        new(shared),
			Containers:                   containers,
			Volumes: []corev1.Volume{{
				Name:         "tls",
				VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{SecretName: "benchmark-tls"}},
			}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	return wait.PollUntilContextTimeout(
		ctx,
		time.Second,
		180*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			current, err := r.kube.CoreV1().Pods(r.cfg.Namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			if current.UID != pod.UID {
				return false, fmt.Errorf("pod %s was replaced", name)
			}
			if current.Status.Phase == corev1.PodFailed {
				return false, fmt.Errorf("pod %s failed: %s", name, current.Status.Message)
			}
			for _, condition := range current.Status.Conditions {
				if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
					return true, nil
				}
			}
			return false, nil
		},
	)
}

func (r *runner) deletePod(ctx context.Context, name string) error {
	pods := r.kube.CoreV1().Pods(r.cfg.Namespace)
	pod, err := pods.Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err = pods.Delete(
		ctx,
		name,
		metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &pod.UID}},
	); err != nil &&
		!apierrors.IsNotFound(err) {
		return err
	}
	return wait.PollUntilContextTimeout(
		ctx,
		time.Second,
		180*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			_, err := pods.Get(ctx, name, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		},
	)
}

func (r *runner) deleteNamespace(ctx context.Context) error {
	if r.namespaceUID == types.UID("") {
		return nil
	}
	err := r.kube.CoreV1().
		Namespaces().
		Delete(ctx, r.cfg.Namespace, metav1.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &r.namespaceUID}})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return wait.PollUntilContextTimeout(
		ctx,
		time.Second,
		180*time.Second,
		true,
		func(ctx context.Context) (bool, error) {
			_, err := r.kube.CoreV1().Namespaces().Get(ctx, r.cfg.Namespace, metav1.GetOptions{})
			if apierrors.IsNotFound(err) {
				return true, nil
			}
			return false, err
		},
	)
}

func (r *runner) logs(ctx context.Context, prefix string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pods, err := r.kube.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var failures []error
	for _, pod := range pods.Items {
		for _, container := range pod.Spec.Containers {
			if container.Name == "load" {
				continue
			}
			data, err := r.kube.CoreV1().
				Pods(r.cfg.Namespace).
				GetLogs(pod.Name, &corev1.PodLogOptions{Container: container.Name, Timestamps: true}).
				DoRaw(ctx)
			if err == nil {
				err = r.write(prefix+"."+pod.Name+"."+container.Name+".log", data)
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("logs %s/%s: %w", pod.Name, container.Name, err))
			}
		}
	}
	return errors.Join(failures...)
}
