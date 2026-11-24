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

package mitm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"istio.io/istio/pkg/ptr"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/kube/kclient"
	"github.com/openkruise/agentio/pkg/security/internal/casecret"
	"github.com/openkruise/agentio/pkg/security/pki"
)

const (
	mitmCACertKey = "ca.crt"
	mitmCAKeyKey  = "ca.key"
	mitmBundleKey = "root-cert.pem"
)

var mitmCAKeys = casecret.Keys{
	Certificate:           mitmCACertKey,
	PrivateKey:            mitmCAKeyKey,
	Bundle:                mitmBundleKey,
	AllowCertificateChain: true,
}

type MITMSignMode string

const (
	MITMSignModeSecret   MITMSignMode = "SECRET"
	MITMSignModeSelfSign MITMSignMode = "SELF_SIGN"
)

type MITMSignerOptions struct {
	Mode                  MITMSignMode
	Namespace             string // Agentio system namespace.
	SecretNamespace       string // Defaults to Namespace.
	SecretName            string
	RootLifetime          time.Duration
	RootRenewBefore       time.Duration
	RotationCheckInterval time.Duration
	LeafExpiryMargin      time.Duration
	CRLOrigin             string
	ConfigMaps            krt.Collection[*corev1.ConfigMap]
	KrtOptions            krt.OptionsBuilder
}

type caState struct {
	ca        pki.SigningCA
	secretUID types.UID
}

func (caState) ResourceName() string {
	return "ca-state"
}

func (c caState) Equals(other caState) bool {
	return c.secretUID == other.secretUID && c.ca.Equal(other.ca)
}

// MITMSigner signs on-demand DNS certificates from CA material whose ownership
// is selected explicitly by MITMSignMode. SECRET is strictly read-only;
// SELF_SIGN persists and renews a control-plane-owned CA in the configured
// Secret using Kubernetes optimistic concurrency.
type MITMSigner struct {
	client      kube.Client
	options     MITMSignerOptions
	caSingleton krt.Singleton[caState]
	signerState krt.StaticSingleton[SignerState]
	trustBundle krt.StaticSingleton[TrustBundle]
	crls        *crlPublisher
	// unavailable is a fail-closed gate for the small interval in which a
	// direct authoritative read has observed deletion but the KRT collection
	// has not delivered its removal yet. Valid CA material is still installed
	// only by caSingleton.
	unavailable atomic.Bool
	// unavailableUID prevents an already-queued KRT event for the deleted
	// Secret from reopening the gate. Kubernetes assigns a new UID when the
	// fixed-name Secret is recreated.
	availabilityMu sync.Mutex
	unavailableUID types.UID
	reconcileNow   chan struct{}
}

var _ DomainCertificateSigner = (*MITMSigner)(nil)

func NewMITMSigner(
	ctx context.Context,
	client kube.Client,
	options MITMSignerOptions,
) (*MITMSigner, error) {
	if ctx == nil || client == nil {
		return nil, fmt.Errorf("context and Kubernetes client are required")
	}
	applyMITMSignerDefaults(&options)
	if options.KrtOptions.Stop() == nil {
		options.KrtOptions = krt.NewOptionsBuilder(ctx.Done(), "", nil)
	}
	if err := validateMITMSignerOptions(options); err != nil {
		return nil, err
	}

	signer := &MITMSigner{
		client:       client,
		options:      options,
		reconcileNow: make(chan struct{}, 1),
	}
	if options.CRLOrigin != "" {
		publisher, err := newCRLPublisher(options, client)
		if err != nil {
			return nil, err
		}
		signer.crls = publisher
	}
	signer.signerState = krt.NewStatic[SignerState](nil, true,
		options.KrtOptions.WithName("MITM_Signer_State")...)
	signer.trustBundle = krt.NewStatic[TrustBundle](nil, true, options.KrtOptions.WithName("MITM_Trust_Bundle")...)
	signer.caSingleton = newDelayedCASecretSingleton(client, options)
	signer.caSingleton.Register(func(event krt.Event[caState]) {
		if event.New == nil {
			signer.setUnavailable("")
			if options.Mode == MITMSignModeSelfSign {
				signer.requestReconcile()
			}
			return
		}
		signer.acceptAvailable(*event.New)
	})
	if options.Mode == MITMSignModeSelfSign {
		go signer.runSelfSignMaintenance(ctx)
	}
	if signer.crls != nil && signer.crls.managed {
		go signer.crls.run(ctx, signer.caSingleton)
	}
	return signer, nil
}

func applyMITMSignerDefaults(options *MITMSignerOptions) {
	if options.SecretNamespace == "" {
		options.SecretNamespace = options.Namespace
	}
	if options.Mode == "" {
		options.Mode = MITMSignModeSelfSign
	}
	if options.SecretName == "" {
		options.SecretName = "agentio-mitm-ca"
	}
	if options.RootLifetime <= 0 {
		options.RootLifetime = 10 * 365 * 24 * time.Hour
	}
	if options.RootRenewBefore <= 0 {
		options.RootRenewBefore = 365 * 24 * time.Hour
	}
	if options.RotationCheckInterval <= 0 {
		options.RotationCheckInterval = time.Hour
	}
	if options.LeafExpiryMargin <= 0 {
		options.LeafExpiryMargin = time.Hour
	}
}

func validateMITMSignerOptions(options MITMSignerOptions) error {
	if options.Namespace == "" || options.SecretName == "" {
		return fmt.Errorf("MITM signer system namespace and CA Secret name are required")
	}
	if options.LeafExpiryMargin <= 0 {
		return fmt.Errorf("MITM signer leaf expiry margin must be positive")
	}
	switch options.Mode {
	case MITMSignModeSecret:
		return nil
	case MITMSignModeSelfSign:
		if options.RootLifetime <= 0 || options.RootRenewBefore <= 0 ||
			options.RootRenewBefore >= options.RootLifetime || options.RotationCheckInterval <= 0 {
			return fmt.Errorf("invalid self-signed MITM CA rotation durations")
		}
		return nil
	default:
		return fmt.Errorf("unsupported MITM sign mode %q", options.Mode)
	}
}

func newDelayedCASecretSingleton(
	client kube.Client,
	options MITMSignerOptions,
) krt.Singleton[caState] {
	callback := func() krt.Singleton[caState] {
		return newCASecretSingleton(client, options)
	}
	// Retry non-authoritative read errors so delayed RBAC is not mistaken for a missing Secret.
	waitForReadPermission := func(ctx context.Context) bool {
		_, err := client.Kube().CoreV1().Secrets(options.SecretNamespace).Get(ctx, options.SecretName, metav1.GetOptions{})
		return err == nil || apierrors.IsNotFound(err)
	}
	syncer := krt.NewPollingSyncer("MITM_Secret", waitForReadPermission, 30*time.Second)
	return krt.NewDelayedSingleton(syncer, callback, options.KrtOptions.Stop())
}

func newCASecretSingleton(
	client kube.Client,
	options MITMSignerOptions,
) krt.Singleton[caState] {
	secretClient := kclient.NewFiltered[*corev1.Secret](client, kclient.Filter{
		Namespace:     options.SecretNamespace,
		FieldSelector: "metadata.name=" + options.SecretName,
	})
	secrets := krt.WrapClient(secretClient, options.KrtOptions.WithName("MITM_Secret_"+options.SecretName)...)
	secretClient.Start(options.KrtOptions.Stop())

	secretKey := types.NamespacedName{Namespace: options.SecretNamespace, Name: options.SecretName}.String()
	return krt.NewSingleton(func(ctx krt.HandlerContext) *caState {
		secret := ptr.Flatten(krt.FetchOne(ctx, secrets, krt.FilterKey(secretKey)))
		if secret == nil {
			log.Warn("MITM CA Secret not found", "namespace", options.SecretNamespace, "secret", options.SecretName)
			return nil
		}
		ca, err := pki.ParseSigningCABundle(secret.Data[mitmCACertKey], secret.Data[mitmCAKeyKey], time.Now())
		if err != nil {
			log.Error("parse MITM CA Secret", "namespace", options.SecretNamespace, "secret", options.SecretName, "error", err)
			return nil
		}
		return &caState{ca: ca, secretUID: secret.UID}
	}, options.KrtOptions.WithName("MITM_CA")...)
}

func (s *MITMSigner) State() krt.Singleton[SignerState] {
	return s.signerState
}

func (s *MITMSigner) currentRevision() string {
	state := s.signerState.Get()
	if state == nil {
		return ""
	}
	return state.Revision
}

func (s *MITMSigner) SignDNS(ctx context.Context, domain string, lifetime time.Duration) (SignedCertificate, error) {
	if err := ctx.Err(); err != nil {
		return SignedCertificate{}, fmt.Errorf("sign MITM certificate for %s: %w", domain, err)
	}
	generation := s.caSingleton.Get()
	state := s.signerState.Get()
	if s.unavailable.Load() || generation == nil || state == nil || state.Revision != generation.ca.Revision() {
		return SignedCertificate{}, fmt.Errorf("MITM CA is not loaded")
	}
	ca := generation.ca
	now := time.Now()
	var distributionPoints []string
	if s.crls != nil {
		horizon, err := s.crls.issuanceHorizon(ca, now)
		if err != nil {
			return SignedCertificate{}, fmt.Errorf("MITM CRL unavailable: %w", err)
		}
		distributionPoints = []string{s.crls.origin + "/crl/" + ca.CRLKeyID() + ".crl"}
		lifetime = min(lifetime, horizon.Sub(now))
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SignedCertificate{}, fmt.Errorf("generate MITM leaf key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return SignedCertificate{}, fmt.Errorf("encode MITM leaf key: %w", err)
	}
	issued, err := ca.Sign(ctx, &key.PublicKey, pki.LeafOptions{
		CommonName:            domain,
		DNSNames:              []string{domain},
		CurrentTime:           now,
		CRLDistributionPoints: distributionPoints,
		Lifetime:              lifetime,
		IssuerExpiryMargin:    s.options.LeafExpiryMargin,
		MinimumLifetime:       time.Minute,
		Server:                true,
	})
	if err != nil {
		return SignedCertificate{}, fmt.Errorf("sign MITM certificate for %s: %w", domain, err)
	}
	return SignedCertificate{
		CertificateChain: pki.AppendCertificateChain(issued.CertificatePEM, ca.BundlePEM()),
		PrivateKey:       pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		NotAfter:         issued.NotAfter,
		SignedAt:         issued.IssuedAt,
		SignerRevision:   ca.Revision(),
	}, nil
}

func (s *MITMSigner) requestReconcile() {
	select {
	case s.reconcileNow <- struct{}{}:
	default:
	}
}

func (s *MITMSigner) setUnavailable(uid types.UID) {
	s.availabilityMu.Lock()
	if uid != "" {
		s.unavailableUID = uid
	}
	changed := s.unavailable.CompareAndSwap(false, true)
	if changed {
		s.signerState.Set(nil)
		s.trustBundle.Set(nil)
	}
	s.availabilityMu.Unlock()
}

func (s *MITMSigner) acceptAvailable(state caState) bool {
	uid, revision := state.secretUID, state.ca.Revision()
	s.availabilityMu.Lock()
	defer s.availabilityMu.Unlock()
	if current := s.caSingleton.Get(); current == nil || !current.Equals(state) {
		return false
	}
	if s.unavailableUID != "" && uid == s.unavailableUID {
		return false
	}
	s.unavailableUID = ""
	s.unavailable.Store(false)
	current := s.signerState.Get()
	if current == nil || current.Revision != revision {
		s.signerState.Set(&SignerState{Revision: revision})
	}
	bundle := TrustBundle{PEM: string(state.ca.BundlePEM()), Revision: revision}
	if current := s.trustBundle.Get(); current == nil || !current.Equals(bundle) {
		s.trustBundle.Set(&bundle)
	}
	return true
}

func (s *MITMSigner) currentSecretUID() types.UID {
	state := s.caSingleton.Get()
	if state == nil {
		return ""
	}
	return state.secretUID
}

func (s *MITMSigner) runSelfSignMaintenance(ctx context.Context) {
	retryTicker := time.NewTicker(30 * time.Second)
	defer retryTicker.Stop()
	rotationTicker := time.NewTicker(s.options.RotationCheckInterval)
	defer rotationTicker.Stop()

	var lastErrorLog time.Time
	run := func(operation string, action func(context.Context) error) {
		if err := action(ctx); err != nil && time.Since(lastErrorLog) >= 30*time.Second {
			log.Error("MITM signer operation failed", "operation", operation, "mode", s.options.Mode, "error", err)
			lastErrorLog = time.Now()
		}
	}
	run("initialize", s.reconcileSelfSignedCA)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.reconcileNow:
			run("reconcile", s.reconcileSelfSignedCA)
		case <-retryTicker.C:
			if s.currentRevision() == "" {
				run("reconcile", s.reconcileSelfSignedCA)
			}
		case <-rotationTicker.C:
			run("renew", s.renewSelfSignedCA)
		}
	}
}

func (s *MITMSigner) reconcileSelfSignedCA(ctx context.Context) error {
	if s.currentRevision() != "" {
		return nil
	}
	_, err := s.client.Kube().CoreV1().Secrets(s.options.SecretNamespace).Get(ctx, s.options.SecretName, metav1.GetOptions{})
	if !apierrors.IsNotFound(err) {
		if err != nil {
			return fmt.Errorf("read MITM CA Secret %s/%s: %w", s.options.SecretNamespace, s.options.SecretName, err)
		}
		// An existing Secret can contain a root that expired while this
		// process was stopped. Recover it without waiting for the rotation tick.
		return s.renewSelfSignedCA(ctx)
	}
	s.setUnavailable(s.currentSecretUID())
	_, err = casecret.LoadOrCreate(ctx, s.client.Kube(), s.options.SecretNamespace, s.options.SecretName,
		mitmCAKeys, "Agentio MITM Root CA", s.options.RootLifetime)
	if err != nil {
		return fmt.Errorf("create MITM CA Secret %s/%s: %w", s.options.SecretNamespace, s.options.SecretName, err)
	}
	return nil
}

func (s *MITMSigner) renewSelfSignedCA(ctx context.Context) error {
	err := casecret.Rotate(ctx, s.client.Kube(), s.options.SecretNamespace, s.options.SecretName,
		mitmCAKeys, s.options.RootLifetime, s.options.RootRenewBefore, time.Now())
	if apierrors.IsNotFound(err) {
		// A direct authoritative read can win the race with the KRT delete event.
		// Fail closed immediately; the collection remains the only path that can
		// install the recreated CA.
		s.setUnavailable(s.currentSecretUID())
		s.requestReconcile()
		return fmt.Errorf("MITM CA Secret %s/%s was deleted", s.options.SecretNamespace, s.options.SecretName)
	}
	if err != nil && !apierrors.IsConflict(err) {
		return err
	}
	return nil
}

// TrustBundles exposes accepted public CA generations, including staged trust anchors.
func (s *MITMSigner) TrustBundles() krt.Singleton[TrustBundle] { return s.trustBundle }
