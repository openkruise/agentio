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

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	securityapi "istio.io/api/security/v1alpha1"

	"github.com/openkruise/agentio/pkg/krt"
	"github.com/openkruise/agentio/pkg/kube"
	"github.com/openkruise/agentio/pkg/model"
	"github.com/openkruise/agentio/pkg/security/attestation"
	"github.com/openkruise/agentio/pkg/security/internal/casecret"
	"github.com/openkruise/agentio/pkg/security/pki"
)

const (
	caCertKey   = "ca-cert.pem"
	caKeyKey    = "ca-key.pem"
	caBundleKey = "root-cert.pem"
)

var workloadCAKeys = casecret.Keys{Certificate: caCertKey, PrivateKey: caKeyKey, Bundle: caBundleKey}

type AuthorityOptions struct {
	TrustDomain   string
	ClusterDomain string
	Namespace     string
	SecretName    string
	ConfigMapName string
	ServiceName   string
	// LeafLifetime is the validity period of the certificates this authority
	// issues: workload certificates served over the CA API, and the xDS server's
	// own serving certificate.
	LeafLifetime time.Duration
	// LeafRenewBefore is how long before expiry the server's own certificate is
	// re-issued. Defaults to a third of LeafLifetime.
	LeafRenewBefore       time.Duration
	LeaseName             string
	RootLifetime          time.Duration
	RenewBefore           time.Duration
	RotationCheckInterval time.Duration
	KrtOptions            krt.OptionsBuilder
}

type Authority struct {
	securityapi.UnimplementedIstioCertificateServiceServer
	authenticator   attestation.Authenticator
	ca              pki.SigningCA
	rootPEM         []byte
	leafLifetime    time.Duration
	leafRenewBefore time.Duration
	serverCert      tls.Certificate
	client          kube.Client
	ctx             context.Context
	options         AuthorityOptions
	serverNames     []string
	caSingleton     krt.Singleton[caState]
	trustBundles    krt.StaticSingleton[TrustBundle]
	caInstallMu     sync.Mutex

	authorizerMu                sync.RWMutex
	delegatedIdentityAuthorizer attestation.DelegatedIdentityAuthorizer

	mu sync.RWMutex
}

// applyAuthorityDefaults fills in unset option defaults.
func applyAuthorityDefaults(options *AuthorityOptions) {
	if options.SecretName == "" {
		options.SecretName = "agentio-ca-secret"
	}
	if options.ConfigMapName == "" {
		options.ConfigMapName = "agentio-ca-certs"
	}
	if options.ServiceName == "" {
		options.ServiceName = "agentiod"
	}
	if options.ClusterDomain == "" {
		options.ClusterDomain = "cluster.local"
	}
	if options.LeafLifetime <= 0 {
		options.LeafLifetime = 24 * time.Hour
	}
	if options.LeafRenewBefore <= 0 || options.LeafRenewBefore >= options.LeafLifetime {
		options.LeafRenewBefore = options.LeafLifetime / 3
	}
	if options.LeaseName == "" {
		options.LeaseName = "agentiod-ca-leader"
	}
	if options.RootLifetime <= 0 {
		options.RootLifetime = 10 * 365 * 24 * time.Hour
	}
	if options.RenewBefore <= 0 {
		options.RenewBefore = 365 * 24 * time.Hour
	}
	if options.RotationCheckInterval <= 0 {
		options.RotationCheckInterval = time.Hour
	}
}

// LoadOrCreateAuthority loads or initializes the configured CA and trust domain.
func LoadOrCreateAuthority(
	ctx context.Context,
	client kube.Client,
	authenticator attestation.Authenticator,
	options AuthorityOptions,
) (*Authority, error) {
	if client == nil || authenticator == nil {
		return nil, fmt.Errorf("kubernetes client and authenticator are required")
	}
	if _, err := model.NewPrincipal(options.TrustDomain, "workload"); err != nil {
		return nil, fmt.Errorf("CA trust domain: %w", err)
	}
	applyAuthorityDefaults(&options)
	if options.KrtOptions.Stop() == nil {
		options.KrtOptions = krt.NewOptionsBuilder(ctx.Done(), "", nil)
	}
	secret, err := casecret.LoadOrCreate(ctx, client.Kube(), options.Namespace, options.SecretName,
		workloadCAKeys, "Agentio Root CA", options.RootLifetime)
	if err != nil {
		return nil, err
	}
	if _, err := parseCASecret(secret, time.Now()); err != nil {
		return nil, fmt.Errorf("parse CA secret %s/%s: %w", options.Namespace, options.SecretName, err)
	}
	authority := &Authority{
		authenticator:   authenticator,
		leafLifetime:    options.LeafLifetime,
		leafRenewBefore: options.LeafRenewBefore,
		client:          client,
		ctx:             ctx,
		options:         options,
	}
	serverNames := []string{
		options.ServiceName,
		options.ServiceName + "." + options.Namespace,
		options.ServiceName + "." + options.Namespace + ".svc",
		options.ServiceName + "." + options.Namespace + ".svc." + options.ClusterDomain,
		"localhost",
	}
	authority.serverNames = serverNames
	authority.trustBundles = krt.NewStatic[TrustBundle](nil, true,
		options.KrtOptions.WithName("Workload_Trust_Bundle")...)
	authority.caSingleton = newCASecretSingleton(client, options)
	registration := authority.caSingleton.Register(authority.handleCAEvent)
	keepRegistration := false
	defer func() {
		if !keepRegistration {
			registration.UnregisterHandler()
		}
	}()
	if !registration.WaitUntilSynced(ctx.Done()) {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("sync workload CA Secret %s/%s: %w", options.Namespace, options.SecretName, err)
		}
		return nil, fmt.Errorf(
			"workload CA Secret collection %s/%s stopped before sync",
			options.Namespace,
			options.SecretName,
		)
	}
	authority.mu.RLock()
	caAvailable := authority.ca.Available()
	rootPEM := append([]byte(nil), authority.rootPEM...)
	serverCertificateReady := authority.serverCert.Leaf != nil
	authority.mu.RUnlock()
	if !caAvailable || !serverCertificateReady {
		return nil, fmt.Errorf(
			"workload CA Secret %s/%s has no valid signing state",
			options.Namespace,
			options.SecretName,
		)
	}
	if err := publishRoot(ctx, client.Kube(), options.Namespace, options.ConfigMapName, rootPEM); err != nil {
		return nil, err
	}
	keepRegistration = true

	go authority.runServerCertificateMaintenance(ctx)
	go authority.runLeaderElection(ctx)
	return authority, nil
}

// UseDelegatedIdentityAuthorizer installs the policy for explicit targets and instance requests.
func (a *Authority) UseDelegatedIdentityAuthorizer(authorizer attestation.DelegatedIdentityAuthorizer) {
	a.authorizerMu.Lock()
	a.delegatedIdentityAuthorizer = authorizer
	a.authorizerMu.Unlock()
}

func (a *Authority) delegatedAuthorizer() attestation.DelegatedIdentityAuthorizer {
	a.authorizerMu.RLock()
	defer a.authorizerMu.RUnlock()
	return a.delegatedIdentityAuthorizer
}

func (a *Authority) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			a.mu.RLock()
			defer a.mu.RUnlock()
			certificate := a.serverCert
			return &certificate, nil
		},
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
	}
}

func (a *Authority) RootPEM() []byte {
	bundle := a.trustBundles.Get()
	if bundle == nil {
		return nil
	}
	return []byte(bundle.PEM)
}

func (a *Authority) TrustBundles() krt.Singleton[TrustBundle] {
	return a.trustBundles
}

// CreateCertificate authorizes the requested workload target before signing its CSR key.
func (a *Authority) CreateCertificate(
	ctx context.Context,
	request *securityapi.IstioCertificateRequest,
) (*securityapi.IstioCertificateResponse, error) {
	caller, err := a.authenticator.Authenticate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	csr, err := parseCertificateRequest(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	target, err := a.certificateTarget(ctx, caller, request, csr)
	if err != nil {
		// Keep the response opaque: the detailed reason names nodes and identities,
		// which would give an unauthorized caller a topology probe.
		log.Warn("certificate identity selection failed", "attestation", caller.AttestedBy, "error", err)
		return nil, status.Error(codes.Unauthenticated, "request authenticate failure")
	}
	spiffeURI, err := url.Parse(target.Principal.String())
	if err != nil {
		return nil, status.Error(codes.Internal, "encode workload identity")
	}
	var extensions []pkix.Extension
	if target.Workload != (attestation.WorkloadIdentity{}) {
		extension, err := workloadIdentityExtension(target.Workload)
		if err != nil {
			return nil, status.Error(codes.Internal, "encode workload identity")
		}
		extensions = append(extensions, extension)
	}
	lifetime := a.leafLifetime
	if requested := time.Duration(request.GetValidityDuration()) * time.Second; requested > 0 && requested < lifetime {
		lifetime = requested
	}
	a.mu.RLock()
	ca, rootPEM := a.ca, append([]byte(nil), a.rootPEM...)
	a.mu.RUnlock()
	if !ca.Available() {
		return nil, status.Error(codes.Internal, "CA is not loaded")
	}
	issued, err := ca.Sign(ctx, csr.PublicKey, pki.LeafOptions{
		URIs:            []*url.URL{spiffeURI},
		ExtraExtensions: extensions,
		Lifetime:        lifetime,
		Client:          true,
		Server:          true,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &securityapi.IstioCertificateResponse{
		CertChain: orderedCertificateChain(issued.CertificatePEM, nil, rootPEM),
	}, nil
}

// issueServerCertificate signs a serving certificate valid for lifetime from now.
func issueServerCertificate(ca pki.SigningCA, rootPEM []byte, names []string,
	lifetime time.Duration, now time.Time,
) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate server key: %w", err)
	}
	issued, err := ca.Sign(context.Background(), &key.PublicKey, pki.LeafOptions{
		CommonName:  names[0],
		DNSNames:    names,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		CurrentTime: now,
		Lifetime:    lifetime,
		Server:      true,
	})
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign server certificate: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("marshal server key: %w", err)
	}
	certificate, err := tls.X509KeyPair(
		pki.AppendCertificateChain(issued.CertificatePEM, rootPEM),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("load server certificate: %w", err)
	}
	certificate.Leaf = issued.Certificate
	return certificate, nil
}

func orderedCertificateChain(leaf []byte, intermediates [][]byte, roots []byte) []string {
	chain := make([]string, 0, 2+len(intermediates))
	if len(leaf) != 0 {
		chain = append(chain, string(leaf))
	}
	for _, intermediate := range intermediates {
		if len(intermediate) != 0 {
			chain = append(chain, string(intermediate))
		}
	}
	if len(roots) != 0 {
		chain = append(chain, string(roots))
	}
	return chain
}
