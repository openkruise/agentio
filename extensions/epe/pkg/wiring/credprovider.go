// Copyright 2026 The Kruise Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wiring

import (
	"fmt"
	"strings"

	"istio.io/istio/pkg/env"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/extensionprovider"
)

// Default-provider environment settings are resolved at the composition root.
// Provider clients receive explicit values and never read process configuration.
var (
	identityProviderURL = env.Register("IDENTITY_PROVIDER_URL", "",
		"Base URL of the credential provider API. The client fails every credential lookup while it is unset").Get()

	// insecureSkipVerify disables verification of the credential provider's
	// server certificate. It is orthogonal to the client identity, which is
	// still supplied by the configured certificate source.
	insecureSkipVerify = env.Register("CREDENTIAL_PROVIDER_INSECURE_SKIP_VERIFY", false,
		"Skip verification of the credential provider's server certificate. The client certificate, when one is "+
			"configured, is still presented. Intended for self-signed providers on trusted networks; any on-path "+
			"attacker can then read the bearer token and forge the credential response").Get()
)

// Source names for CREDENTIAL_PROVIDER_MTLS_SOURCE.
const (
	credProviderSourceNone   = "none"
	credProviderSourceSecret = "secret"
)

const defaultCredentialProviderName = "agentio-default-credential-provider"

// Where the credential provider's mTLS material comes from. This is the
// default configuration's concern; resolution happens after all layers merge.
var (
	credProviderMTLSSource = env.Register("CREDENTIAL_PROVIDER_MTLS_SOURCE", credProviderSourceNone,
		"Where the credential provider's mTLS material comes from: \"secret\" (the Secret named by "+
			"CREDENTIAL_PROVIDER_SECRET_NAMESPACE and _NAME), or \"none\". Exactly one "+
			"source is used; there is no fallback between them. Material that is absent "+
			"or unusable means no client certificate is presented and the provider's "+
			"certificate is verified against the system trust store").Get()

	// Namespace and name of the Secret holding the credential provider's mTLS
	// material. Both must be set for the Secret source to join the chain at all.
	credProviderSecretNamespace = env.Register("CREDENTIAL_PROVIDER_SECRET_NAMESPACE", "",
		"Namespace of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
	credProviderSecretName = env.Register("CREDENTIAL_PROVIDER_SECRET_NAME", "",
		"Name of the Secret holding the credential provider mTLS certificate, key, and CA").Get()
)

// DefaultEPEConfig converts environment settings into the lowest configuration
// layer. It neither resolves certificate material nor creates provider clients.
func DefaultEPEConfig() (*configv1.EPEConfig, error) {
	cfg := &configv1.EPEConfig{}
	if identityProviderURL == "" {
		return cfg, nil
	}
	provider := &configv1.CredentialProvider{
		Url:     identityProviderURL,
		Timeout: "10s",
	}
	if strings.HasPrefix(identityProviderURL, "https://") {
		tlsConfig := &configv1.ClientTLS{InsecureSkipVerify: insecureSkipVerify, Optional: true}
		switch credProviderMTLSSource {
		case credProviderSourceNone:
		case credProviderSourceSecret:
			if credProviderSecretNamespace == "" || credProviderSecretName == "" {
				return nil, fmt.Errorf("CREDENTIAL_PROVIDER_MTLS_SOURCE=secret requires a namespace and a name")
			}
			tlsConfig.CaSource = &configv1.ClientTLS_CaSecretRef{
				CaSecretRef: &configv1.TargetReference{
					Name:      credProviderSecretName,
					Namespace: credProviderSecretNamespace,
				},
			}
			tlsConfig.ClientCertificateSource = &configv1.ClientTLS_ClientCertificateSecretRef{
				ClientCertificateSecretRef: &configv1.TargetReference{
					Name:      credProviderSecretName,
					Namespace: credProviderSecretNamespace,
				},
			}
		default:
			return nil, fmt.Errorf(
				"CREDENTIAL_PROVIDER_MTLS_SOURCE=%q is not one of secret or none",
				credProviderMTLSSource,
			)
		}
		provider.Tls = tlsConfig
	}
	cfg.ExtensionProviders = []*configv1.ExtensionProvider{{
		Name:     defaultCredentialProviderName,
		Provider: &configv1.ExtensionProvider_CredentialProvider{CredentialProvider: provider},
	}}
	cfg.DefaultProviders = &configv1.DefaultExtensionProviders{CredentialProvider: defaultCredentialProviderName}
	return cfg, extensionprovider.Validate(cfg)
}
