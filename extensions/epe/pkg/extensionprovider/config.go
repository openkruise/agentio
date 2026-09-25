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
// Package extensionprovider owns EPE's dynamically configured external services.
package extensionprovider

import (
	"fmt"
	"net/url"
	"time"

	"google.golang.org/protobuf/proto"
	"k8s.io/apimachinery/pkg/util/validation"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/pkg/config"
)

// ApplyConfig merges providers by name while preserving the shared decoder's
// omission, null, and explicit-empty semantics. Same-name entries replace the
// whole provider, so changing a type or TLS source cannot inherit stale fields.
func ApplyConfig(content string, base *configv1.EPEConfig) (*configv1.EPEConfig, error) {
	next, err := config.Apply(content, base)
	if err != nil || len(next.GetExtensionProviders()) == 0 {
		return next, err
	}
	// The decoder has already inherited the list if omitted/null, or replaced
	// it if supplied. Merging an inherited list back by name is a no-op.
	providers := proto.Clone(base).(*configv1.EPEConfig).ExtensionProviders
	positions := make(map[string]int, len(providers))
	for i, p := range providers {
		positions[p.GetName()] = i
	}
	seen := make(map[string]bool, len(next.ExtensionProviders))
	for _, p := range next.ExtensionProviders {
		name := p.GetName()
		if seen[name] {
			return nil, fmt.Errorf("duplicate extension provider %q", name)
		}
		seen[name] = true
		if i, found := positions[name]; found {
			providers[i] = p
		} else {
			providers = append(providers, p)
		}
	}
	next.ExtensionProviders = providers
	return next, nil
}

// Validate checks structure only; dependency availability is a runtime failure.
func Validate(cfg *configv1.EPEConfig) error {
	names := map[string]*configv1.ExtensionProvider{}
	for _, p := range cfg.GetExtensionProviders() {
		if p == nil || len(validation.IsDNS1123Subdomain(p.GetName())) != 0 {
			return fmt.Errorf("invalid extension provider name %q", p.GetName())
		}
		if names[p.Name] != nil {
			return fmt.Errorf("duplicate extension provider %q", p.Name)
		}
		names[p.Name] = p
		endpoint, timeout, tlsCfg := settings(p)
		u, err := url.Parse(endpoint)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
			u.Fragment != "" {
			return fmt.Errorf("provider %q requires an absolute HTTP(S) URL without userinfo or fragment", p.Name)
		}
		if _, err := duration(timeout, 500*time.Millisecond); err != nil {
			return fmt.Errorf("provider %q timeout: %w", p.Name, err)
		}
		if err := validateProviderTLS(p.Name, u.Scheme, tlsCfg); err != nil {
			return err
		}
	}
	// A missing or wrong-type default, like an explicit rule reference, remains
	// unavailable at runtime. Deleting a provider must not retain its old client.
	return nil
}

func duration(raw string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", raw)
	}
	return d, nil
}

func settings(p *configv1.ExtensionProvider) (string, string, *configv1.ClientTLS) {
	if h := p.GetHttpCallout(); h != nil {
		return h.Url, h.Timeout, h.Tls
	}
	if c := p.GetCredentialProvider(); c != nil {
		return c.Url, c.Timeout, c.Tls
	}
	return "", "", nil
}

func resourceKey(defaultNamespace, namespace, name string) string {
	if namespace == "" {
		namespace = defaultNamespace
	}
	return namespace + "/" + name
}

func certificateFiles(t *configv1.ClientTLS) []string {
	var paths []string
	files := t.GetClientCertificateFiles()
	for _, path := range []string{t.GetCaCertificateFile(), files.GetCertificateFile(), files.GetPrivateKeyFile()} {
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func validateProviderTLS(name, scheme string, tlsCfg *configv1.ClientTLS) error {
	if tlsCfg == nil {
		return nil
	}

	if scheme != "https" {
		return fmt.Errorf("provider %q TLS requires https", name)
	}
	if tlsCfg.ServerName != "" && len(tlsCfg.PeerSpiffeIds) != 0 {
		return fmt.Errorf("provider %q serverName and peerSpiffeIDs are mutually exclusive", name)
	}
	if _, err := certs.NewSPIFFEAllowList(tlsCfg.PeerSpiffeIds...); err != nil {
		return fmt.Errorf("provider %q: %w", name, err)
	}
	if tlsCfg.InsecureSkipVerify && len(tlsCfg.PeerSpiffeIds) != 0 {
		return fmt.Errorf("provider %q insecureSkipVerify and peerSpiffeIDs are mutually exclusive", name)
	}
	switch source := tlsCfg.GetCaSource().(type) {
	case *configv1.ClientTLS_CaSecretRef:
		ref := source.CaSecretRef
		if err := validateReference(name, "Secret", ref.GetName(), ref.GetNamespace()); err != nil {
			return err
		}
	case *configv1.ClientTLS_CaConfigMapRef:
		ref := source.CaConfigMapRef
		if err := validateReference(name, "ConfigMap", ref.GetName(), ref.GetNamespace()); err != nil {
			return err
		}
	case *configv1.ClientTLS_CaCertificateFile:
		if source.CaCertificateFile == "" {
			return fmt.Errorf("provider %q requires a non-empty caCertificateFile", name)
		}
	}
	switch source := tlsCfg.GetClientCertificateSource().(type) {
	case *configv1.ClientTLS_ClientCertificateSecretRef:
		ref := source.ClientCertificateSecretRef
		return validateReference(name, "Secret", ref.GetName(), ref.GetNamespace())
	case *configv1.ClientTLS_ClientCertificateFiles:
		files := source.ClientCertificateFiles
		if files.GetCertificateFile() == "" || files.GetPrivateKeyFile() == "" {
			return fmt.Errorf(
				"provider %q clientCertificateFiles requires both certificateFile and privateKeyFile", name)
		}
	}
	return nil
}

func validateReference(provider, kind, name, namespace string) error {
	if len(validation.IsDNS1123Subdomain(name)) != 0 {
		return fmt.Errorf("provider %q has invalid %s name %q", provider, kind, name)
	}
	if namespace != "" && len(validation.IsDNS1123Label(namespace)) != 0 {
		return fmt.Errorf("provider %q has invalid %s namespace %q", provider, kind, namespace)
	}
	return nil
}
