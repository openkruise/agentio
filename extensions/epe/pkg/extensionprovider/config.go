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

	"k8s.io/apimachinery/pkg/util/validation"

	configv1 "github.com/openkruise/agentio/api/config/v1"
	"github.com/openkruise/agentio/extensions/epe/pkg/certs"
	"github.com/openkruise/agentio/extensions/epe/pkg/httpclient"
)

// Validate checks structure only; dependency availability is a runtime failure.
func Validate(cfg *configv1.AgentioConfig) error {
	names := map[string]*configv1.ExtensionProvider{}
	for _, p := range cfg.GetExtensionProviders() {
		if p == nil || len(validation.IsDNS1123Subdomain(p.GetName())) != 0 {
			return fmt.Errorf("invalid extension provider name %q", p.GetName())
		}
		if names[p.Name] != nil {
			return fmt.Errorf("duplicate extension provider %q", p.Name)
		}
		names[p.Name] = p
		if h := p.GetHttpCallout(); h != nil {
			if _, err := calloutOptions(h); err != nil {
				return fmt.Errorf("provider %q: %w", p.Name, err)
			}
		}
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

func calloutOptions(h *configv1.HTTPCalloutProvider) (httpclient.CalloutOptions, error) {
	o := httpclient.CalloutOptions{
		Options:              httpclient.DefaultOptions(),
		Protocol:             h.Protocol.String(),
		MaxConcurrentStreams: 32,
	}
	switch h.Protocol {
	case configv1.HTTPCalloutProvider_AUTO, configv1.HTTPCalloutProvider_HTTP1:
	case configv1.HTTPCalloutProvider_HTTP2:
		o.MaxConnsPerHost = 32
		o.MaxIdleConnsPerHost = 8
	default:
		return o, fmt.Errorf("unknown HTTPCallout protocol %d", h.Protocol)
	}
	if h.Protocol == configv1.HTTPCalloutProvider_HTTP1 && h.Http2 != nil {
		return o, fmt.Errorf("http2 parameters cannot be used with HTTP1")
	}
	if h.Http2 != nil && h.Http2.MaxConcurrentStreams != nil {
		v := h.Http2.GetMaxConcurrentStreams()
		if v == 0 || v > 2147483647 {
			return o, fmt.Errorf("maxConcurrentStreams must be between 1 and 2147483647")
		}
		o.MaxConcurrentStreams = int(v)
	}
	if pool := h.ConnectionPool; pool != nil {
		if pool.MaxConnections != nil {
			if *pool.MaxConnections == 0 || *pool.MaxConnections > 2147483647 {
				return o, fmt.Errorf("maxConnections must be between 1 and 2147483647")
			}
			o.MaxConnsPerHost = int(*pool.MaxConnections)
		}
		o.MaxIdleConnsPerHost = min(o.MaxIdleConnsPerHost, o.MaxConnsPerHost)
		if pool.MaxIdleConnections != nil {
			if *pool.MaxIdleConnections > uint32(o.MaxConnsPerHost) {
				return o, fmt.Errorf("maxIdleConnections must not exceed maxConnections")
			}
			o.MaxIdleConnsPerHost = int(*pool.MaxIdleConnections)
		}
		var err error
		o.IdleConnTimeout, err = duration(pool.IdleTimeout, o.IdleConnTimeout)
		if err != nil {
			return o, fmt.Errorf("idleTimeout: %w", err)
		}
	}
	return o, nil
}
