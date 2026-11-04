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

package model

import (
	"fmt"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"

	configv1 "github.com/openkruise/agentio/api/config/v1"
)

// ExtProcEnabled reports whether the provider selects a Service or a DNS endpoint.
func ExtProcEnabled(provider *configv1.ExtProcProvider) bool {
	return provider.GetServiceRef() != nil || provider.GetService() != ""
}

// ValidateExtProcServiceRef validates the Kubernetes Service reference and its port.
func ValidateExtProcServiceRef(provider *configv1.ExtProcProvider) error {
	ref := provider.GetServiceRef()
	if ref == nil {
		return nil
	}
	if errs := validation.IsDNS1123Label(ref.GetNamespace()); len(errs) > 0 {
		return fmt.Errorf("serviceRef.namespace: %s", strings.Join(errs, "; "))
	}
	if errs := validation.IsDNS1123Label(ref.GetName()); len(errs) > 0 {
		return fmt.Errorf("serviceRef.name: %s", strings.Join(errs, "; "))
	}
	if provider.GetPort() > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, or 0 for the default 9002")
	}
	return nil
}

// ValidateAdditionalExtProcs checks the named processor list at the configuration boundary.
func ValidateAdditionalExtProcs(providers []*configv1.ExtProcProvider) error {
	names := make(map[string]bool, len(providers))
	for i, provider := range providers {
		field := fmt.Sprintf("additionalExtProcs[%d]", i)
		name := provider.GetName()
		if errs := validation.IsDNS1123Label(name); len(errs) != 0 {
			return fmt.Errorf("%s.name: %s", field, strings.Join(errs, "; "))
		}
		if names[name] {
			return fmt.Errorf("%s.name: duplicate name %q", field, name)
		}
		names[name] = true
		if err := ValidateExtProcServiceRef(provider); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
		if provider.GetServiceRef() == nil && (strings.TrimSpace(provider.GetService()) == "" ||
			strings.TrimSpace(provider.GetService()) != provider.GetService()) {
			return fmt.Errorf("%s.service must be non-empty without surrounding whitespace", field)
		}
		if provider.GetPort() > 65535 {
			return fmt.Errorf("%s.port must be between 1 and 65535, or 0 for the default 9002", field)
		}
		if value := provider.GetMessageTimeout(); value != "" {
			duration, err := time.ParseDuration(value)
			if err != nil || duration <= 0 {
				return fmt.Errorf("%s.messageTimeout must be a positive duration", field)
			}
		}
		for _, mode := range []*configv1.ProcessingModeOptions{provider.GetRequest(), provider.GetResponse()} {
			if _, ok := configv1.HeaderSendMode_name[int32(mode.GetHeaderMode())]; !ok {
				return fmt.Errorf("%s: invalid header mode %d", field, mode.GetHeaderMode())
			}
		}
		if err := ValidateExtProcTLS(provider.GetTls()); err != nil {
			return fmt.Errorf("%s: %w", field, err)
		}
	}
	return nil
}
