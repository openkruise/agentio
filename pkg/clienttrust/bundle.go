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

package clienttrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Package is the public JSON contract of upstream trust-manager CA package images.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Bundle  string `json:"bundle"`
}

// ParsePackage validates package metadata and certificate contents.
func ParsePackage(data []byte) (Package, error) {
	var p Package
	if err := json.Unmarshal(data, &p); err != nil {
		return p, err
	}
	if p.Name == "" || p.Version == "" || p.Bundle == "" {
		return p, fmt.Errorf("trust package requires name, version and bundle")
	}
	if _, _, err := Merge([][]byte{[]byte(p.Bundle)}, time.Now()); err != nil {
		return p, err
	}
	return p, nil
}

// Merge canonicalizes a union of public CA certificates, never silently accepting partial sources.
func Merge(sources [][]byte, now time.Time) ([]byte, []string, error) {
	certs := map[string][]byte{}
	var warnings []string
	for index, source := range sources {
		rest := source
		count := 0
		for len(bytes.TrimSpace(rest)) > 0 {
			rest = bytes.TrimSpace(rest)
			// Debian/OpenSSL bundles commonly carry comment lines between certificates.
			if rest[0] == '#' {
				_, rest, _ = bytes.Cut(rest, []byte("\n"))
				continue
			}
			if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, nil, fmt.Errorf("CA source %d contains non-certificate data", index)
			}
			block, tail := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
				return nil, nil, fmt.Errorf("invalid PEM in CA source %d", index)
			}
			// pem.Decode can skip malformed blocks to find a later valid block.
			// Require it to consume exactly the certificate at the start of rest.
			consumed := rest[:len(rest)-len(tail)]
			if bytes.Count(consumed, []byte("-----BEGIN ")) != 1 {
				return nil, nil, fmt.Errorf("invalid PEM in CA source %d", index)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid certificate in CA source %d: %w", index, err)
			}
			if !cert.BasicConstraintsValid || !cert.IsCA {
				return nil, nil, fmt.Errorf("non-CA certificate in source %d", index)
			}
			digest := Digest(cert.Raw)
			if _, ok := certs[digest]; !ok {
				certs[digest] = cert.Raw
				if cert.NotAfter.Before(now.Add(30 * 24 * time.Hour)) {
					warnings = append(warnings, fmt.Sprintf("CA %s expires %s", digest, cert.NotAfter.UTC().Format(time.RFC3339)))
				}
			}
			count++
			rest = tail
		}
		if count == 0 {
			return nil, nil, fmt.Errorf("CA source %d is empty", index)
		}
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no CA certificates")
	}
	keys := make([]string, 0, len(certs))
	for key := range certs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	sort.Strings(warnings)
	var result bytes.Buffer
	for _, key := range keys {
		if err := pem.Encode(&result, &pem.Block{Type: "CERTIFICATE", Bytes: certs[key]}); err != nil {
			return nil, nil, err
		}
	}
	// ConfigMaps have a 1 MiB payload limit; leave room for metadata and diagnostics.
	if result.Len() > 900*1024 {
		return nil, nil, fmt.Errorf("CA bundle exceeds 900 KiB limit")
	}
	return result.Bytes(), warnings, nil
}

// Digest returns the SHA-256 identifier of canonical bundle contents.
func Digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// PackageVersion identifies the upstream package and its release.
func PackageVersion(p Package) string { return strings.TrimSpace(p.Name + "/" + p.Version) }
