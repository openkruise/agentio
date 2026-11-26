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
	"crypto/sha256"
	"fmt"

	"github.com/openkruise/agentio/pkg/krt"
)

func (s *MITMSigner) withCRLRevision(cas krt.Singleton[caState]) krt.Singleton[caState] {
	return krt.NewSingleton(func(ctx krt.HandlerContext) *caState {
		ca := krt.FetchOne(ctx, cas.AsCollection())
		if ca == nil {
			return nil
		}
		state := *ca
		cm := krt.FetchOne(ctx, s.crls.maps,
			krt.FilterKey(s.options.Namespace+"/"+crlConfigMapName))
		var der []byte
		if cm != nil {
			der = (*cm).BinaryData[ca.ca.CRLKeyID()+".crl"]
		}
		// Only this issuer's CRL invalidates delivered staples. Other OCSP/CRL
		// updates in the shared ConfigMap must not trigger mass reissuance.
		state.crlRevision = fmt.Sprintf("%x", sha256.Sum256(der))
		return &state
	}, s.options.KrtOptions.WithName("MITM_OCSP_Signing_Generation")...)
}
