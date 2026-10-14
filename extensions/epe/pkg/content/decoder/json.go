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
package decoder

import (
	"encoding/json"

	capturestatus "github.com/openkruise/agentio/extensions/epe/pkg/content/status"
)

func decodeJSON(raw []byte) (any, capturestatus.Code) {
	var body any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, capturestatus.InvalidJSON
	}
	return body, capturestatus.Complete
}
