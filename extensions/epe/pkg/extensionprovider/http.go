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

package extensionprovider

import (
	"context"
	"io"
	"net/http"
)

type httpEndpoint struct {
	url string
}

// Do supplies the HTTP transport for a named HTTPCallout provider. The callout
// client handles the request and response protocol. Redirects are not followed.
// The provider timeout covers body reads.
// The caller must close the response body.
func (r *Registry) Do(
	ctx context.Context,
	provider, method string,
	headers http.Header,
	body io.Reader,
) (*http.Response, error) {
	p, err := r.find(provider, false)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, p.httpCallout.url, body)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		req.Header = headers.Clone()
	}
	return p.client.Do(req)
}
