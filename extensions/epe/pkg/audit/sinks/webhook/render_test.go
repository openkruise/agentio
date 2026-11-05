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
package webhook

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"text/template"

	"github.com/openkruise/agentio/extensions/epe/pkg/audit"
	"github.com/openkruise/agentio/extensions/epe/pkg/inputs"
)

// --- RenderURL ---

func TestRenderURL_NilWebhook(t *testing.T) {
	ca := &audit.Audit{}
	_, err := RenderURL(ca, &audit.Scope{})
	if err == nil {
		t.Fatal("expected error for nil webhook")
	}
	if !strings.Contains(err.Error(), "nil webhook") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRenderURL_ValidHTTP(t *testing.T) {
	tests := []struct {
		name    string
		tmpl    string
		ctx     *audit.Scope
		wantURL string
	}{
		{
			name:    "static http url",
			tmpl:    "http://webhook.example.com/audit",
			ctx:     &audit.Scope{},
			wantURL: "http://webhook.example.com/audit",
		},
		{
			name:    "static https url",
			tmpl:    "https://secure.example.com/audit",
			ctx:     &audit.Scope{},
			wantURL: "https://secure.example.com/audit",
		},
		{
			name: "url with template variables",
			tmpl: "http://hook.example.com/{{.Profile.Name}}/{{.Rule.Name}}",
			ctx: &audit.Scope{
				Scope: *inputs.NewScope(inputs.Request{}, inputs.Workload{},
					inputs.Profile{Name: "p1"}, inputs.Rule{Name: "r1"}, nil),
			},
			wantURL: "http://hook.example.com/p1/r1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := &audit.Audit{
				Webhook: &audit.Webhook{
					URL: template.Must(template.New("url").Parse(tc.tmpl)),
				},
			}
			got, err := RenderURL(ca, tc.ctx)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantURL {
				t.Errorf("want %q, got %q", tc.wantURL, got)
			}
		})
	}
}

func TestRenderURL_InvalidScheme(t *testing.T) {
	tests := []struct {
		name string
		tmpl string
	}{
		{name: "ftp scheme", tmpl: "ftp://example.com/audit"},
		{name: "empty scheme", tmpl: "//example.com/audit"},
		{name: "mailto scheme", tmpl: "mailto:admin@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := &audit.Audit{
				Webhook: &audit.Webhook{
					URL: template.Must(template.New("url").Parse(tc.tmpl)),
				},
			}
			_, err := RenderURL(ca, &audit.Scope{})
			if err == nil {
				t.Fatal("expected error for invalid scheme")
			}
			if !strings.Contains(err.Error(), "invalid url scheme") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRenderURL_BadTemplate(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			URL: template.Must(template.New("url").Parse("{{.Missing.Field}}")),
		},
	}
	_, err := RenderURL(ca, &audit.Scope{})
	// missingkey=zero means it won't error on missing keys; just check it doesn't panic.
	_ = err
}

// --- RenderHeaders ---

func TestRenderHeaders_NilWebhook(t *testing.T) {
	ca := &audit.Audit{}
	_, err := RenderHeaders(ca, &audit.Scope{})
	if err == nil {
		t.Fatal("expected error for nil webhook")
	}
}

func TestRenderHeaders_EmptyHeaders(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{},
	}
	headers, err := RenderHeaders(ca, &audit.Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(headers) != 0 {
		t.Errorf("expected 0 headers, got %d", len(headers))
	}
}

func TestRenderHeaders_RendersTemplates(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			Headers: []audit.Header{
				{
					Name:  "X-Profile",
					Value: template.Must(template.New("h1").Parse("{{.Profile.Name}}")),
				},
				{
					Name:  "X-Result",
					Value: template.Must(template.New("h2").Parse("{{.Result}}")),
				},
			},
		},
	}
	ctx := &audit.Scope{
		Scope:  *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{Name: "strict"}, inputs.Rule{}, nil),
		Result: "blocked",
	}
	headers, err := RenderHeaders(ca, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(headers))
	}
	if headers[0] != [2]string{"X-Profile", "strict"} {
		t.Errorf("header[0]: %v", headers[0])
	}
	if headers[1] != [2]string{"X-Result", "blocked"} {
		t.Errorf("header[1]: %v", headers[1])
	}
}

// --- RenderBody ---

func TestRenderBody_NilWebhook(t *testing.T) {
	ca := &audit.Audit{}
	_, _, err := RenderBody(ca, &audit.Scope{})
	if err == nil {
		t.Fatal("expected error for nil webhook")
	}
}

func TestRenderBody_NoBody(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			Body: audit.Body{HasBody: false},
		},
	}
	body, ct, err := RenderBody(ca, &audit.Scope{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body != nil {
		t.Errorf("expected nil body, got %q", body)
	}
	if ct != contentTypeJSON {
		t.Errorf("content type should be JSON, got %q", ct)
	}
}

func TestRenderBody_TextTemplate(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			Body: audit.Body{
				HasBody:  true,
				TextTmpl: template.Must(template.New("body").Parse("result={{.Result}}")),
			},
		},
	}
	body, ct, err := RenderBody(ca, &audit.Scope{Result: "blocked"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != contentTypeText {
		t.Errorf("content type: want text, got %q", ct)
	}
	if string(body) != "result=blocked" {
		t.Errorf("body: %q", body)
	}
}

func TestRenderBody_JSONTemplate(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			Body: audit.Body{
				HasBody: true,
				IsJSON:  true,
				JSONRoot: map[string]any{
					"result":  template.Must(template.New("leaf").Parse("{{.Result}}")),
					"profile": template.Must(template.New("leaf").Parse("{{.Profile.Name}}")),
					"static":  int64(42),
				},
			},
		},
	}
	ctx := &audit.Scope{
		Scope:  *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{Name: "p1"}, inputs.Rule{}, nil),
		Result: "blocked",
	}
	body, ct, err := RenderBody(ca, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct != contentTypeJSON {
		t.Errorf("content type: want json, got %q", ct)
	}
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid JSON body: %v", err)
	}
	if parsed["result"] != "blocked" {
		t.Errorf("result: %v", parsed["result"])
	}
	if parsed["profile"] != "p1" {
		t.Errorf("profile: %v", parsed["profile"])
	}
	if parsed["static"] != float64(42) {
		t.Errorf("static: %v", parsed["static"])
	}
}

func TestRenderBody_JSONNestedArray(t *testing.T) {
	ca := &audit.Audit{
		Webhook: &audit.Webhook{
			Body: audit.Body{
				HasBody: true,
				IsJSON:  true,
				JSONRoot: []any{
					template.Must(template.New("leaf").Parse("{{.Result}}")),
					int64(1),
					map[string]any{
						"nested": template.Must(template.New("leaf").Parse("{{.Rule.Name}}")),
					},
				},
			},
		},
	}
	ctx := &audit.Scope{
		Scope:  *inputs.NewScope(inputs.Request{}, inputs.Workload{}, inputs.Profile{}, inputs.Rule{Name: "r1"}, nil),
		Result: "blocked",
	}
	body, _, err := RenderBody(ca, ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var parsed []any
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(parsed))
	}
	if parsed[0] != "blocked" {
		t.Errorf("element[0]: %v", parsed[0])
	}
}

// --- capBody ---

func TestCapBody(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "small body unchanged", size: 10, wantErr: false},
		{name: "body at exact limit accepted untruncated", size: MaxRenderedBodyBytes, wantErr: false},
		{name: "oversized body rejected", size: MaxRenderedBodyBytes + 1000, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := make([]byte, tc.size)
			for i := range body {
				body[i] = 'A'
			}
			got, err := capBody(body)
			if tc.wantErr {
				if !errors.Is(err, errBodyTooLarge) {
					t.Fatalf("oversized body must be rejected, got err=%v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != string(body) {
				t.Errorf("body should be unchanged, got %d bytes want %d", len(got), len(body))
			}
		})
	}
}

// An oversized body used to be sliced at the byte boundary, which for JSON
// delivered syntactically invalid payloads (and could cut a multi-byte rune in
// half) while the dispatch metric still reported success. Rejecting is the
// only outcome that never puts a corrupt record on the wire.
func TestRenderBody_OversizedRejected(t *testing.T) {
	tests := []struct {
		name string
		body audit.Body
	}{
		{
			name: "json body",
			body: audit.Body{
				HasBody:  true,
				IsJSON:   true,
				JSONRoot: map[string]any{"payload": strings.Repeat("x", MaxRenderedBodyBytes+1000)},
			},
		},
		{
			name: "text body",
			body: audit.Body{
				HasBody:  true,
				TextTmpl: template.Must(template.New("b").Parse(strings.Repeat("y", MaxRenderedBodyBytes+1))),
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ca := &audit.Audit{Webhook: &audit.Webhook{Body: tc.body}}
			_, _, err := RenderBody(ca, &audit.Scope{})
			if !errors.Is(err, errBodyTooLarge) {
				t.Fatalf("want errBodyTooLarge, got %v", err)
			}
		})
	}
}
