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

package dns

import (
	"context"
	mdns "github.com/miekg/dns"
	"net"
	"testing"
	"time"
)

// Test the exported query path with real DNS packets, including zero TTL in
// different positions so zero cannot be mistaken for an uninitialized minimum.
func TestTransportAnswerTTL(t *testing.T) {
	for _, tt := range []struct {
		name    string
		records []string
		want    time.Duration
	}{
		{"address minimum", []string{"api.example. 45 IN A 192.0.2.1", "api.example. 20 IN A 192.0.2.2"}, 20 * time.Second},
		{"zero first", []string{"api.example. 0 IN A 192.0.2.1", "api.example. 20 IN A 192.0.2.2"}, 0},
		{"zero last", []string{"api.example. 20 IN A 192.0.2.1", "api.example. 0 IN A 192.0.2.2"}, 0},
		{"cname minimum", []string{"api.example. 5 IN CNAME target.example.", "target.example. 60 IN A 192.0.2.1"}, 5 * time.Second},
		{"zero cname", []string{"api.example. 0 IN CNAME target.example.", "target.example. 60 IN A 192.0.2.1"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var answers []mdns.RR
			for _, text := range tt.records {
				record, err := mdns.NewRR(text)
				if err != nil {
					t.Fatal(err)
				}
				answers = append(answers, record)
			}
			packet, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server := &mdns.Server{PacketConn: packet, Handler: mdns.HandlerFunc(func(w mdns.ResponseWriter, request *mdns.Msg) {
				response := new(mdns.Msg)
				response.SetReply(request)
				response.Answer = answers
				_ = w.WriteMsg(response)
			})}
			go func() { _ = server.ActivateAndServe() }()
			t.Cleanup(func() { _ = server.Shutdown() })
			result, err := NewTransport([]string{packet.LocalAddr().String()}, time.Second).Lookup(context.Background(), "api.example", IPv4Only)
			if err != nil || len(result.Addresses) == 0 || result.TTL != tt.want {
				t.Fatalf("got %+v, %v; want TTL %v", result, err, tt.want)
			}
		})
	}
}
