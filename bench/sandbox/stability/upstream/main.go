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

// Test-only upstream, with no product imports.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/fault") && injectFault(w) {
			return
		}
		w.Header().Set("X-Stability-Upstream", os.Getenv("HOSTNAME"))
		switch r.URL.Path {
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			for i := range 20 {
				if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
					return
				}
				w.(http.Flusher).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(500 * time.Millisecond):
				}
			}
		case "/download":
			size := 1 << 20
			w.Header().Set("Content-Length", strconv.Itoa(size))
			block := strings.Repeat("x", 16384)
			for i := 0; i < size/len(block); i++ {
				if _, err := io.WriteString(w, block); err != nil {
					return
				}
			}
		case "/upload":
			n, err := io.Copy(io.Discard, http.MaxBytesReader(w, r.Body, 8<<20))
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			if _, err := fmt.Fprintf(w, "uploaded:%d", n); err != nil {
				log.Print(err)
			}
		default:
			sni := ""
			if r.TLS != nil {
				sni = r.TLS.ServerName
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).
				Encode(map[string]any{"marker": "STABILITY-UPSTREAM", "tls_sni": sni, "host": r.Host, "path": r.URL.Path, "proto": r.Proto, "headers": r.Header, "backend": os.Getenv("HOSTNAME")}); err != nil {
				log.Print(err)
			}
		}
	})
	return mux
}

func main() {
	mux := handler()
	srv := &http.Server{
		Addr:              ":8443",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		HTTP2:             &http.HTTP2Config{CountError: func(kind string) { log.Printf("http2_error=%s", kind) }},
	}
	go func() { log.Fatal(http.ListenAndServe(":8080", mux)) }()
	log.Fatal(srv.ListenAndServeTLS("/tls/tls.crt", "/tls/tls.key"))
}

func injectFault(w http.ResponseWriter) bool {
	mode, err := os.ReadFile("/fault/mode")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return true
	}
	switch strings.TrimSpace(string(mode)) {
	case "reset":
		h, ok := w.(http.Hijacker)
		if ok {
			c, _, e := h.Hijack()
			if e == nil {
				if err := c.Close(); err != nil {
					log.Print(err)
				}
			}
			return true
		}
		panic(http.ErrAbortHandler)
	case "slow":
		time.Sleep(3 * time.Second)
	case "tls-ok", "normal":
	default:
		http.Error(w, "invalid fixture fault mode", 500)
		return true
	}
	return false
}
