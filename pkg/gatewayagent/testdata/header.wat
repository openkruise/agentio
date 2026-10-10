;; Copyright 2026 The Kruise Authors
;; SPDX-License-Identifier: Apache-2.0
;; Minimal Proxy-Wasm ABI 0.2.1 fixture: add a response header. No SDK/runtime dependencies.
(module
 (import "env" "proxy_add_header_map_value" (func $add (param i32 i32 i32 i32 i32) (result i32)))
 (memory (export "memory") 2)
 (data (i32.const 32) "x-agentio-wasm")
 (data (i32.const 64) "wasm-v1")
 (global $heap (mut i32) (i32.const 1024))
 (func (export "malloc") (param $size i32) (result i32)
  (local $ptr i32)
  (local.set $ptr (global.get $heap))
  (global.set $heap (i32.add (global.get $heap) (local.get $size)))
  (local.get $ptr))
 (func (export "proxy_abi_version_0_2_1"))
 (func (export "_initialize"))
 (func (export "proxy_on_context_create") (param i32 i32))
 (func (export "proxy_on_vm_start") (param i32 i32) (result i32) (i32.const 1))
 (func (export "proxy_on_configure") (param i32 i32) (result i32) (i32.const 1))
 (func (export "proxy_on_response_headers") (param i32 i32 i32) (result i32)
  ;; Map type 2 is HTTP response headers. Return 0 (continue).
  (drop (call $add (i32.const 2) (i32.const 32) (i32.const 14) (i32.const 64) (i32.const 7)))
  (i32.const 0))
)
