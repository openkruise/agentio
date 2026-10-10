# Wasm runtime fixture

`header.wat` is an SDK-free Proxy-Wasm ABI 0.2.1 test plugin. It adds the `x-agentio-wasm: wasm-v1` response header. `header.wasm` is its compiled form. The integration test changes the equal-length marker to `wasm-v2` and delivers another ECDS version through the gateway-agent ADS relay; it asserts the actual response header changes without restarting Envoy.

Regenerate using a local WAT compiler, e.g.:

```sh
wat2wasm header.wat -o header.wasm
```

Alternatively, Python's `wasmtime.wat2wasm` produces the checked-in module. No compiler, SDK, or download client is included in the gateway image. Run the real runtime checks inside the final image with:

```sh
AGENTIO_TEST_ENVOY_BINARY=/usr/local/bin/envoy AGENTIO_TEST_NETWORK_FAULTS=1 \
  /tests/gatewayagent.test -test.v -test.run='TestCommunityEnvoyWasmECDS|TestADSDetectsSilentBlackhole'
```
