# Kubernetes E2E framework

This nested Go module is the repository-owned Kubernetes E2E framework. Its core packages are product-neutral and use ordinary `testing.T`, `t.Run`, `t.Cleanup`, and `go test -run`. The reusable components cover Agentio installation, namespaces, Helm releases, strict manifest plans, network prefixes, the pinned echo application, and retry-aware echo checks.

The framework never imports Istio Pilot, operator, security, istioctl, or the Istio test framework. `go test . -run TestForbiddenDependencies` enforces that boundary.

## Unit tests

Run all tests without a cluster:

```bash
make test
```

The live suites are opt-in and skip by default.

## Reusable test helpers

The framework provides the following helpers:

- `config.New(scope).YAML/Eval/File/EvalFile(...).ApplyOrFail(...)` renders and applies ordered manifest plans. Explicit plan deletion and final `ResourceScope` cleanup share the same UID/run-label ownership records.
- `echo.CallOptions.Check` is evaluated inside the call retry loop. `components/echo/check` provides `OK`, `NoError`, `Error`, `Status`, `And`, and workload-reachability checks; `Instance.CallOrFail` reports all attempts.
- `echo.Instance` owns named-port call options, Service IP, and ready-workload lookup. `network` owns host and arbitrary-prefix CIDR derivation.
- `components/agentio.Setup` installs the production `manifests/charts/agentio` chart once per suite. It pins immutable images, owns the chart CRDs and external Sandbox CRD through the suite ledger, and fails closed when a requested reusable release has a different fingerprint.
- `e2e.Context` bounds a helper operation by both its requested timeout and the enclosing Go test deadline.

Consumer suites should keep only product semantics such as policy propagation or firewall assertions. Generic YAML, Kubernetes, network, or echo-call helpers belong in their reusable package, not in an individual test file.

## Agentio product suites

The Agentio product tests are split into per-domain suites. Each suite is an independent Go package with its own `TestMain` and setup graph, installs the production chart through `components/agentio.Setup`, and uninstalls it on exit. Required deployment and firewall coverage is declared per suite and per top-level test in [`product/catalog.go`](product/catalog.go):

- `suites/trafficpolicy`: Workload TrafficPolicy matrix and an explicit native-binding check without synthetic Sandboxes and the control-plane config debug surface. The fixture contains `client`, `server`, `another-server`, and two `workload-target` Pods using the selected dataplane path. The matrix covers basic ingress and egress rules, global policy and priority, selector expressions, workload and service peers, TCP/UDP/ICMP protocol rules, policy interaction, Cartesian port/source cases, and selectorless Services with manual EndpointSlices. Policy documents use explicit `to`/`from` peers, including port-only and protocol-only restrictions.
- `suites/gateway`: egress gateway configuration, TLS termination and on-demand certificates, DFP routing, static ServiceEntries, ext-proc, and egress policies.
- `suites/clienttrust`: sidecar CA injection, container/template selection, runtime environment variables, verified Python/Node/curl HTTPS, and CA source update/retention. Runs in the sidecar-auto CI scenario; see [client trust suite](suites/clienttrust/README.md).
- `suites/agentgateway`: native static configuration, Gateway API deployment lifecycle, and shared outbound protocol/ext-proc/port-selection checks. See [agentgateway suite](suites/agentgateway/README.md) for its separate image input and scope.
- `suites/securitypolicy`: SNI SecurityProfile and GlobalSecurityProfile lifecycle against dedicated SNI fixture namespaces.
- `suites/epe`: the Egress Policy Enforcer attribute, RBAC, metrics, profile-priority, and ordinary-Workload Secret token injection contracts against Envoy. A dedicated EPE fixture also covers native Workload/TrafficPolicy xDS updates, selector rebinding, policy deletion, destination IP/port checks, DNS target pinning, and request-header authorization before body processing. `TestHTTPCalloutFixture` verifies the shared HTTPCallout service contract. `TestEPEHTTPCallout` reuses that service and covers real curl → ztunnel → Envoy → EPE → HTTP provider/origin traffic in the sidecar test environment: bidirectional header/body mutation, disclosure filters, GlobalSecurityProfile metadata-only calls, immediate denial even with Allow, provider failures under Block/Allow/Ignore, and independent request/response body limits. The fixture records actual invocations and origin traffic so a bypassed policy cannot satisfy the assertions. Direct ext_proc probes isolate EPE decisions from ztunnel enforcement; real Envoy traffic verifies body checks survive header bypass. Agentgateway EPE coverage is deferred until production peer attributes are available.

The shared product conventions (the `AGENTIO_E2E` gate, baseline ConfigMap, scenario ledgers with contamination tracking, and profile-neutral echo fixtures) live in `suites/internal/harness`. Each product fixture namespace is enrolled with `agentio.kruise.io/dataplane-mode`; ordinary Echo workloads carry only workload labels. In sidecar mode the namespace selector activates the default ztunnel injection template, while ambient mode uses CNI redirection and the node-level ztunnel. Every scenario owns its transient policies and endpoint objects through a scoped ledger: successful scenarios clean up before the next scenario, while a failed scenario retains its evidence and causes later scenarios in the same suite to skip instead of running against contaminated state.

`TestEPEOAuth2DeviceFlow` reuses the ext-proc fixture image to serve a stateful OAuth2 credential-service contract and a protected HTTPS origin. A fresh client traverses the injected proxy, Envoy gateway and production EPE using a public SecurityProfile. The test covers device authorization, repeated HTTP 400/200 pending responses, HTTP 200 `slow_down`, explicit approval, placeholder token replies, authenticated resource forwarding, form/JSON refresh, and authorization loss with a zero credential-cache TTL. The origin accepts only its runtime-generated private test token and returns no credentials; call counters prove that OAuth endpoints were intercepted and denied requests never reached the origin. Both HTTPS hops verify their test CAs. This fixture exercises Agentio's credential-service integration without an external Identity deployment, provider account or human consent.

Policy checks read workload-scoped JSON from both sidecar and ambient proxies. Native checks require a Workload TrafficPolicy reference and the corresponding cached policy body; an unrelated cached policy does not count as applied. Legacy checks identify each source policy by its ingress/egress Authorization names and verify its Workload reference or applicable global/namespace scope. Real-traffic convergence assertions then verify enforcement. Egress routing tests use `GATEWAY`/`PASSTHROUGH`, with separate TrafficPolicy tests for rejection.

All supplied suite images must be immutable digest references. The forward proxy fixture uses a framework-owned Envoy digest by default; set `AGENTIO_E2E_FORWARD_PROXY_IMAGE` only to override it. Release and manual E2E workflows build the repository's ext-proc fixture into each job's local registry when no `ext_proc_image` override or candidate archive is supplied. CI uses separate `product-e2e` and `epe-e2e` jobs generated by the same planner used locally. Product E2E has four isolated environment groups: its two `auto` groups run gateway, securitypolicy, trafficpolicy, and the profile-specific suites; its two `iptables` groups run only trafficpolicy. EPE behavior is independent of workload capture mode, so it runs once in a separate sidecar cluster with the `auto` backend. This schedules 10 suite executions, with no EPE tests duplicated in product jobs. clienttrust runs only in `sidecar-auto`. Suite setup verifies the requested `FIREWALL_BACKEND` on the injected sidecar or ambient ztunnel Pod before any product assertion runs.

Pull requests and master pushes use `agentio-e2e-presubmit.yml`. It builds agentiod, EPE, gateway-agent with community Envoy and its dynamic modules, Porter, ztunnel from the source SHA in `agentio.deps`, and the ext-proc test fixture once, transfers them to each matrix job as a same-run artifact, and publishes them only to that job's KinD-local registry. Presubmit caches the ztunnel binary by source repository, commit, architecture, runner OS, and build workflow; cache hits skip compilation but still verify the architecture and smoke-test the runtime image. Published release candidates always compile from source. CNI and proxy-init remain the immutable public images recorded in `agentio.deps`, so presubmit needs no registry credentials. Both jobs consume the same candidate image artifact and can run concurrently; failures in other product suites do not prevent EPE from running. Release calls both jobs with the same immutable candidate BOM and requires both to pass before tagging or promoting images. EPE does not require a CNI image; CNI is required only for ambient tests. For a manual EPE-only run, dispatch `agentio-e2e.yml` with `epe_only: true`; its default runs the other product suites. Concurrency groups, cluster names, ext-proc artifacts, and diagnostic artifacts are scoped separately for EPE and product runs.

A complete local run of all product suites is:

```bash
cd test/e2e
export AGENTIO_E2E_AGENTIOD_IMAGE='registry.example/agentiod@sha256:<64-hex-digest>'
export AGENTIO_E2E_CNI_IMAGE='registry.example/install-cni@sha256:<64-hex-digest>'
export AGENTIO_E2E_ZTUNNEL_IMAGE='registry.example/ztunnel@sha256:<64-hex-digest>'
export AGENTIO_E2E_PROXY_INIT_IMAGE='registry.example/proxy-init@sha256:<64-hex-digest>'
export AGENTIO_E2E_GATEWAY_IMAGE='registry.example/agentio-gateway@sha256:<64-hex-digest>'
export AGENTIO_E2E_PORTER_IMAGE='registry.example/agentio-porter@sha256:<64-hex-digest>'
export AGENTIO_E2E_EPE_IMAGE='registry.example/epe@sha256:<64-hex-digest>'
export AGENTIO_E2E_EXT_PROC_IMAGE='registry.example/ext-proc@sha256:<64-hex-digest>'
export AGENTIO_E2E_CLIENT_TRUST_IMAGE='registry.example/clienttrust@sha256:<64-hex-digest>'
# Preview all required combinations without installing anything.
go run ./cmd/product-e2e plan
# Execute all required coverage (CI splits EPE into a separate job).
go run ./cmd/product-e2e run
```

From the repository root, `make test.integration.agentio.plan` and
`make test.integration.agentio.product` call the same entry point. Pass planner
options with `AGENTIO_E2E_ARGS='--suites clienttrust'`. `AGENTIO_E2E_SUITES`
continues to accept comma- or space-separated names or `./suites/<name>` paths.
The default selects the five required Envoy product suites; agentgateway is
explicitly selected with `--suites agentgateway` and its own immutable images.

Examples from this module directory:

```bash
# Select one environment or one test; filters that select nothing are errors.
go run ./cmd/product-e2e plan --group ambient-iptables --format=json
go run ./cmd/product-e2e run --suites trafficpolicy --tests '^TestSandboxTrafficPolicyProtocol$'
# HTTPCallout real-traffic scenarios (same image/cluster prerequisites).
go run ./cmd/product-e2e run --suites epe --tests '^TestEPEHTTPCallout$'
# OAuth2 device authorization, refresh and credential-injection flow.
go run ./cmd/product-e2e run --suites epe --tests '^TestEPEOAuth2DeviceFlow$'
# Manually verify a supported backend beyond the required CI coverage.
go run ./cmd/product-e2e run --suites clienttrust --profile sidecar --backend iptables --force
```

`--profile`, `--backend`, and `--group` also read `AGENTIO_E2E_PROFILE`,
`AGENTIO_E2E_FIREWALL_BACKEND`, and `AGENTIO_E2E_GROUP`. The runner enables
firewall rules and passes the selected environment to each suite. It executes
packages serially, uses exact top-level `-run` patterns, and consumes `go test
-json` events. Missing, skipped, failed or unexpected top-level tests fail the
run, even if the Go command exits successfully. Each run saves its selected
plan alongside the normal framework artifacts. `--timeout` defaults to 30
minutes per suite. Direct `AGENTIO_E2E=1 go test ./suites/<name> -run ...` remains
available for debugging; it does not apply the coverage planner.

By default every suite creates and deletes its own Kind cluster. CI creates one cluster per environment group and borrows it across that group's suites. To use the same lifecycle locally, create a cluster and select exactly one group:

```bash
kind create cluster --name dev-e2e
E2E_CLUSTER_NAME=dev-e2e E2E_CLUSTER_REUSE=true \
  go run ./cmd/product-e2e run --group sidecar-auto
```

Each suite still installs and uninstalls its own chart release; the borrowed
cluster is never deleted. The runner stops on the first failing suite so a
retained environment is not reused by another suite. Cluster sharing does not
imply sharing an Agentio installation.

### Maintaining coverage

Add product suites to `product.Catalog`; every direct `suites/<name>` package
except the framework smoke suite must have a declaration, including opt-in
suites. Set the profiles that must run; omitted backends mean only `auto`.
Existing suites automatically include new top-level Go tests. An exact-name
`Overrides` entry inherits unspecified dimensions from the suite. The config
debug test runs only in sidecar-auto; traffic-policy protocol tests still run
in all four groups. All EPE tests run once in the sidecar environment. Pure
helper tests within suite packages inherit the same coverage; they also remain
part of `make test`.

Discovery uses `go list` build-selected test files and Go syntax parsing. It does
not execute `TestMain` or need runtime image inputs. Invalid or stale overrides,
duplicate declarations and empty selections fail before cluster setup. Run
`go test ./product ./cmd/product-e2e` to validate discovery, coverage, scheduling
and execution. CI fixture downloads use the generated group's `fixtures` list.

The gateway and securitypolicy suites need outbound DNS plus HTTP and HTTPS access to `example.com` and `example.org`. Set `-agentio.enable-firewall-rules=true` to exercise the full trafficpolicy protocol matrix; otherwise the three UDP/ICMP scenarios skip explicitly. The `-agentio.firewall-backend` value is `auto` or `iptables` and can also be set by `AGENTIO_E2E_FIREWALL_BACKEND`. The corresponding boolean environment variable is `AGENTIO_E2E_ENABLE_FIREWALL_RULES`.

The same framework cluster and retention flags described below apply. For failure investigation, add `-e2e.lifecycle.retain=on-failure`; a passing run is still cleaned, while a failing run keeps the exact owned cluster/resources and prints reconnect and deletion commands. Set `AGENTIO_E2E_REUSE=true` only when the existing Agentio installation has the exact manifest and image fingerprint requested by the run; a mismatch fails closed without patching it.

The component defaults to Helm release `agentio` and the production chart in this source tree. Override those only for an intentional integration setup with `-agentio.release-name`, `-agentio.chart-path`, `AGENTIO_E2E_RELEASE_NAME`, or `AGENTIO_E2E_CHART_PATH`.

This matrix covers native Workload policies on ordinary Pods without synthetic Sandboxes. It does not claim coverage of a real Sandbox UID and structured Workload-to-Sandbox binding; that remains a separate future scenario.

## New disposable Kind cluster

Install Docker, Kind, kubectl, and Helm, then run:

```bash
make test.integration.agentio.kube
```

The default creates a unique Kind cluster, writes artifacts below `test/e2e/artifacts/<run-id>`, and removes resources and the owned cluster at the end.

## Reuse a named Kind cluster

The named cluster must already exist. It is borrowed and is never deleted:

```bash
cd test/e2e
E2E_FRAMEWORK_SMOKE=1 go test ./suites/framework -v -count=1 \
  -e2e.cluster.name=dev-e2e \
  -e2e.cluster.reuse=true
```

If the name exists while reuse is false, setup fails without changing that cluster.

## Existing kubeconfig context

An existing context is always borrowed. Retention controls only resources owned by the current run:

```bash
cd test/e2e
E2E_FRAMEWORK_SMOKE=1 go test ./suites/framework -v -count=1 \
  -e2e.cluster.mode=existing \
  -e2e.cluster.kubeconfig=/absolute/path/to/kubeconfig \
  -e2e.cluster.context=my-context \
  -e2e.lifecycle.retain=on-failure
```

`KUBECONFIG` is used only when `-e2e.cluster.kubeconfig` and `E2E_CLUSTER_KUBECONFIG` are unset.

## Retention and recovery

`-e2e.lifecycle.retain` accepts:

- `never`: delete exact-owned resources and an owned Kind cluster;
- `on-failure`: retain Kubernetes state after a failed run;
- `always`: retain Kubernetes state after every run.

Borrowed clusters are never deleted for any value. Local processes and temporary kubeconfigs are always closed or removed.

For `on-failure` and `always`, component-level Kubernetes cleanup is deferred until the Suite knows the final result. This avoids `testing.T` cleanup deleting the evidence before `TestMain` can apply the retention policy. A successful `on-failure` run is still cleaned normally by the Suite ledger.

Every run writes `environment.json` with cluster identity, ownership, resource GVR/name/namespace/UID, run label, manifest hash, component fingerprints, retention policy, and final status. Cleanup re-reads each object and requires both the recorded UID and run label before issuing a UID-preconditioned delete. A replaced or foreign object is left untouched.

For a retained owned Kind cluster the Suite prints both a reconnect command and the exact manual deletion command:

```bash
KUBECONFIG=/path/from/output kubectl --context kind-cluster-name get pods -A
kind delete cluster --name cluster-name
```

## Configuration

Configuration precedence is:

```text
framework defaults < suite defaults < strict YAML < E2E_* environment < CLI
```

Use `-e2e.config=/path/config.yaml` for the framework-only strict schema. Unknown fields and invalid combinations fail before cluster mutation. Product suites own separate flag and file namespaces.

The core flags are:

```text
-e2e.config
-e2e.artifacts.dir
-e2e.cluster.mode=kind|existing
-e2e.cluster.name
-e2e.cluster.kubeconfig
-e2e.cluster.context
-e2e.cluster.reuse
-e2e.cluster.kind.node-image
-e2e.cluster.kind.config
-e2e.lifecycle.retain=never|on-failure|always
-e2e.diagnostics.full-on-failure
-e2e.diagnostics.max-full-dumps
```

Command arguments, output, credential paths, and configured secrets are redacted in artifacts. Failure diagnostics always keep the original failure; collector failures are recorded separately, and full dumps are capped by `max-full-dumps`.

## Live-test prerequisites

New Kind runs require Docker and Kind. The framework smoke test additionally expects the pinned echo image to be reachable; Agentio runs require the seven immutable images above. Existing-context runs do not require Docker or Kind, but the selected Kubernetes context and image registry must be reachable.

The unit, vet, race, and dependency-boundary gates do not require a cluster. Do not treat a skipped live suite or a failed prerequisite check as a passing Kubernetes E2E run.

## On-demand certificate rotation (opt-in)

`TestSandboxOnDemandCertificateRotation` in `suites/gateway` is built only with `-tags=certrotation`. The default product planner therefore does not discover or schedule it, and ordinary E2E runs add no certificate expiry waits. With the usual immutable Agentio image inputs and a dedicated test cluster configured, run it separately:

```bash
AGENTIO_E2E=1 \
  go test -tags=certrotation ./suites/gateway -run '^TestSandboxOnDemandCertificateRotation$' -v -count=1 -timeout=15m
```

The test requires `agentio.reuse=false` and one Agentiod replica. It temporarily sets a 75-second leaf lifetime with a 45-second renewal window, verifies two serial changes through fresh CA-verified HTTPS requests to the local TLS fixture, then scales Agentiod to zero. It checks cached-certificate availability before expiry, the target secret disappearing from Envoy's active SDS config dump after expiry, and HTTPS recovery with a new certificate after Agentiod returns. It also asserts that the gateway did not restart. Issuer settings and replica count are restored on failure as well as success.

Once the fixtures are ready, certificate-clock waits take roughly 135 seconds; rollout, setup, recovery and cleanup add time. Each successful rotation logs the number of fresh connections and maximum probe latency. This is a correctness check, not a throughput benchmark, a CA private-key rotation test, or proof of zero interruption at production load. Normal-rotation probe failures fail the test immediately; only initial convergence and fault recovery use retries.
