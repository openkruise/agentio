# EPE (Egress Policy Enforcer)

## Provenance

EPE is Agentio's Envoy external processor for applying `SecurityProfile` and `GlobalSecurityProfile` rules to agent egress traffic. The deployed artifact is named `agentio-epe` (image, chart `epe.*` values, Kubernetes resources); the code lives under `extensions/epe/`.

The `tokenTransformation` action can fetch short-lived credentials from an external credential provider; the HTTP contract a provider must implement is documented in [docs/reference/credential-provider.md](../../docs/reference/credential-provider.md).

## OAuth protocol capability

`pkg/filters/oauth2` provides a policy-neutral filter for device authorization,
token exchange, and resource credential injection. It returns public device
session data and `unused` token placeholders to the workload, and obtains the
real bearer token from the credential service for each resource request.
Application compatibility fields come from optional response extensions.

The filter accepts its own `Config` payload and has no dependency on the
SecurityProfile API. Production registration and CRD-to-payload projection are
follow-up integration work. The existing Identity device-service client supports
device authorization, device-code polling, and refresh-token/resource reads;
other grants receive `unsupported_grant_type` without calling a device RPC.
The protocol layer can recognize other grants, but their execution requires a
credential-service implementation that supports them.

## Code layout

```text
extensions/epe/
├── cmd/
│   └── epe/                 # Process entrypoint, flags, Kubernetes clients,
│                            # health, admin, metrics, and TLS setup.
├── pkg/
│   ├── engine/              # Evaluates rules in policy order and actions within each
│   │   │                    # rule in registration order. Owns body-phase cursor
│   │   │                    # continuation, the per-invocation budget/metrics wrapper,
│   │   │                    # and net-effect mutation folding. Its dependency closure
│   │   │                    # is guarded free of the policy API and ext_proc protos.
│   │   └── filter/          # Filter contract: interface, actions, mutations,
│   │                        # registry, stream info, peer identity.
│   ├── extproc/             # The protocol edge: ext_proc stream handling, body
│   │   │                    # handling, and response translation.
│   │   └── attributes/      # Envoy attribute and filter-state extraction.
│   ├── filters/             # Concrete filters implementing the contract:
│   │   │                    # block, bypass, headermutation, mcpacl,
│   │   │                    # tokentransform.
│   │   └── tokentransform/
│   │       └── signers/     # Per-provider request re-signing; aliyun implements the
│   │                        # published ACS V3/ROA/RPC and OSS V4 signing specs.
│   ├── policy/              # The only subtree allowed to import the CRD API.
│   │   ├── securityprofile/ # Compiled profile model, rule binder, resolver,
│   │   │                    # and the policy-side audit stream logger.
│   │   └── profilestore/    # KRT-backed SecurityProfile and GlobalSecurityProfile
│   │                        # watches and lock-free snapshots.
│   ├── wiring/              # Composition root assembling the production filter
│   │                        # chain and loggers; hosts the arch guard tests.
│   ├── eval/                # CEL/template evaluation.
│   ├── inputs/              # Shared request evaluation scope.
│   ├── httpreq/             # Neutral HTTP request tuple.
│   ├── audit/               # Audit routing and CEL conditions, plus the shared
│   │   │                    # bounded async delivery primitive.
│   │   ├── accesslog/       # Per-request audit log entries.
│   │   └── sinks/webhook/   # Audit webhook rendering and delivery.
│   ├── credential/          # Credential-provider client and token caches.
│   ├── certs/               # Serving certificate providers and SPIFFE-aware TLS validation.
│   ├── admin/               # Admin and profile-debug HTTP endpoints.
│   ├── server/              # ext_proc gRPC server construction.
│   ├── metrics/             # Process-wide Prometheus registry.
│   ├── labels/              # Label key/value pair parsing.
│   ├── logging/             # Log verbosity level constants.
│   ├── runnable/            # Long-running component contract and gRPC/HTTP adapters.
│   └── testing/
│       ├── enginetest/      # Policy-neutral in-process harness with a fake Envoy
│       │                    # stream, audit receiver, and metric probes.
│       └── securityprofile/ # SecurityProfile YAML fixtures and full-chain scenarios.
└── docker/                  # Runtime container image definition.
```

## Build and test

From the Agentio repository root:

```bash
make test.epe
make build.epe
```

The container image is `agentio-epe`, defined by
`extensions/epe/docker/Dockerfile`. Build it from the repository root:

```bash
docker build -f extensions/epe/docker/Dockerfile -t agentio-epe:dev .
```

The image workflow builds `linux/amd64` and `linux/arm64` directly from this
root Go module. Releases publish `agentio-epe` and `agentiod` from the same
commit with the same product tag.

The repository-level test suites can be run with:

```bash
make test
```

The current Kubernetes E2E framework does not deploy the real EPE image. The
imported unit, filter-scenario, policy-scenario, and gRPC assembly tests are the
behavioral parity gate; a real-image KinD scenario remains a documented gap.

### Test layers

Tests are layered by the contract they guard; each behavior is asserted at exactly one layer.

| Layer | Lives in | Guards |
| --- | --- | --- |
| Unit | each package's `_test.go` | single-package semantics (parsing, matching, signing) |
| Conformance | `pkg/wiring/conformance_test.go` | the `filter.Definition` contract, auto-applied to every filter in the production chain; a new filter must add its `minimalPayloads` entry or the suite fails by name |
| Filter scenario | `<filter>/scenario_test.go` via `enginetest.NewSingleFilter` | the filter's engine/wire interaction (phases, mutations, failure routing) driven by the filter's **own** payload schema — never a CRD, never importing `pkg/policy` |
| Policy scenario | `pkg/testing/securityprofile` | the only package combining CRD → store → resolver → engine → wire: CRD-to-payload translation, cross-filter composition (ordering, terminal actions), and the failure semantics (compile-time errors reject a version with last-known-good retention; runtime errors resolve through each action's failure policy) |
| Repository E2E | `test/e2e` | Kubernetes framework and chart integration outside the EPE process |

Ownership rule: a filter scenario owns behavior details; the policy layer proves the CRD reaches the same behavior with one golden path and does not restate it. Note the access-log vocabulary: `passthrough` means no policy matched; a matched request left unmodified logs as `bypassed`.

The `enginetest` harness drives the real `extproc.Server.Process` loop over a fake Envoy stream (`pkg/testing/enginetest/doc.go`). The boundaries it names as out-of-scope — Envoy-authenticated attributes, egress TLS termination, apiserver/CRD deployment consistency, krt watch propagation, cross-pod webhook delivery — have no KinD coverage today.

## Contributor guide

Keep the policy boundary intact: `pkg/policy/` owns the SecurityProfile CRD API. The architecture guard permits only two narrow exceptions: `pkg/admin/` renders CRD-typed debug views, and `pkg/testing/securityprofile/` owns CRD fixtures and scenarios. `pkg/extproc/` translates the external-processing protocol; `pkg/engine/` and `pkg/filters/` remain policy- and ext_proc-proto-free. `pkg/wiring/` is the composition root and its architecture guards enforce these rules.

To add an action/filter, define its schema and descriptor under `pkg/filters/`, register it in `pkg/wiring/`, and map the CRD action to the filter payload in `pkg/policy/securityprofile/payloads.go`. Add the action's CRD/API schema upstream rather than hand-editing generated CRDs. Update `pkg/wiring/arch_guard_test.go` when a new filter needs a source-directory mapping. Test per the layers above: unit tests, a `minimalPayloads` entry for the conformance suite, a filter scenario when the filter touches body/response phases, wire mutations, failure branching, or external IO, and one CRD golden path under `pkg/testing/securityprofile`.

Use focused checks while iterating:

```bash
go test ./extensions/epe/pkg/filters/<filter>/...
go test ./extensions/epe/pkg/policy/securityprofile/...
go test ./extensions/epe/pkg/wiring/...
go test ./extensions/epe/pkg/testing/enginetest/... ./extensions/epe/pkg/testing/securityprofile/...
```

The `enginetest` package provides the policy-neutral scenario harness; write SecurityProfile YAML fixtures and full-chain scenarios under `pkg/testing/securityprofile`. The current `test/e2e` suite does not deploy `agentio-epe`. Treat the Envoy-authenticated attributes, gateway TLS termination, Kubernetes watch/deployment propagation, and cross-Pod webhook delivery as KinD coverage gaps.
