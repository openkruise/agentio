# Proxy initialization

`cmd/proxy-init` installs Agentio REDIRECT rules before a workload starts. It runs inside the Pod network namespace or inside a VM guest alongside ztunnel. It does not enter a namespace from a host path. TPROXY and policy routing are not supported.

The rule generators were adapted from the `release-0.1` Istio tools at source commit `79734fe48c`, including this project's DNS ordering and non-TCP patches. Original copyright and license notices are retained. The binary does not import Istio packages. Agentio owns `AGENTIO_*` iptables chains and the native nftables `agentio-proxy-{nat,raw,mangle,filter}` tables.

## Configuration

CLI flags use lowercase words separated by hyphens, without a project prefix. Environment names use `AGENTIO_` followed by the uppercase flag name with `-` replaced by `_`, except `--outbound-capture-port` / `-p`, which remains command-line only as in upstream. Flags override environment variables. `INVALID_DROP` remains the sole legacy alias: precedence is CLI, then `INVALID_DROP`, then `AGENTIO_DROP_INVALID`, then the default. Run `proxy-init --help` for the full list.

The supported REDIRECT path follows Istio's error handling, including best-effort probe and guardrail cleanup, validation socket cleanup, and dry-run output files. Invalid environment flag values follow upstream `BindEnv` behavior rather than aborting configuration loading; invalid command-line values still fail. The migration retains upstream backend-selection fixes. Agentio names, the removed TPROXY mode, and the explicitly configured DNS ordering and non-TCP policy remain intentional differences.

Dry-run also follows upstream behavior: the iptables backend generates rules without applying them, while native nftables still uses the real backend even with `--dry-run`. Use an isolated network namespace for native nftables experiments, or `--skip-rule-apply` to skip installation. `AGENTIO_NETWORK_NAMESPACE` supplies CNI execution context rather than entering a namespace; start proxy-init inside the target namespace. With native nftables selected, `AGENTIO_FORCE_IPTABLES_BINARY` is ignored by the selected backend.

| Environment | Flag | Default | Behavior |
| --- | --- | --- | --- |
| `AGENTIO_NATIVE_NFTABLES` | `--native-nftables` | `false` | Use native nftables. Failure is reported without backend fallback. |
| `AGENTIO_FORCE_IPTABLES_BINARY` | `--force-iptables-binary` | empty | Select `legacy` or `nft` explicitly for the iptables backend. |
| `AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY` | `--native-nftables-output-priority` | `-100` | Signed 32-bit priority greater than `-200`; custom values require native nftables. |
| `AGENTIO_REJECT_NON_TCP` | `--reject-non-tcp` | `false` | Capture all TCP/UDP port 53 DNS and reject other non-TCP output, with the exceptions below. |
| `AGENTIO_REDIRECT_DNS` | `--redirect-dns` | `false` | Enable DNS capture for the configured resolvers. |
| `AGENTIO_CAPTURE_ALL_DNS` | `--capture-all-dns` | `false` | Match any destination on port 53 when DNS capture is enabled. |

Traffic selection and operational options use the same naming rules:

| Flag | Environment | Purpose |
| --- | --- | --- |
| `--outbound-capture-port` / `-p` | None; CLI only | Outbound TCP proxy port, default `15001`. |
| `--inbound-capture-port` / `-z` | `AGENTIO_INBOUND_CAPTURE_PORT` | Inbound TCP proxy port, default `15006`. |
| `--inbound-tunnel-port` / `-e` | `AGENTIO_INBOUND_TUNNEL_PORT` | Bypass inbound interception for the HBONE port, default `15008`. |
| `--proxy-uid` / `-u` | `AGENTIO_PROXY_UID` | Proxy UID exempt from application interception. |
| `--proxy-gid` / `-g` | `AGENTIO_PROXY_GID` | Proxy GID; defaults to the selected proxy UID. |
| `--interception-mode` / `-m` | `AGENTIO_INTERCEPTION_MODE` | Only `REDIRECT` is supported. |
| `--include-inbound-ports` / `-b` | `AGENTIO_INCLUDE_INBOUND_PORTS` | Inbound ports to capture, or `*`. |
| `--exclude-inbound-ports` / `-d` | `AGENTIO_EXCLUDE_INBOUND_PORTS` | Inbound ports excluded from wildcard capture. |
| `--include-outbound-ip-ranges` / `-i` | `AGENTIO_INCLUDE_OUTBOUND_IP_RANGES` | Destination CIDRs to capture, or `*`. |
| `--exclude-outbound-ip-ranges` / `-x` | `AGENTIO_EXCLUDE_OUTBOUND_IP_RANGES` | Destination CIDRs excluded from capture. |
| `--include-outbound-ports` / `-q` | `AGENTIO_INCLUDE_OUTBOUND_PORTS` | Outbound ports explicitly included in capture. |
| `--exclude-outbound-ports` / `-o` | `AGENTIO_EXCLUDE_OUTBOUND_PORTS` | Outbound ports excluded from capture. |
| `--exclude-interfaces` / `-c` | `AGENTIO_EXCLUDE_INTERFACES` | Interfaces excluded from capture. |
| `--reroute-virtual-interfaces` / `-k` | `AGENTIO_REROUTE_VIRTUAL_INTERFACES` | Interfaces whose incoming traffic is treated as outbound. |
| `--drop-invalid` | `AGENTIO_DROP_INVALID`, legacy alias `INVALID_DROP` | Drop INVALID packets. |
| `--dual-stack` | `AGENTIO_DUAL_STACK` | Detect addresses for dual-stack capture. |
| `--dry-run` / `-n` | `AGENTIO_DRY_RUN` | Use the selected backend's dry-run behavior described above. |
| `--skip-rule-apply` | `AGENTIO_SKIP_RULE_APPLY` | Skip rule installation. |
| `--run-validation` | `AGENTIO_RUN_VALIDATION` | Validate interception after initialization. |
| `--iptables-probe-port` | `AGENTIO_IPTABLES_PROBE_PORT` | Validation listener port, default `15002`. |
| `--probe-timeout` | `AGENTIO_PROBE_TIMEOUT` | Validation timeout, default `5s`. |
| `--network-namespace` | `AGENTIO_NETWORK_NAMESPACE` | CNI execution context; does not enter a namespace. |
| `--cni-mode` | `AGENTIO_CNI_MODE` | Use host-filesystem/Pod-network execution semantics. |
| `--reconcile` | `AGENTIO_RECONCILE` | Reconcile existing incompatible rules. |
| `--cleanup-only` | `AGENTIO_CLEANUP_ONLY` | Clean rules without installing new ones. |
| `--force-apply` | `AGENTIO_FORCE_APPLY` | Force rule application despite detected existing state. |
| `--log-output-level` | `AGENTIO_LOG_OUTPUT_LEVEL` | Log level, default `default:info`. |
| `--log-as-json` | `AGENTIO_LOG_AS_JSON` | Emit JSON logs. |

The following settings remain environment-only:

| Environment | Default | Purpose |
| --- | --- | --- |
| `AGENTIO_INCLUDE_OUTBOUND_OWNER_GROUPS` | `*` | Process groups whose outgoing traffic is captured. |
| `AGENTIO_EXCLUDE_OUTBOUND_OWNER_GROUPS` | empty | Process groups excluded when the include value is `*`. |
| `AGENTIO_OUTBOUND_IPV4_LOOPBACK_CIDR` | `127.0.0.1/32` | Loopback destination range used for application traffic. |
| `AGENTIO_PROXY_USER` | `agentio-proxy` | Username used to find a default proxy UID when `-u` is omitted; lookup failure falls back to `1337`. |
| `AGENTIO_DRY_RUN_FILE_PATH` | empty | File for the iptables dry-run rule output. |

These are the canonical names for the new standalone binary. Earlier PR versions' unprefixed variables, old `--agentio-*` flags, `--envoy-port`, `--kube-virt-interfaces`, and log flags with underscores are not accepted as aliases. `ISTIO_META_DNS_CAPTURE`, `AGENTIO_META_DNS_CAPTURE`, and `ISTIO_DUAL_STACK` are not init configuration inputs. Existing short flags remain available. Diagnostics report the effective configuration; detected addresses and resolvers are outputs rather than environment settings.

`AGENTIO_REJECT_NON_TCP` forces DNS capture before interface, port, CIDR and owner-group exclusions. It preserves redirected loopback UDP DNS, proxy UID/GID UDP upstream DNS to port 53, proxy replies from port 15053, and ICMPv6 types 1–4, 130–136 and 143. It does not filter inbound traffic. Reserve the proxy UID/GID for ztunnel; applications using those credentials share its DNS exceptions. ztunnel must separately enable its DNS listener on TCP/UDP port 15053.

For kube-proxy native nftables Service DNAT at OUTPUT priority `-100`, use:

```sh
AGENTIO_NATIVE_NFTABLES=true \
AGENTIO_NATIVE_NFTABLES_OUTPUT_PRIORITY=-101 \
AGENTIO_REJECT_NON_TCP=true \
proxy-init -u 1337 -g 1337 -m REDIRECT -i '*' -b '*'
```

The iptables variants cannot configure a custom base-chain priority. Detection checks executable versions, existing rules and an actual kernel rule operation in the current namespace, rather than comparing kernel version numbers. Native nftables validates and applies its transaction through `nft`.

Backend detection counts actual `-A` / `-I` rules rather than empty table headers, incorporating the fix from [Istio #61024](https://github.com/istio/istio/pull/61024). This prevents capability probes from changing the selected backend on a later initialization in the same namespace.

Changing configuration requires a fresh Pod/Sandbox network namespace or a fresh VM network setup before application startup. This release does not hot-update live connections, migrate conntrack entries, or clean legacy `ISTIO_*` chains. Do not install both generations into an existing namespace.

## Injection and sandbox charts

The standalone chart exposes:

```yaml
agentiod:
  injector:
    proxyInit:
      nativeNftables: true
      natOutputPriority: "-101"
      rejectNonTCP: true
```

These values also seed the generated OpenKruise sandbox-controller `agentio.trafficProxy` configuration. Rebuild the integration bundle after changing the source chart. In the exported sandbox-controller chart the same fields are `agentio.trafficProxy.nativeNftables`, `natOutputPriority`, and `rejectNonTCP`.

Standalone Pod overrides use `traffic.sidecar.agentio.kruise.io/native-nftables`, `traffic.sidecar.agentio.kruise.io/nat-output-priority`, and `traffic.sidecar.agentio.kruise.io/reject-non-tcp`. Traffic selection annotations use the `traffic.sidecar.agentio.kruise.io/` prefix. Interception and status port are `sidecar.agentio.kruise.io/interception-mode` and `sidecar.agentio.kruise.io/status-port`.

Agentio annotation suffixes use lowercase words separated by hyphens. Under `traffic.sidecar.agentio.kruise.io/`, the traffic selection keys are:

| Annotation suffix | Purpose |
| --- | --- |
| `include-outbound-ip-ranges` | Destination CIDRs to capture, or `*`. |
| `exclude-outbound-ip-ranges` | Destination CIDRs excluded from capture. |
| `include-inbound-ports` | Inbound TCP ports to capture, or `*`. |
| `exclude-inbound-ports` | Inbound TCP ports excluded from capture. |
| `include-outbound-ports` | Outbound TCP ports explicitly included in capture. |
| `exclude-outbound-ports` | Outbound TCP ports excluded from capture. |
| `exclude-interfaces` | Interfaces excluded from capture. |
| `reroute-virtual-interfaces` | Interfaces whose incoming traffic is treated as outbound. |
| `kubevirt-interfaces` | Alternative virtual-interface input; `reroute-virtual-interfaces` takes precedence. |

The earlier Agentio camelCase annotation spellings are no longer read. Helm values keep their existing camelCase field names.

The pinned external CNI still requires its legacy traffic/status annotations; the injector projects Agentio inputs into those keys only when CNI is enabled. That CNI owns traffic capture in its mode; proxy-init performs validation only. These proxy-init options therefore target init-container / guest-local capture. Existing ztunnel protocol environment variables remain governed by the pinned ztunnel binary and are not renamed by this migration.

## Firewall ordering and verification

The pinned ztunnel firewall can install an OUTPUT filter at priority `-150`. An attached policy that rejects UDP DNS there can run before NAT at `-101`. Allow application UDP port 53 in that earlier policy. Changing NAT priority alone is insufficient: NAT lookup priorities do not necessarily move the surrounding NAT hook ahead of an independently registered filter on every supported kernel. The Linux 5.15 packet test confirms that an earlier rejecting filter still wins. OUTPUT may also carry the original interface before rerouting, so an `oif lo` exception is insufficient. Proxy-init matches the translated loopback address plus DNAT state. Check the actual ztunnel policy; proxy-init cannot override another chain's reject. The preserved ICMPv6 types also require permission in other firewalls. Guest DHCP renewal is not exempted by `AGENTIO_REJECT_NON_TCP`.

```sh
make build.proxy-init
make test.proxy-init
# Linux with root/namespace capabilities, iptables, nft, ip and unshare:
make test.integration.proxy-init
```

The Linux tests include kernel installation/cleanup, a Service DNAT chain registered before capture, and a DNS backend in another network namespace. They reproduce failure with Service DNAT ordered first and verify TCP/UDP DNS through UID/GID 1337, upstream Service DNAT, reverse NAT and reverse REDIRECT, plus non-DNS UDP rejection.

`make test.integration.proxy-init.kind` builds an isolated two-node Kubernetes 1.32.2 cluster using native nftables kube-proxy (requires kind 0.27 or newer). It tests native nftables, iptables-nft and legacy iptables in ordinary Pods, and native nftables in a host-network Pod sharing kube-proxy's OUTPUT hook. A test DNS sidecar forwards to the real CoreDNS Service. Logs and rules are retained under the printed artifact directory; the test cluster is deleted on exit.

These tests do not deploy the real ztunnel, exercise live ztunnel policy updates, or run a VM/KubeVirt guest. The packet tests currently exercise IPv4; IPv6 rules are covered by rule-generation and kernel-installation tests.

Verified on `my-ecs` with Linux 5.15.0-117-generic, nftables 1.0.2, iptables 1.8.7 and kind 0.27.0 / Kubernetes 1.32.2. All four kind scenarios passed UDP/TCP DNS forwarding to CoreDNS and non-DNS UDP rejection. The separate network-namespace test reproduced the Service-DNAT-first failure and passed with capture priority `-101`.
