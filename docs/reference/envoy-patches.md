# Envoy patches

Use a ConfigMap to patch the Envoy resources generated for an Agentio egress gateway. The payload directly defines the target gateways and patches; it does not require an Istio EnvoyFilter or a new custom resource.

Use the [gateway configuration fields](agentio-configuration.md) for settings they already cover. Patches provide access to lower-level Envoy configuration.

Configure CONNECT bandwidth through AgentioConfig's `bandwidthLimit`. When applying other patches to that CONNECT chain, preserve the [module's placement restrictions](../../extensions/envoy/network-limits/README.md): do not enable router retries or retain already-forwarded data for replay.

## Apply a configuration

Create a ConfigMap in the control plane's root namespace, normally `agentio-system`, with the `manifests.agentio.kruise.io/type: gateway-patch` label and YAML in `data.patches`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-patches
  namespace: agentio-system
  labels:
    manifests.agentio.kruise.io/type: gateway-patch
data:
  patches: |
    targetGateways:
      - demo/egress
    patches:
      - target: cluster
        operation: MERGE
        match:
          name: http_dynamic_forward_proxy
        value:
          connect_timeout: 3s
```

Save the manifest and run:

```sh
kubectl apply -f gateway-patches.yaml
```

Replace `demo/egress` with the namespace/name of your Envoy egress gateway. Static Agentio gateways and gateways managed through the `agentio-egress` GatewayClass are supported. The deployment-only `agentgateway` path does not consume these patches.

`agentiod` watches the ConfigMap and rebuilds the selected gateways' configuration. Updating the configuration does not require restarting `agentiod` or the gateway. A complete [example manifest](../../manifests/examples/gateway-patches.yaml) also demonstrates patching an HTTP connection manager's typed configuration.

## Selecting a configuration

The `manifests.agentio.kruise.io/type` label declares one configuration type per ConfigMap. The exact, case-sensitive value `gateway-patch` selects `data.patches`. A `patches` key alone does not select a ConfigMap.

The legacy `manifests.agents.kruise.io/kube-source` label selects embedded Istio documents in `data.sources`. Separate multiple documents with `---`; List wrappers are not supported.

| Labels | Gateway patch input |
| --- | --- |
| `type: gateway-patch`, with or without the legacy label | Only `data.patches`; embedded EnvoyFilters in `data.sources` are ignored. |
| Legacy label, without `type: gateway-patch` | Only EnvoyFilters in `data.sources`; `data.patches` is ignored. |
| Neither matching label | No gateway patches are read. |

The gateway-patch type label takes precedence even when `data.patches` is missing, empty, or invalid. Removing the gateway-patch type label reactivates embedded EnvoyFilters if the legacy label remains. This precedence applies within one ConfigMap; it does not change priority ordering between ConfigMaps.

Legacy Telemetry remains independently selected by the legacy label and read from `data.sources`, including when the gateway-patch type is selected. The gateway-patch type label alone does not select Telemetry.

## Configuration fields

Each ConfigMap contains one configuration object:

| Field | Required | Meaning |
| --- | --- | --- |
| `targetGateways` | Yes | Nonempty list of exact `namespace/name` gateway identities. Duplicates are removed. Targets can be in different business namespaces. |
| `priority` | No | Signed 32-bit integer, default `0`. Lower values are ordered first. |
| `patches` | Yes | Nonempty list of patches using the fields below. |

The containing ConfigMap supplies the configuration's name and namespace. No inner `metadata`, `spec`, `kind`, or `apiVersion` is needed. Use separate ConfigMaps for groups requiring different priorities or targets.

Each patch contains:

| Field | Meaning |
| --- | --- |
| `target` | Envoy object type from the table below. |
| `operation` | Operation from the supported set for that target. |
| `match` | Optional object selecting existing resources. Its fields depend on the target and operation. |
| `value` | Envoy v3 protobuf configuration. Required for all operations except REMOVE, which must omit it. |

Configuration field names, target names, and operation names are case-sensitive. Unknown fields, duplicate YAML keys, invalid types, additional YAML documents, and unsupported operations reject the entire patch update for that ConfigMap.

## Targets and operations

| Target | Operations |
| --- | --- |
| `cluster` | ADD, MERGE, REMOVE |
| `listener` | ADD, MERGE, REMOVE |
| `listenerFilter` | ADD, MERGE, REMOVE, REPLACE, INSERT_BEFORE, INSERT_AFTER, INSERT_FIRST |
| `filterChain` | ADD, MERGE, REMOVE |
| `networkFilter` | ADD, MERGE, REMOVE, REPLACE, INSERT_BEFORE, INSERT_AFTER, INSERT_FIRST |
| `httpFilter` | ADD, MERGE, REMOVE, REPLACE, INSERT_BEFORE, INSERT_AFTER, INSERT_FIRST |
| `routeConfiguration` | MERGE |
| `virtualHost` | ADD, MERGE, REMOVE, REPLACE |
| `httpRoute` | ADD, MERGE, REMOVE, INSERT_BEFORE, INSERT_AFTER, INSERT_FIRST |
| `extensionConfiguration` | ADD |

### Matching resources

- **cluster**: `match.name` is the exact cluster name.
- **listener and its descendants**: `match.name` and `match.portNumber` select the containing listener. Descendants can use `filterChain` with `name`, `sni`, `transportProtocol`, `applicationProtocols`, and `destinationPort`. Application protocols are a comma-separated string; every listed protocol must be present.
- **listenerFilter**: `match.listenerFilter` selects the listener filter by name.
- **networkFilter**: `match.filterChain.filter.name` selects the network filter.
- **httpFilter**: `match.filterChain.filter.name`, if supplied, must be `envoy.filters.network.http_connection_manager`. `match.filterChain.filter.subFilter.name` selects the HTTP filter.
- **routes**: `match.name` selects the route configuration. `virtualHost` supports `name` and `domainName`; its `route` supports `name` and `action`. Actions are ANY (default), ROUTE, REDIRECT, and DIRECT_RESPONSE.
- **extensionConfiguration** has no match.

Only fields used by a target and operation are accepted. For example, a listener patch cannot match a filter chain, a virtual host patch cannot match a route, and cluster/listener ADD must omit match.

INSERT_BEFORE and INSERT_AFTER require a named anchor. Filter REMOVE and REPLACE require a named filter; listenerFilter MERGE also requires a name. ADD and INSERT_FIRST must omit the child-element match they do not use. Parent selectors, such as the listener name for an HTTP filter ADD, remain available.

The patch configuration does not accept Istio proxy/context selectors or service/subset/route-port matching based on Istio resource-name encodings. Use actual generated resource names.

A valid match that finds no resource makes no change. An insertion whose anchor does not exist also makes no change. A missing target gateway does not make the configuration global: it becomes applicable if that gateway is later configured.

### Values and merge behavior

Values follow [ProtoJSON](https://protobuf.dev/programming-guides/json/). Envoy fields accept their protobuf snake_case names or JSON lowerCamelCase names. Use strings such as `3s` for durations and `@type` inside typed configurations. The control plane must have the protobuf type registered, and the Envoy image must contain the corresponding extension. Unknown value fields or types are rejected.

MERGE accepts partial messages. Messages merge recursively, repeated fields append, maps merge by key, and Duration messages replace as a whole. This differs from the replacement behavior of the high-level `data.config` configuration.

An empty list does not clear an existing protobuf list. For proto3 scalar fields without presence, values such as `false` or `0` do not express resetting a non-default value. Use REPLACE with a complete object where the target supports it.

Lower priorities are ordered first. Equal-priority patch configurations are ordered by ConfigMap namespace/name. The engine also processes resources and operations in phases; patches are not an arbitrary sequential instruction list. For example, cluster ADD runs after modifications of existing clusters, so a MERGE in the same rebuild does not modify a newly added cluster. Include the complete configuration in its ADD value.

## Updates and diagnostics

Each rebuild starts from generated resources, so repeated updates do not accumulate appended values from previous rebuilds.

- An invalid patch input retains that ConfigMap's complete previously accepted patch collection, including when switching input formats. It does not fall back to the other format.
- If applying accepted patches produces an invalid gateway resource set, the compiler retains that gateway's previous resource set.
- Remove or clear `data.patches` while retaining the gateway-patch type label to withdraw its patches without activating legacy EnvoyFilters. Deleting the ConfigMap or removing both selection labels withdraws all patches from that source. A nonempty object with `patches: []` is invalid.
- Last-known-good state is held in memory: an invalid source on a fresh start produces no patches, and an invalid first gateway compilation has no previous resource set to retain. Source and gateway updates are not a transaction across gateways or resource types.

When the authenticated `/debug/configz` endpoint is enabled:

- `items` contains accepted patches using the diagnostic kind `GatewayPatch`, including patches converted from legacy EnvoyFilters. This is an internal representation, not a Kubernetes resource. Use `?kind=GatewayPatch` to filter patch entries.
- `failures` includes compilation failures under `Gateway/namespace/name`.

Check the `agentiod` logs for rejected ConfigMap revisions and parsing errors. Successful `kubectl apply` only stores the ConfigMap; acceptance and compilation do not guarantee an Envoy ACK or a match against a particular generated object. The debug endpoint does not provide per-patch match counts or Envoy ACK state.

## Migrate from embedded EnvoyFilter

- Deploy an `agentiod` version supporting the gateway-patch type label and `data.patches` before changing the ConfigMap; older binaries ignore the patch configuration.
- Within one ConfigMap update, add `manifests.agentio.kruise.io/type: gateway-patch` and the equivalent direct configuration in `data.patches`. This replaces all embedded EnvoyFilters from that ConfigMap. Legacy documents may remain for rollback; they are ignored while the gateway-patch type is selected.
- Keep target gateways and patch values equivalent. Set explicit priorities when order matters. Keep each intended patch in one source: identical content in different ConfigMaps executes once per source.
- Apply a separate ConfigMap for patches; the Helm `agentiod.config.sources` value still contains legacy resource documents.
- Before rolling back to an older binary, ensure the legacy label and documents contain the desired configuration. To switch back, remove the gateway-patch type label while retaining the legacy label and documents.
