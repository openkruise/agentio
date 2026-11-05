# Gateway protocol names

> Design note. Internal `filter_state` keys, filter-name prefixes, and log-expression names used by Agentio egress gateways. Operators writing custom CEL expressions, access-log formats, or Envoy patches use these names; the rest is implementation detail.

## Native gateway names

Native `agentio-egress` gateways capture TLS termination SNI in `agentio.tls.outer_sni`, log policy denials from `agentio.egress.denial_reason`, and store CONNECT authority in `agentio.connect.authority`. Native CONNECT filter instances use the `agentio.` prefix.

Workload, peer, route, and SNI-policy fields retain their existing `agentio.*` names. Sandbox context retains `agentio.sandbox.id` and `sandbox.token`; native gateways pass the verified Workload UID in `agentio.workload.uid`, along with its name and namespace. Porter does not pass labels.

Sandbox identity is captured from the CONNECT header `x-agentio-sandbox-id` into
`agentio.sandbox.id` and forwarded to Porter and EPE under that filter-state key.
Upgrade the sending ztunnel and receiving gateway together; custom filter-state
references must use `agentio.sandbox.id` as well.

EPE obtains metadata and SecurityProfile references from WDS. Legacy gateways retain `sandbox.labels` from `X-AGENTIO-SANDBOX-LABELS`, but production WDS resolution replaces those labels.

Configured ext_proc attribute names are passed through unchanged. Additional ext_proc filters, clusters, and statistics retain `agentio.additional-ext-proc.<name>`.

## Legacy waypoint names

Legacy waypoint gateways retain their existing keys, filter names, and default log expressions, including `io.kruise.outer_sni`, `io.kruise.egress_denial_reason`, and `io.istio.connect_authority`.

Custom CEL expressions, log formats, and filter-name patches must use the names for the target gateway. Envoy built-in keys, HTTP headers, Kubernetes API domains, and protobuf type URLs retain their protocol names.
