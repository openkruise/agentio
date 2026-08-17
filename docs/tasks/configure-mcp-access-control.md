# Configure MCP access control

Use a `SecurityProfile` with `mcpToolPolicy` to allow or deny Model Context Protocol (MCP) tool invocations made by selected Pods. This task assumes that Egress Policy Enforcer (EPE) is enabled through the [external-processing provider configuration](../reference/agentio-configuration.md#external-processing-provider) and that the selected traffic reaches an EPE-enabled egress gateway.

`mcpToolPolicy` is a tool-call policy, not a general MCP authorization layer. It evaluates JSON-RPC `tools/call` requests and matches the exact `params.name` tool name.

## Before you begin

Set the MCP endpoint that the selected Pod reaches through the egress gateway:

```console
$ export MCP_URL=https://mcp.example.com/mcp
```

Find one Pod selected by the manifest below and name its application container:

```console
$ MCP_POD=$(kubectl get pod --namespace agent-demo \
    --selector app=agent \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$MCP_POD"
$ : "${MCP_CONTAINER:?Set the application container in the selected Pod}"
```

Because this task uses `https://mcp.example.com`, configure the selected gateway to terminate TLS for `mcp.example.com`, ensure the chart renders `ENABLE_ON_DEMAND_CERTS=true`, and make this workload trust the signing CA. Otherwise the connection remains on the gateway's TCP path and bypasses EPE's HTTP filter chain. Follow [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

The EPE stream must receive source identity from Envoy. If the downstream Pod name or namespace is unavailable, EPE cannot select a `SecurityProfile` and passes the request through. See [EPE request context](../reference/epe-request-context.md).

## Apply a whitelist policy

The following complete manifest allows only `read_file` and `search_docs`; every other readable `tools/call` is rejected with the configured response. It applies to Pods labelled `app: agent` in `agent-demo`.

```yaml
apiVersion: agents.kruise.io/v1alpha1
kind: SecurityProfile
metadata:
  name: mcp-tool-whitelist
  namespace: agent-demo
spec:
  selector:
    matchLabels:
      app: agent
  rules:
  - name: protect-mcp-tools
    match:
    - domains:
      - mcp.example.com
      schemes:
      - https
      paths:
      - type: Prefix
        value: /mcp
    actions:
      mcpToolPolicy:
        defaultAction: deny
        unsupportedVersionAction: deny
        denyResponse:
          statusCode: 403
          body: MCP tool is not permitted
        rules:
        - method: tools/call
          toolNames:
          - read_file
          - search_docs
          action: allow
```

Apply it with `kubectl apply -f mcp-tool-whitelist.yaml`. A rule's match clauses are ORed; fields within one match clause are ANDed. The full matching and action reference is [SecurityProfile](../reference/security-profile.md).

## Verify the decision

Use a supported protocol version and one JSON-RPC document per HTTP request. An allowed tool returns the MCP server's normal response:

```console
$ kubectl exec "$MCP_POD" --namespace agent-demo \
    --container "$MCP_CONTAINER" -- \
    curl --fail --silent --show-error "$MCP_URL" \
    --header 'Content-Type: application/json' \
    --header 'MCP-Protocol-Version: 2025-11-25' \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}'
```

An unlisted tool must return HTTP 403 and `MCP tool is not permitted` before EPE forwards it upstream:

```console
$ MCP_STATUS=$(kubectl exec "$MCP_POD" --namespace agent-demo \
    --container "$MCP_CONTAINER" -- \
    curl --silent --show-error --output /dev/null --write-out '%{http_code}' "$MCP_URL" \
      --header 'Content-Type: application/json' \
      --header 'MCP-Protocol-Version: 2025-11-25' \
      --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"delete_file","arguments":{"path":"README.md"}}}')
$ test "$MCP_STATUS" = 403
```

Both commands run in the selected workload container. A request made from the operator's shell, outside the selector, or outside the egress route does not exercise this policy.

## Supported framing and matching behavior

EPE always buffers the full request body for a matching `mcpToolPolicy`; it does not make a decision from the client-controlled version header alone. The current implementation supports MCP protocol versions `2025-06-18`, `2025-11-25`, and `2026-07-28`.

- Only JSON-RPC method `tools/call` is governed. `initialize`, `ping`, `tools/list`, resource, prompt, task, logging, and other methods pass through.
- Rules are considered in document order. The first matching rule wins. An empty `toolNames` list matches every tool name for that method; multiple names are ORed.
- The only permissive action is exactly `allow`. Action spelling is trimmed and case-normalized for payload compatibility, but unknown values fail closed.
- A supported `tools/call` with a missing or non-string `params.name` follows `defaultAction`.
- Missing or unsupported `MCP-Protocol-Version` is denied by the manifest above. Set `unsupportedVersionAction: passthrough` only when intentionally accepting calls EPE does not understand.
- A single JSON object with insignificant leading or trailing whitespace is accepted. JSON-RPC batches, malformed JSON, trailing non-whitespace content, and a second JSON document are unreadable and therefore follow `defaultAction`.
- EPE normalizes UTF-8 with a BOM and BOM-marked UTF-16 text, plus `gzip`, `x-gzip`, and `deflate` content codings (at most two codings). Decoded bodies over 8 MiB or any unsupported/invalid encoding are unreadable and follow `defaultAction`.

Use `defaultAction: deny` for tool whitelists. With a blacklist (`defaultAction: allow`), an unreadable body or an unnameable tool call is allowed by design; a nonconforming or unusually lenient upstream could then execute a call that EPE could not attribute. The policy does not inspect tool arguments, authorize `tools/list`, or enforce MCP sessions or server responses.

## Clean up

```console
$ kubectl delete securityprofile mcp-tool-whitelist --namespace agent-demo
```

After the deletion reaches EPE, its ACL no longer applies. Confirm this with an otherwise denied test call before relying on the result.

## See also

- [SecurityProfile reference](../reference/security-profile.md)
- [EPE request context](../reference/epe-request-context.md)
- [`SecurityProfile` CRD schema](../../manifests/charts/agentio/files/securityprofile-crd.yaml)
