# Configure MCP access control

Use a `SecurityProfile` with `mcpToolPolicy` to allow or deny Model Context Protocol (MCP) tool invocations made by selected Pods. This task assumes that Egress Policy Enforcer (EPE) is enabled and that the selected traffic reaches an EPE-enabled egress gateway.

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

Because this task uses `https://mcp.example.com`, configure the selected gateway to terminate TLS for `mcp.example.com`, configure the MITM signing CA, and make this workload trust that CA. Otherwise the connection stays on the gateway's TCP path and bypasses EPE's HTTP filter chain. See [TLS termination for HTTPS inspection](../reference/agentio-configuration.md#tls-termination-for-https-inspection).

The EPE stream must receive source identity. If the downstream Pod name or namespace is unavailable, EPE cannot select a `SecurityProfile` and passes the request through. See [EPE request context](../reference/epe-request-context.md).

## Apply a whitelist policy

The following manifest allows only `read_file` and `search_docs`; every other readable `tools/call` is rejected with the configured response. It applies to Pods labelled `app: agent` in `agent-demo`.

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

Apply it with `kubectl apply -f mcp-tool-whitelist.yaml`. Match semantics follow the [SecurityProfile reference](../reference/security-profile.md#rule-structure-and-matching).

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

## Matching behavior at a glance

- Rules are considered in document order; the first matching rule wins.
- The only permissive action is `allow`; unknown action values fail closed.
- Missing or unsupported `MCP-Protocol-Version` follows `unsupportedVersionAction`.
- Unreadable or malformed request bodies follow `defaultAction`.

Use `defaultAction: deny` for whitelists. With a blacklist (`defaultAction: allow`), an unreadable body or an unnameable tool call is allowed by design. The policy does not inspect tool arguments or enforce MCP sessions. See [MCP tool policy matching details](../design/mcp-tool-policy-matching.md) for framing and decoding behavior.

## Clean up

```console
$ kubectl delete securityprofile mcp-tool-whitelist --namespace agent-demo
```

After the deletion reaches EPE, its ACL no longer applies. Confirm this with an otherwise denied test call before relying on the result.

## See also

- [SecurityProfile reference](../reference/security-profile.md)
- [EPE request context](../reference/epe-request-context.md)
- [`SecurityProfile` API reference](../reference/security-profile-api.md)
