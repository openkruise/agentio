# Troubleshoot policy enforcement

Use this sequence when a policy is accepted by Kubernetes but the request is allowed unexpectedly, blocked unexpectedly, or unchanged. Follow one request from the calling Pod through the gateway to EPE; a ready Deployment or an existing policy object is not proof that this request used it.

## Identify the installation and request

Record the calling Pod namespace, name and labels, the URL including scheme and port, the expected result, and the actual response body. Use the workload variables from onboarding:

```console
$ kubectl get pods --namespace "$AGENTIO_DEMO_NAMESPACE" \
    --selector "app=$AGENTIO_WORKLOAD_LABEL" --show-labels
```

Use the control plane that this workload actually connects to. Standalone examples normally use `agentio-system`; the manager integration normally uses `sandbox-system` and is upgraded through the manager release. Set the following namespace accordingly, and adjust Deployment names if you used name overrides:

```console
$ export AGENTIO_CONTROL_PLANE_NAMESPACE=agentio-system
$ kubectl get deployments --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE"
```

If a preceding tutorial's profile still matches this request, it may run first. Inspect all matching profiles, including global ones, before attributing the result to the newest profile.

## Check capture, routing and TLS

1. Confirm the Pod is enrolled in the intended [sidecar](../getting-started/sidecar-mode.md) or [ambient](../getting-started/ambient-mode.md) data plane. Changing injection settings does not modify an already-created Pod.
2. Inspect **both** `agentio-config` and `agentio-config-primary`. A primary routing list replaces the base list; a successful Helm upgrade may leave the effective route unchanged.
3. Confirm the actual destination is sent to the expected gateway and that gateway is ready. `matchHosts` routes by resolved destination addresses, not by HTTP path.
4. For HTTPS, confirm termination in the selected TLS mode and caller CA trust. TLS passthrough and opaque TCP do not invoke EPE's request-level filters. See [Inspect HTTPS traffic](inspect-https-traffic.md).

```console
$ kubectl get configmap agentio-config agentio-config-primary \
    --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE" --ignore-not-found --output yaml
$ kubectl logs deployment/agentiod --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE" \
    --container discovery --since=10m
```

For a connection rejected before EPE, check TrafficPolicy and gateway identity/SNI decisions. The [traffic processing guide](../concepts/traffic-processing.md) distinguishes Porter connection handling from EPE HTTP handling.

## Inspect Agentiod's effective configuration

When `AGENTIO_ENABLE_DEBUG_ON_HTTP` is enabled, forward its monitoring listener in a separate terminal:

```console
$ kubectl port-forward --namespace "$AGENTIO_CONTROL_PLANE_NAMESPACE" \
    deployment/agentiod 15014:15014
```

Then inspect the effective source and compiler failures:

```console
$ curl --fail --silent --show-error 'http://127.0.0.1:15014/debug/configz?pretty'
$ curl --fail --silent --show-error \
    'http://127.0.0.1:15014/debug/configz?kind=AgentioConfig&pretty'
```

The response contains `synced`, `items`, and `failures`. Optional `kind`, `namespace`, and `name` filters narrow the dump. This is control-plane evidence, not confirmation that every proxy accepted the update. A 404 can mean the debug endpoint is disabled. Real loopback requests bypass authentication; other callers require TokenReview and root-namespace authorization. Use the local port forward rather than exposing the listener.

## Check EPE selection and compilation

Use the [EPE admin API](../reference/epe-admin-api.md) instructions to forward port 15000 from an EPE Pod. In another terminal, use the actual calling Pod labels to inspect selector matches:

```console
$ curl --fail --silent --show-error --get \
    --data-urlencode "namespace=$AGENTIO_DEMO_NAMESPACE" \
    --data-urlencode "pod_labels=app=$AGENTIO_WORKLOAD_LABEL" \
    http://127.0.0.1:15000/debug/profiles
```

Supply all labels relevant to your selectors. Match mode includes global profiles and returns evaluation order. It checks selectors only, not HTTP matches or credentials. A namespace-only list excludes global profiles. `full=true` fetches live Kubernetes specifications, so it is not evidence that a rejected new version replaced an older compiled version.

Inspect EPE logs and [compilation metrics](../reference/epe-observability.md):

- `epe_profile_compile_failures_total`: authoring/compilation errors.
- `epe_profile_stale`: a previous valid version remains active.
- `epe_profile_unenforced`: no valid version exists for a profile.
- `epe_profile_inputs_unavailable`: a ConfigMap input is unavailable; rules remain installed but input-dependent actions can fail.

Check every EPE replica when results vary between requests; a port forward reaches only one process. After selector checks, compare the request's host, scheme, path, method and port with the rule. Confirm that an earlier terminal action did not stop evaluation.

## Interpret the result

| Symptom | Next evidence to inspect |
| --- | --- |
| TLS certificate error | Caller CA bundle, Pod recreation, gateway signing CA and upstream TLS errors |
| Upstream response instead of the demo block body | Capture, effective gateway route, TLS termination, selector, rule match and earlier bypass |
| Correct 403 but an old demo response body | Earlier profile, creation-time ordering, or a rejected update retaining the last valid version |
| Generic 403 during credential transformation | Secret namespace and EPE RoleBinding, data key, provider response, template and signer errors; default `failStrategy` is `Block` |
| 403 with missing caller identity | `--fail-closed-on-missing-identity`, or forced rejection from `--enable-egressauthz` |
| HTTP 500 with EPE authorization errors | ADS authentication, source cluster ID, Workload/TrafficPolicy availability and authorization budget |
| Accepted policy but unchanged header | Request matches the transformation, EPE ran, and a later action did not overwrite it; verify at a controlled upstream |

Use a unique demo response body or dummy header value and an unmodified control request to distinguish enforcement from an upstream response. Restore any temporary log levels and remove only your test policies after diagnosis.
