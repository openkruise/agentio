# EPE admin API

The Egress Policy Enforcer (EPE) always starts an HTTP admin server. Its default bind address is `127.0.0.1:15000`, which makes it available only inside the EPE Pod unless an operator changes `--admin-addr`. The Kubernetes Service does not expose this port. Use port-forwarding for inspection:

```console
$ EPE_POD=$(kubectl get pod --namespace agentio-system \
    --selector app.kubernetes.io/name=agentio-epe \
    --output jsonpath='{.items[0].metadata.name}')
$ test -n "$EPE_POD"
$ kubectl port-forward --namespace agentio-system "$EPE_POD" 15000:15000
```

## Index endpoint

`GET /` is always available and returns plain text. It lists available debug endpoints and says whether they are enabled. Only the exact root path is an index: unknown paths return `404 Not Found`.

```console
$ curl --fail --silent http://127.0.0.1:15000/
```

The binary defaults `--enable-debug=true`. Starting it with `--enable-debug=false` leaves the index available but does not register debug paths; requests to `/debug/profiles` and `/debug/logging` then return 404.

## Credential cache invalidation

`POST /cache/credentials/invalidate` synchronously invalidates credentials in the EPE process reached by the request. This operational endpoint is available even with `--enable-debug=false`. It shares the admin listener's trusted-operator boundary; it has no independent authentication and is not exposed by the Service.

Invalidate one provider:

```console
$ curl --fail --silent --request POST \
    --header 'Content-Type: application/json' \
    --data '{"providerName":"my-provider"}' \
    http://127.0.0.1:15000/cache/credentials/invalidate
{"apiKeyEntries":12,"stsEntries":3,"oauth2Entries":2}
```

`providerName` is required and must be non-empty; it is the remote `credentialProviderName`, not the local `EPEConfig.extensionProviders[].name`. A successful `200 OK` response reports removed entries, including expired entries not yet reaped; zero counts are successful. The response does not mean new credentials have been fetched. For cache semantics and invalidation behavior, see [Credential provider](credential-provider.md#external-cache-invalidation).

Requests must contain one JSON object of at most 4 KiB. Unknown fields, invalid types, trailing JSON, and missing or empty provider names return `400` without changing cache state. Other methods return `405` with `Allow: POST`. JSON responses carry `Cache-Control: no-store`.

The interface is local to one process. Calling a load-balanced Service once does not invalidate every replica; deliver invalidation to every instance. No Kubernetes watches or provider-specific integrations are installed by EPE.

## Runtime log level

EPE supports `agentiod`'s logging API format on its admin listener. EPE exposes one process-wide scope, `default`; component scopes such as `krt` are not available here.

| Request | Response |
| --- | --- |
| `GET /debug/logging` or `GET /debug/logging/` | `200 OK`, a list of scopes. |
| `GET /debug/logging/default` | `200 OK`, the `default` scope object. |
| `HEAD` on either route | Same status as GET, without a body. |
| `PUT` on either route with `output_level` | Applies immediately, then returns `202 Accepted` without a body. |

All logging responses have `Cache-Control: no-store`. For example, at the default startup verbosity:

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/logging
[{"name":"default","output_level":"info"}]

$ curl --fail --silent --request PUT \
    --header 'Content-Type: application/json' \
    --data '{"output_level":"debug"}' \
    http://127.0.0.1:15000/debug/logging/default

$ curl --fail --silent http://127.0.0.1:15000/debug/logging/default
{"name":"default","output_level":"debug"}
```

The PUT body may include `"name":"default"`, so a scope object returned by GET can be sent back unchanged. Omitting `/default` from the PUT URL has the same effect.

| `output_level` value | Effect in EPE |
| --- | --- |
| `"debug"` | Enables EPE debug records at verbosity 1, including token-transformation and external-processing diagnostics. |
| `"info"` | Restores EPE's default verbosity. |
| `"warn"`, `"error"` | Sets the corresponding minimum level. |
| `"none"` | Suppresses all log output. Panic/fatal control flow is unchanged. |

EPE also accepts numeric strings from `"0"` through `"127"` for exact verbosity, and the `"dpanic"`, `"panic"`, and `"fatal"` thresholds. Named levels match the startup `--zap-log-level` flag.

| Value form | Meaning |
| --- | --- |
| `"0"`–`"127"` | Exact verbosity (logr's `V(n)`); higher numbers are more verbose. `"2"` enables trace records. |
| `"debug"`, `"info"` | Named levels. GET reports verbosity 0 as `"info"` and verbosity 1 as `"debug"`; higher verbosity thresholds remain numeric. |
| `"dpanic"`, `"panic"`, `"fatal"` | Thresholds at or above panic. |

Send exactly one JSON object with a non-empty `output_level` string and an optional `name`. Invalid values, unknown fields, a mismatched `name`, trailing JSON, and bodies larger than 4 KiB return `400` without changing the level. Unknown scopes return `400`; nested scope paths return `404`. Unsupported HTTP methods return `405` with `Allow: GET, HEAD, PUT`.

To restore the default EPE verbosity, PUT `{"output_level":"info"}`. A runtime change applies immediately to existing loggers in the EPE process reached by this request; configure each replica separately if necessary. Changes are not persisted: a restart restores `-v` or the overriding `--zap-log-level`. Encoding, stacktrace thresholds, and startup sampling configuration stay unchanged.

The endpoint controls EPE's shared logging core (Zap is the underlying logger; logr is the interface it implements), including existing controller-runtime loggers. Shared Agentio packages retain their separate INFO scope gate, so increasing EPE verbosity does not enable those packages' DEBUG records. This endpoint does not change `agentiod` logging.

## Profile inspection endpoint

When debug is enabled, `GET` and `POST /debug/profiles` list compiled `SecurityProfile`, `GlobalSecurityProfile`, and Sandbox annotation profiles from EPE's in-memory store. Every JSON response has `Content-Type: application/json; charset=utf-8` and `Cache-Control: no-store`.

### List mode

List mode returns every loaded profile, optionally filtering exact namespaced profiles by `namespace`. A namespace filter excludes global profiles. Results are sorted in the same order EPE evaluates them: priority, creation timestamp, name, then namespace.

```console
$ curl --fail --silent http://127.0.0.1:15000/debug/profiles
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo'
$ curl --fail --silent --request POST \
    --header 'Content-Type: application/json' \
    --data '{"namespace":"agent-demo"}' \
    http://127.0.0.1:15000/debug/profiles
```

### Match mode

Supply workload labels and a namespace to see the profiles EPE would match for a Workload. A GET uses comma-separated `key=value` pairs in `workload_labels`; a POST uses an object. Supply `workload_name` to also include the same-name Sandbox profile after selector matches. Match results are returned in evaluation order. A namespace is required whenever `workload_labels` or `workload_name` is supplied.

```console
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo&workload_labels=app=agent-demo,team=payments'

$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo&workload_name=agent-0&workload_labels=app=agent-demo'

$ curl --fail --silent --request POST \
    --header 'Content-Type: application/json' \
    --data '{"namespace":"agent-demo","workload_labels":{"app":"agent-demo","team":"payments"}}' \
    http://127.0.0.1:15000/debug/profiles
```

The endpoint selects profiles from workload metadata, including same-name Sandbox profiles when `workload_name` is supplied. It does not run HTTP rule matching, fetch credentials, evaluate request bodies, or predict a final request decision.

### Response shape and full mode

The default response returns identity and ordering fields only:

```json
{
  "count": 1,
  "profiles": [
    {
      "kind": "SecurityProfile",
      "namespace": "agent-demo",
      "name": "audit-blocked-admin",
      "priority": 1000
    }
  ]
}
```

`kind` is `SecurityProfile` or `GlobalSecurityProfile`; a global profile has an empty `namespace`. Add `full=true` to a GET or `"full": true` to a POST to include `creationTimestamp` and the complete source `spec` of each locally installed profile. Full mode makes no Kubernetes API requests:

```console
$ curl --fail --silent \
    'http://127.0.0.1:15000/debug/profiles?namespace=agent-demo&full=true'
```

The details describe the same version EPE is executing, including the last known-good version when a newer source fails compilation. Changes become visible after watch processing and successful installation. Full mode can disclose policy templates, inline inputs, and other sensitive configuration; use it only from trusted operator workstations.

## Errors and limits

| Request | Status and response |
| --- | --- |
| `PUT`, `DELETE`, or another unsupported method on `/debug/profiles` | `405` JSON `{"error":"method not allowed; use GET or POST"}` and `Allow: GET, POST` |
| Labels supplied without `namespace` | `400` JSON error |
| Malformed POST JSON | `400` JSON error |
| POST body larger than 1 MiB | `400` JSON error from the request decoder |
| Invalid logging configuration or PUT body larger than 4 KiB on `/debug/logging` | `400` JSON error; current level is unchanged |
| Unsupported method on `/debug/logging` | `405` JSON error and `Allow: GET, HEAD, PUT` |
| Unknown path, or debug path while disabled | `404` |

The API exposes profile selectors, ordering, and, in full mode, complete policy specifications. It also permits runtime log-level changes, which can increase log volume or suppress diagnostics. Do not set `--admin-addr=:15000` or any other non-loopback address without restrictive NetworkPolicies, service exposure controls, and authentication in an enclosing trusted boundary. The server itself provides no authentication or authorization.

## See also

- [EPE configuration](epe-configuration.md)
- [EPE observability](epe-observability.md)
