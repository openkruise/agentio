# SecurityProfile status

agentiod writes `.status` on every SecurityProfile. Only the elected leader for
a revision writes, and writing can be turned off entirely with
`ENABLE_SECURITY_PROFILE_STATUS=false`.

| Condition | True means |
| --- | --- |
| `Accepted` | The spec is self-consistent: every regex, CEL expression and Go template compiles, and rule names are unique. |
| `ResolvedRefs` | Every `credentialRef` with `kind: Secret` points at a Secret that exists in the profile's own namespace. |
| `Programmed` | The profile was accepted. This follows `Accepted` only and is not a confirmation that the data plane has loaded the profile. |

## Known limitations

- An unresolved `credentialRef` sets `ResolvedRefs=False` but leaves
  `Programmed=True`. `ResolvedRefs` carries reference problems on its own.
- The Secret informer honours `RESTRICTED_SECRETS_SCOPE`. The chart sets it to
  the control plane namespace by default (`agentiod.restrictedSecretsScope`), so
  a `credentialRef` in any other namespace reports `SecretNotFound`. Set
  `agentiod.restrictedSecretsScope=false` to watch secrets cluster-wide.
- Only the existence of a referenced Secret is checked. Whether it carries the
  data keys a transformation needs (`apiKey`, or `accessKeyId` /
  `accessKeySecret` / `securityToken`) is enforced by traffic-extension at
  request time.
- String leaves inside `audit[].webhook.request.body.json` are rendered as Go
  templates by the data plane but are not validated by the control plane.
  `body.text`, header values and the webhook URL are validated.
