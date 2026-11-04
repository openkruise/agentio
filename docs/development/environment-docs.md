# Generate environment variable documentation

The `agentiod` and Egress Policy Enforcer (EPE) environment variable reference tables are generated from `istio.io/istio/pkg/env` registrations, using the same `env.VarDescriptions()` registry as the CLI output. To add or update a variable, edit the owning package's `env.Register` call.

Generate the tables, then verify them:

```sh
make gen.envdocs
make check.envdocs
```

`make gen.envdocs` is the primary entry point: it regenerates the environment tables. `make check.envdocs` verifies the generated output matches the registrations, and CI runs it to catch drift. `make gen` also regenerates these tables, but only as part of a broader regeneration. Commit the generated document changes together with the registration changes.

The generator builds both binaries with the repository's Go toolchain and invokes `-print-env -print-env-format=markdown` in a clean environment. It exits before logging setup, Kubernetes client creation, and server startup. Only the regions between the generated environment markers are replaced; usage instructions and Helm examples remain hand-written.

Markdown output covers `AGENTIO_*` for `agentiod` and `IDENTITY_PROVIDER_*`, `TOKEN_CACHE_*`, `STS_CACHE_*`, `CREDENTIAL_PROVIDER_*`, `HTTP_CALLOUT_*`, and `AUDIT_WEBHOOK_*` for EPE. Extend the command's prefix selection when introducing a new family of documented settings. Plain `-print-env` lists every visible registration, including dependencies; shared packages may register settings that a particular binary does not consume.

Types and defaults come from registration metadata, not current environment values or Helm values. Hidden variables are omitted and deprecated variables are marked. For CPU-dependent defaults such as `AGENTIO_PUSH_CONCURRENCY`, the Markdown exporter replaces the machine-specific number with a reference to the registration's description; keep that description consistent with the calculation. Text output retains the binary's calculated default.

Settings read through `os.Getenv` without registration are outside this mechanism. Helm mappings, runtime resolution rules, and configuration examples belong in the surrounding reference prose.
