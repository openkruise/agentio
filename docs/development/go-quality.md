# Go quality checks

`make lint` also runs `cargo fmt --check` and `cargo clippy` for Porter, so it requires the Rust toolchain and Clippy as well as Go. It checks Go layout on changed lines and runs `go vet` for the main module and the e2e module. `make lint.golangci` runs the pinned golangci-lint version from the Makefile against both modules, using `.golangci.yml`. It includes error checking, exported API documentation, duplication, complexity, `modernize` suggestions, import formatting, and `golines` with a target line length of 120 columns (tabs count as four columns).

Generated files are excluded. Test code follows the same layout, formatting, and modernization rules, but remains exempt from documentation, duplication, and complexity checks. `modernize` checks language and standard-library improvements supported by the module's Go version; linting does not apply its fixes.

The layout checker uses only the Go standard library and enforces three conventions: each field of a multiline keyed literal occupies its own line, each struct field is declared separately, and separate statements in a block occupy separate lines. Short single-line literals, grouped function parameters, and semicolons in `if`/`for` headers are allowed. Multiline keyed maps follow the same layout rule as struct literals.

`make lint.style` checks staged, unstaged, and untracked Go changes relative to `HEAD`, including the nested e2e module. To include committed branch changes, set `GO_STYLE_BASE`. Explicit file arguments to `go run ./tools/gostyle path/to/file.go` check every line of those files.

The full golangci-lint audit currently contains historical findings. To check changes relative to a known base:

```sh
make lint GO_STYLE_BASE=<base-commit>
make lint.golangci GOLANGCI_LINT_ARGS="--new-from-rev=<base-commit>"
```

CI uses the pull request base or the previous push commit for both incremental checks. Thus a long-lived feature branch can still report findings from earlier commits on that branch; this is not a clean baseline for the entire branch. New rules do not replace the existing full-module `go vet` gate.

`make fmt` applies `goimports` and `golines` to the repository, including the e2e module, while excluding generated files. Use `FMT_PATHS` to limit Go formatting to selected files or directories. `make fmt` still runs `cargo fmt` for all of Porter regardless of `FMT_PATHS`:

```sh
make fmt FMT_PATHS="pkg/policy/authorization.go tools/gostyle"
```

`golines` wraps code where possible; it does not guarantee that long string literals or comments fit within 120 columns. Comments and struct tags are not rewritten. The three layout conventions still need the dedicated checker because a short line can contain multiple fields or statements. Expand those manually and then run `make fmt`.

An installed binary can be used with `GOLANGCI_LINT=golangci-lint`. Configuration uses the [golangci-lint v2 schema](https://golangci-lint.run/docs/configuration/file/).

## Equality benchmarks

```sh
go test ./pkg/model -run '^$' -bench BenchmarkModelEquals -benchmem -count=3
```

The fixtures use independently allocated equal objects to model an unchanged
informer update. The Workload, Sandbox, and Service comparisons preserve field
order where applicable and distinguish nil from empty maps and slices. Their
field-coverage tests also fail when a new field is added but omitted from Equals.

These microbenchmarks measure equality costs, not end-to-end KRT throughput.
TrafficPolicy, SecurityProfile, and Telemetry retain their existing comparisons;
changing their nested specifications requires separate profiling and semantic
coverage.

Measured on Apple M4, darwin/arm64, Go 1.26.5 (median of three runs):

| Equal, independently allocated objects | Before (ns/op) | After (ns/op) | Allocations before → after |
| --- | ---: | ---: | ---: |
| Workload | 547.4 | 73.73 | 11 → 0 |
| Sandbox | 417.1 | 60.12 | 11 → 0 |
| Service | 279.6 | 18.01 | 2 → 0 |
