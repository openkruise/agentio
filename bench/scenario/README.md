# Reproducible test scenarios

`bench/scenario` is a Go execution framework for assertion-based scenarios. It runs test programs on the host or in isolated Docker containers, enforces deadlines, preserves evidence, and returns failure if any case or container cleanup fails. It is shared infrastructure: protocol-specific traffic generators and assertions stay in their own packages.

The first consumer is [CONNECT/network limits](../connect/README.md#stability-scenarios). Existing Porter, xDS and other Go runners can be invoked as host commands without rewriting their clients. This framework does not replace `bench/load` scheduling or the existing benchmark statistics.

## Scenario contract

Write a Go test (or a Go program) that owns:

1. Setup: start an origin/proxy or create the resources needed by the scenario. Register cleanup immediately with `t.Cleanup`.
2. Workload: use the existing protocol client and explicit, recorded parameters.
3. Assertions: check observable behavior, such as data integrity, bounded progress gaps, admission after policy updates, or resource recovery. Sending traffic successfully is not sufficient.
4. Teardown: close connections and stop owned services; teardown errors fail the test too.

Register that program as a `scenario.Case`. Its exit status is authoritative. Set `SuccessMarker` when invoking a selected Go test so a typo, old binary, or skipped test cannot yield an empty success. Emit the marker in a cleanup registered *before* resource cleanup, guarded by `!t.Failed()`; it will run last.

The framework runs cases sequentially, continues collecting evidence after a case fails, and exits nonzero if any failed. Parent cancellation stops the suite. On timeout, the host executor kills the process group; the Docker executor records container state and force-removes its own container. Host scenarios must manage external resources themselves: killing a process cannot delete Kubernetes objects. Keep those resources scoped to a disposable namespace and provide explicit teardown in the scenario. Docker execution removes the complete local fixture even if Go cleanup cannot run after a timeout.

Host execution supports Linux and macOS. Docker cases need a local Docker daemon; remote Docker bind mounts refer to the daemon host. Never put credentials in a plan's environment: the plan and container metadata are saved as artifacts.

## Run and replay

A suite can be constructed in Go and passed to `scenario.Run`, as in [`bench/connect/scenarios`](../connect/scenarios/main.go), or loaded from JSON:

```sh
go run ./bench/scenario/run \
  -suite /tmp/my-scenarios.json \
  -output /tmp/my-scenario-results
```

Example host suite (the `dir` must be an absolute checkout path):

```json
{
  "name": "runner-regression",
  "cases": [
    {
      "name": "failure-and-timeout-contract",
      "dir": "/path/to/agentio",
      "command": ["go", "test", "-count=1", "-v", "./bench/scenario", "-run", "^TestRunFailureTimeoutAndEvidence$"],
      "timeout": "2m"
    }
  ]
}
```

For Docker, add `image`, use a command inside that image, and optionally specify `user` (a Docker UID:GID override), `memory` (for example `12g`) and read-only `mounts` with absolute `source`/`target`. `dir` then refers to the container working directory. Commands are argv arrays; the framework never expands them through a shell. `SCENARIO_ARTIFACTS` points to the writable case directory (or `/artifacts` in Docker). Command arguments and environment values can use `{artifacts}` to pass this location to an existing runner.

Each invocation requires a **new output directory outside the checkout**, whose parent already exists. Outputs include:

- `suite.json`: resolved command, parameters, paths, and environment for replay.
- `results.json`: pass/fail, elapsed time, timestamp, and errors, updated after every case.
- `<case>/test.log`: complete program output.
- `<case>/container.json`: Docker state, image ID and exit/OOM state, saved before cleanup.
- Any additional files the scenario writes to its artifact directory.

Replay the saved suite with the same runner and a new output directory. Preserve the input executables, mounted modules, checkout revision and image: `suite.json` references them; it does not copy arbitrary mounted trees or rebuild old code. Prefer immutable image IDs/digests for comparisons. A missing or changed input is not an equivalent replay.

## Validate the framework

```sh
go test -race ./bench/scenario/...
SCENARIO_TEST_IMAGE=agentio-network-limits:test go test -v ./bench/scenario
```

The optional Docker contract test verifies a successful command, a failed command, timeout handling, saved container state and removal. The image must provide `/bin/sh` and `sleep`. These are runner-contract tests; they do not claim anything about network-limit correctness.
