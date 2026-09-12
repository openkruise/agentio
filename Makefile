.PHONY: build build.agentiod build.epe clean fmt format gen gen.crddocs gen.envdocs check.envdocs lint lint.golangci lint.logging racetest test test.epe test.integration.agentio.kube test.integration.agentio.product tidy

build: build.agentiod build.epe

build.agentiod:
	mkdir -p out
	go build -trimpath -o out/agentiod ./cmd/agentiod

build.epe:
	mkdir -p out
	go build -trimpath -o out/epe ./extensions/epe/cmd/epe

test.epe:
	go test ./extensions/epe/...

test:
	go test ./...
	go -C test/e2e test ./...

test.integration.agentio.kube:
	@for tool in docker kind kubectl helm; do \
		command -v $$tool >/dev/null || { echo "required integration test tool '$$tool' is unavailable" >&2; exit 1; }; \
	done
	E2E_FRAMEWORK_SMOKE=1 go -C test/e2e test ./suites/framework -run '^TestFrameworkSmoke$$' -v -count=1

AGENTIO_E2E_ARGS ?=

test.integration.agentio.product:
	go -C test/e2e run ./cmd/product-e2e run $(AGENTIO_E2E_ARGS)

.PHONY: test.integration.agentio.plan
test.integration.agentio.plan:
	go -C test/e2e run ./cmd/product-e2e plan $(AGENTIO_E2E_ARGS)

# The control plane runs a goroutine per collection, per handler registration and
# per xDS stream, so the race detector is part of the normal gate rather than an
# occasional extra.
racetest:
	go test -race -count=1 ./...
	go -C test/e2e test -race -count=1 ./...

# Keep the analyzer compatible with the Go version in go.mod. Override the command
# to use an installed binary; pass --new-from-rev=<base> for incremental checks.
GOLANGCI_LINT_VERSION := v2.13.2
GOLANGCI_LINT ?= go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
GOLANGCI_LINT_ARGS ?=

lint.golangci:
	$(GOLANGCI_LINT) run $(GOLANGCI_LINT_ARGS) ./...

lint:
	go vet ./...
	go -C test/e2e vet ./...

# The logging convention check runs in its own workflow with path filters.
# Called without an argument it resolves the merge base itself.
lint.logging:
	./bin/lint_logging.sh

gen:
	./tools/generate-proto.sh
	./tools/generate-crd-docs.sh
	$(MAKE) gen.envdocs

gen.crddocs:
	./tools/generate-crd-docs.sh

gen.envdocs:
	go run ./tools/envdocs

check.envdocs:
	go run ./tools/envdocs -check

format: fmt

fmt:
	go fmt ./...
	go -C test/e2e fmt ./...

tidy:
	go mod tidy
	go -C test/e2e mod tidy

clean:
	rm -rf out
