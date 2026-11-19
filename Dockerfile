# syntax=docker/dockerfile:1

# BASE_DISTRIBUTION switches between the debug and distroless runtime images.
ARG BASE_DISTRIBUTION=debug

# Agentio does not publish paired base images under a shared version, so each
# runtime image is pinned directly to an immutable multi-platform digest.
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:debug-nonroot@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee
ARG DISTROLESS_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

FROM --platform=$BUILDPLATFORM golang:1.27.4 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags='-s -w' -o /out/agentiod ./cmd/agentiod

ADD --checksum=sha256:427c064216761a1e72a8b30f0d954d08cb6e4435a82091fb865afd20c8497285 https://curl.se/ca/cacert-2026-11-05.pem /tmp/
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go run ./tools/public-ca-package /tmp/cacert-*.pem > /out/cert-manager-package-debian.json

# The following section is used when BASE_DISTRIBUTION=debug.
FROM ${BASE_IMAGE} AS debug

# The following section is used when BASE_DISTRIBUTION=distroless.
FROM ${DISTROLESS_IMAGE} AS distroless

# Build the final image from the selected runtime stage.
# hadolint ignore=DL3006
FROM ${BASE_DISTRIBUTION:-debug}

COPY --from=builder /out/agentiod /usr/local/bin/agentiod
COPY --from=builder /out/cert-manager-package-debian.json /usr/local/share/agentio/trust-package/
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/agentiod"]
