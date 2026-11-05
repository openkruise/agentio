# syntax=docker/dockerfile:1

# BASE_DISTRIBUTION switches between the debug and distroless runtime images.
ARG BASE_DISTRIBUTION=debug

# Agentio does not publish paired base images under a shared version, so each
# runtime image is pinned directly to an immutable multi-platform digest.
ARG BASE_IMAGE=gcr.io/distroless/static-debian12:debug-nonroot@sha256:d5563cc7f2f44313f332e91138cc8c6a158899afeeeab2fce3b0f9ccdb3cf9ee
ARG DISTROLESS_IMAGE=gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG TRUST_PACKAGE_IMAGE=quay.io/jetstack/trust-pkg-debian-bookworm:20250419-deb12u2.1@sha256:4965dedbe4f54e19af0eae7fafe2c7be54a0bde257e5130c93401a6d5f9489f6

FROM ${TRUST_PACKAGE_IMAGE} AS trust-package

FROM --platform=$BUILDPLATFORM golang:1.27.3 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build -trimpath -ldflags='-s -w' -o /out/agentiod ./cmd/agentiod

# The following section is used when BASE_DISTRIBUTION=debug.
FROM ${BASE_IMAGE} AS debug

# The following section is used when BASE_DISTRIBUTION=distroless.
FROM ${DISTROLESS_IMAGE} AS distroless

# Build the final image from the selected runtime stage.
# hadolint ignore=DL3006
FROM ${BASE_DISTRIBUTION:-debug}

COPY --from=builder /out/agentiod /usr/local/bin/agentiod
COPY --from=trust-package /debian-package/ /usr/local/share/agentio/trust-package/
USER 1337:1337
ENTRYPOINT ["/usr/local/bin/agentiod"]
