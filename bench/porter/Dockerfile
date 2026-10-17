# Copyright 2026 The Kruise Authors
# SPDX-License-Identifier: Apache-2.0
FROM golang:1.26.8-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY api/ api/
COPY pkg/ pkg/
COPY bench/load/ bench/load/
COPY bench/porter/load/ bench/porter/load/
RUN CGO_ENABLED=0 go build -o /out/bench ./bench/porter/load

FROM scratch AS bench
COPY --from=build /out/bench /bench
ENTRYPOINT ["/bench"]
