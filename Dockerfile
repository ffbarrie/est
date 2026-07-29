# syntax=docker/dockerfile:1

# Pin to the exact Go version in go.mod; bump both together.
#
# --platform=$BUILDPLATFORM pins the build stage to the builder's native
# platform even when producing a foreign-arch image (e.g. building
# linux/arm64 on an amd64 CI runner): Go cross-compiles via GOOS/GOARCH
# below with no emulation needed, which is faster and more reliable than
# running the whole toolchain under QEMU.
FROM --platform=$BUILDPLATFORM golang:1.26.5-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/estd ./cmd/estd

# distroless "nonroot" runs as uid/gid 65532 by default, has no shell, no
# package manager — matches this project's "minimal attack surface, no
# unnecessary tooling" posture already applied to the Go code itself.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/estd /usr/local/bin/estd
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/estd"]
CMD ["-config", "/etc/estd/config.json"]
