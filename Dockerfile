# syntax=docker/dockerfile:1

# Pin to the exact Go version in go.mod; bump both together.
FROM golang:1.26.5-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/estd ./cmd/estd

# distroless "nonroot" runs as uid/gid 65532 by default, has no shell, no
# package manager — matches this project's "minimal attack surface, no
# unnecessary tooling" posture already applied to the Go code itself.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/estd /usr/local/bin/estd
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/estd"]
CMD ["-config", "/etc/estd/config.json"]
