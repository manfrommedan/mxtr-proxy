# syntax=docker/dockerfile:1.6

# ---------- Build stage ----------
FROM golang:1.26-alpine AS builder
WORKDIR /src

# Cache modules separately for faster rebuilds.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
        -trimpath \
        -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/mxtr-server \
        ./cmd/mxtr-server

# ---------- Runtime stage ----------
# Distroless — no shell, no apt, ~2 MB base. Runs as non-root by default.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/mxtr-server /usr/local/bin/mxtr-server

# Default listener; override via `docker run -p host:9290:9290/tcp` for remap.
EXPOSE 9290/tcp

# PSK preferred via -psk-file pointing at a volume-mounted file under
# /state. Env MXTR_PSK still works (overrides file). On first run with
# empty file the server auto-generates and persists; restart re-uses.
ENV MXTR_PSK=""

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/mxtr-server"]
# Default flags. Operator overrides with -public-ip <IP> in compose / run.
# -psk-file points at the recommended volume-mount location.
CMD ["-tcp", ":9290", "-log-level", "info", "-psk-file", "/state/psk.hex"]
