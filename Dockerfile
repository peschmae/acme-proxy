# syntax=docker/dockerfile:1

# Build stage runs on the build host's architecture and cross-compiles for the
# target, so multi-arch images don't need emulation. CGO is required by
# go-sqlite3; the binary is linked statically to run on distroless/static.
FROM --platform=$BUILDPLATFORM golang:1.27-trixie AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src

RUN set -eux; \
    if [ "$TARGETARCH" = "$(dpkg --print-architecture)" ]; then \
      echo gcc > /cc; \
    else \
      case "$TARGETARCH" in \
        amd64) pkg=gcc-x86-64-linux-gnu; cc=x86_64-linux-gnu-gcc ;; \
        arm64) pkg=gcc-aarch64-linux-gnu; cc=aarch64-linux-gnu-gcc ;; \
        *) echo "unsupported TARGETARCH $TARGETARCH" >&2; exit 1 ;; \
      esac; \
      apt-get update; \
      apt-get install -y --no-install-recommends "$pkg" "libc6-dev-${TARGETARCH}-cross"; \
      rm -rf /var/lib/apt/lists/*; \
      echo "$cc" > /cc; \
    fi

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS="$TARGETOS" GOARCH="$TARGETARCH" CC="$(cat /cc)" \
    go build -trimpath \
      -tags 'netgo osusergo sqlite_omit_load_extension' \
      -ldflags '-s -w -linkmode external -extldflags "-static"' \
      -o /out/acme-proxy . \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/acme-proxy /usr/local/bin/acme-proxy
COPY --from=build --chown=65532:65532 /out/data /data
ENV ACME_PROXY_LISTEN=:8443 \
    ACME_PROXY_STATE_DIR=/data
EXPOSE 8443
VOLUME ["/data"]
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/acme-proxy"]
