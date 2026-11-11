ARG BUILDPLATFORM=linux/amd64
# Stage 1: Build the statically linked Go binary natively on host platform
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS builder

WORKDIR /build

RUN apk add --no-cache ca-certificates tzdata

# Create an unprivileged user in a custom passwd file
RUN echo "netcheck:x:10001:10001:netcheck:/:/sbin/nologin" > /passwd.netcheck

# Cache Go modules dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy application source tree
COPY . .

# Target OS and Architecture automatically passed by Buildx
ARG TARGETOS TARGETARCH

# Build 100% statically linked stripped binary with embedded frontend (pure cross-compilation)
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -ldflags="-s -w" -trimpath -o netcheck .

# Stage 2: Ultra-minimal hardened scratch runtime
FROM scratch

LABEL org.opencontainers.image.title="NetCheck" \
      org.opencontainers.image.description="Self-hosted network diagnostic toolkit" \
      org.opencontainers.image.url="https://netcheck.nnt25.io.vn" \
      org.opencontainers.image.source="https://github.com/sudo-Penguin-Lalala/netcheck" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Import SSL root certificates and unprivileged user definition from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /passwd.netcheck /etc/passwd

# Copy the single self-contained binary
COPY --from=builder /build/netcheck /netcheck

USER 10001

EXPOSE 7070

ENTRYPOINT ["/netcheck"]
