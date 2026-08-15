# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build

RUN apk add --no-cache git ca-certificates

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=v0.0.0

WORKDIR /src
ENV GOPRIVATE=github.com/hanzoai/*,github.com/luxfi/*,github.com/zap-proto/*
COPY go.mod go.sum ./
RUN --mount=type=secret,id=gh_token \
    if [ -s /run/secrets/gh_token ]; then \
      git config --global url."https://x-access-token:$(cat /run/secrets/gh_token)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download

COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-w -s" -o /egress ./cmd/egress

# The runtime holds a live credential in memory, so it carries nothing that
# could read it out: no shell, no package manager, no utilities. `kubectl exec`
# into this image has nothing to run. Certificates are the only thing copied in,
# because talking to a vendor over TLS is the job.
FROM scratch

LABEL org.opencontainers.image.source="https://github.com/hanzoai/egress"
LABEL org.opencontainers.image.title="Hanzo Egress"
LABEL org.opencontainers.image.description="The outbound trust boundary: callers ask for a call, egress holds the credential"

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /egress /egress

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/egress"]
