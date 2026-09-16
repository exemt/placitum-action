FROM golang:1.25-alpine AS build

WORKDIR /src

ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0

ARG VERSION=dev
ARG REVISION=unknown
RUN go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/action ./cmd/inspector && \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION}" -o /out/action-probe ./cmd/probe

FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/action" \
      org.opencontainers.image.description="WAF action inspector: sender of the action channel" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-action" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/action /out/action-probe /usr/local/bin/
COPY profiles ./profiles
COPY inspector.conf ./inspector.conf

RUN adduser -D -H -u 10001 action && \
    mkdir -p /var/lib/waf/action && \
    chown -R action:action /app /var/lib/waf
USER action

ENV NATS_URL=nats://nats:4222 \
    WAF_ACTION_SUBJECT=waf.req.action \
    WAF_ACTION_NAME=action \
    WAF_ACTION_PROFILES=/app/profiles \
    WAF_ACTION_DATA=/var/lib/waf/action \
    WAF_ACTION_LOG=info

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["action-probe", "--quiet", "--timeout", "1s"]
CMD ["action"]
