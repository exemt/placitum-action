# Контекст сборки -- корень репозитория: модуль Go самостоятелен и ничего
# выше по дереву не берёт. Отсюда же сборка прямо из git, без клона.
#
#     docker build -f deploy/Dockerfile -t placitum/action .
#     docker buildx build -f deploy/Dockerfile -t placitum/action \
#         "https://github.com/exemt/placitum-action.git#develop"

FROM golang:1.25-alpine AS build

WORKDIR /src

# Прокси модулей -- аргументом: в изолированном контуре подставляют своё зеркало.
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=${GOPROXY}

# Зависимости отдельным слоем: они меняются на порядок реже кода.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

# CGO не нужен: NATS, Redis, gRPC и разбор YAML -- чистый Go. Отсюда и
# статический бинарник, и возможность собрать образ без libc.
ENV CGO_ENABLED=0

# Тесты в сборке, как у остальных инспекторов: образ, который собрался с
# красными тестами, всё равно нельзя ставить, а узнать об этом на стенде
# дороже, чем здесь.
RUN go test ./...

RUN go build -trimpath -ldflags="-s -w" -o /out/action ./cmd/inspector

FROM alpine:3.22

# Версия и ревизия приходят снаружи: .git в контекст сборки не попадает
# (BuildKit его вырезает), поэтому сам себя образ подписать не может.
ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.title="placitum/action" \
      org.opencontainers.image.description="WAF action inspector: sender of the action channel" \
      org.opencontainers.image.source="https://github.com/exemt/placitum-action" \
      org.opencontainers.image.licenses="LicenseRef-Placitum" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app

COPY --from=build /out/action /usr/local/bin/
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

# CMD, а не ENTRYPOINT: как у остальных инспекторов, и `docker run <образ> sh`
# остаётся рабочим способом заглянуть внутрь.
CMD ["action"]
