# syntax=docker/dockerfile:1
# build context: repo root (..), not helios/

FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache gcc musl-dev

ARG SERVICE=hermes

COPY helios/go.work ./
COPY helios/proto/go.mod helios/proto/go.sum ./proto/
COPY helios/pkg/go.mod helios/pkg/go.sum ./pkg/
COPY helios/hermes/go.mod helios/hermes/go.sum ./hermes/
COPY helios/aegis/go.mod helios/aegis/go.sum ./aegis/
COPY helios/zwei/go.mod helios/zwei/go.sum ./zwei/
COPY helios/chaos/go.mod helios/chaos/go.sum ./chaos/
COPY aegis-go/guard/go.mod aegis-go/guard/go.sum /aegis-go/guard/
COPY aegis-go/service/go.mod aegis-go/service/go.sum /aegis-go/service/
COPY aegis-go/utilities/go.mod aegis-go/utilities/go.sum /aegis-go/utilities/

RUN --mount=type=cache,target=/go/pkg/mod \
    (cd proto && go mod download) && \
    (cd pkg && go mod download) && \
    (cd hermes && go mod download) && \
    (cd aegis && go mod download) && \
    (cd zwei && go mod download) && \
    (cd chaos && go mod download) && \
    (cd /aegis-go/guard && go mod download) && \
    (cd /aegis-go/service && go mod download) && \
    (cd /aegis-go/utilities && go mod download)

COPY helios/proto/ ./proto/
COPY helios/pkg/ ./pkg/
COPY helios/hermes/ ./hermes/
COPY helios/aegis/ ./aegis/
COPY helios/zwei/ ./zwei/
COPY helios/chaos/ ./chaos/
COPY aegis-go/guard/ /aegis-go/guard/
COPY aegis-go/service/ /aegis-go/service/
COPY aegis-go/utilities/ /aegis-go/utilities/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ "${SERVICE}" = "aegis" ]; then \
      cd aegis && CGO_ENABLED=1 go build -ldflags="-s -w" -o /server ./server; \
    else \
      cd ${SERVICE} && CGO_ENABLED=1 go build -ldflags="-s -w" -o /server .; \
    fi

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 app

WORKDIR /app

COPY --from=builder /server .

ARG ENV=""
ENV APP_ENV=${ENV}

USER app

EXPOSE 18000 50051

CMD ["./server"]
