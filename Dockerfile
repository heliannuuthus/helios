# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    apk add --no-cache gcc musl-dev && \
    (cd proto && go mod download) && \
    (cd pkg && go mod download) && \
    (cd hermes && go mod download) && \
    (cd aegis && go mod download) && \
    (cd zwei && go mod download) && \
    (cd chaos && go mod download) && \
    mkdir -p /out && \
    for service in hermes aegis zwei chaos; do \
      (cd "${service}" && CGO_ENABLED=1 go build -ldflags="-s -w" -o "/out/${service}" .); \
    done

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 app && \
    mkdir -p /app/aegis /app/hermes /app/zwei /app/chaos && \
    chown -R app:app /app

WORKDIR /app

ARG SERVICE=hermes
COPY --from=builder /out/${SERVICE} ./server

ARG ENV=""
ENV APP_ENV=${ENV}

USER app

EXPOSE 18000 50051

CMD ["./server"]
