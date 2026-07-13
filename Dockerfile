# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src

RUN apk add --no-cache gcc musl-dev

ARG SERVICE=hermes

COPY go.work ./
COPY proto/go.mod proto/go.sum ./proto/
COPY pkg/go.mod pkg/go.sum ./pkg/
COPY hermes/go.mod hermes/go.sum ./hermes/
COPY aegis/go.mod aegis/go.sum ./aegis/
COPY zwei/go.mod zwei/go.sum ./zwei/
COPY chaos/go.mod chaos/go.sum ./chaos/

RUN --mount=type=cache,target=/go/pkg/mod \
    (cd proto && go mod download) && \
    (cd pkg && go mod download) && \
    (cd hermes && go mod download) && \
    (cd aegis && go mod download) && \
    (cd zwei && go mod download) && \
    (cd chaos && go mod download)

COPY proto/ ./proto/
COPY pkg/ ./pkg/
COPY hermes/ ./hermes/
COPY aegis/ ./aegis/
COPY zwei/ ./zwei/
COPY chaos/ ./chaos/

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    if [ "${SERVICE}" = "aegis" ]; then \
      cd aegis && CGO_ENABLED=1 go build -ldflags="-s -w" -o /server .; \
    else \
      cd ${SERVICE} && CGO_ENABLED=1 go build -ldflags="-s -w" -o /server .; \
    fi

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 1000 app

WORKDIR /app

COPY --from=builder /server .

RUN mkdir -p aegis hermes zwei chaos

ARG ENV=""
ENV APP_ENV=${ENV}

USER app

EXPOSE 18000 50051

CMD ["./server"]
