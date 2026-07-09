SHELL := /bin/zsh
export PATH := $(HOME)/.asdf/shims:$(HOME)/.go/bin:$(HOME)/.cargo/bin:$(PATH)

.PHONY: all build run test lint fmt generate proto swag clean help tidy \
       up down logs ps dev dev-down dev-ps dev-check reset

SERVICES := hermes aegis zwei chaos
MODULES  := proto pkg $(SERVICES)

ifneq ($(CONTAINER_RUNTIME),)
CTR := $(CONTAINER_RUNTIME)
else ifneq ($(shell command -v nerdctl 2>/dev/null),)
CTR := nerdctl
else
CTR := docker
endif

COMPOSE      := $(CTR) compose
COMPOSE_FULL := $(COMPOSE) -f compose.yaml -f compose.full.yaml
COMPOSE_DEV  := $(COMPOSE) -f compose.yaml -f compose.dev.yaml

CERTS    := environments/certs/fullchain.pem
PRIVKEY  := environments/certs/privkey.pem
CERT_DIR := environments/certs
DOMAINS  := aegis.heliannuuthus.com hermes.heliannuuthus.com zwei.heliannuuthus.com chaos.heliannuuthus.com atlas.heliannuuthus.com iris.heliannuuthus.com

DEV_PID := .dev/pids

VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date +%Y%m%d)
IMAGE_TAG  := $(VERSION)-$(BUILD_DATE)
LDFLAGS    := -ldflags="-s -w -X main.Version=$(VERSION)"

ifeq ($(filter run build,$(firstword $(MAKECMDGOALS))),$(firstword $(MAKECMDGOALS)))
  SERVICE := $(word 2,$(MAKECMDGOALS))
  ifneq ($(SERVICE),)
    $(eval $(SERVICE):;@:)
  endif
endif

# ── build ────────────────────────────────────────────

all: generate build

tidy:
	@for m in $(MODULES); do (cd $$m && go mod tidy); done

build:
ifdef SERVICE
ifeq ($(SERVICE),aegis)
	cd aegis && go build $(LDFLAGS) -o ../bin/aegis .
else
	cd $(SERVICE) && go build $(LDFLAGS) -o ../bin/$(SERVICE) .
endif
else
	cd hermes && go build $(LDFLAGS) -o ../bin/hermes .
	cd aegis && go build $(LDFLAGS) -o ../bin/aegis .
	cd zwei && go build $(LDFLAGS) -o ../bin/zwei .
	cd chaos && go build $(LDFLAGS) -o ../bin/chaos .
endif

run: build
	./bin/$(SERVICE)

test:
	@for m in $(MODULES); do (cd $$m && go test ./...); done

lint:
	@for m in $(MODULES); do (cd $$m && golangci-lint run --fix ./...); done

fmt:
	@for m in $(MODULES); do (cd $$m && go fmt ./...); done

# ── codegen ──────────────────────────────────────────

generate: proto swag

proto:
	cd proto/proto && buf generate

swag:
	go install github.com/swaggo/swag/cmd/swag@latest
	cd zwei && swag init --parseDependency --parseInternal --generalInfo main.go --output ../docs

check-generate: generate
	@if [ -n "$$(git status --porcelain proto/gen/)" ]; then \
		echo "生成的代码有变更，请先运行 make generate 并提交"; \
		git diff proto/gen/; \
		exit 1; \
	fi

clean:
	rm -rf bin/ coverage.out dist/

# ── docker build ─────────────────────────────────────

docker-build:
ifdef SERVICE
	$(CTR) build -f Dockerfile --build-arg SERVICE=$(SERVICE) -t $(SERVICE):$(IMAGE_TAG) -t $(SERVICE):latest .
else
	@$(foreach svc,$(SERVICES),$(CTR) build -f Dockerfile --build-arg SERVICE=$(svc) -t $(svc):$(IMAGE_TAG) -t $(svc):latest . &&) true
endif

# ── dev-check ────────────────────────────────────────

dev-check:
	@set -e; \
	log() { echo "[dev-check] $$*"; }; \
	if [ -f "$(CERTS)" ] && [ -f "$(PRIVKEY)" ]; then \
		log "SSL 证书 OK: $(CERTS)"; \
		openssl x509 -in "$(CERTS)" -noout -subject -dates 2>/dev/null || true; \
	else \
		command -v mkcert >/dev/null || { log "ERROR: 未找到 mkcert"; exit 1; }; \
		mkdir -p "$(CERT_DIR)"; \
		log "SSL 证书缺失，正在生成..."; \
		cd "$(CERT_DIR)" && mkcert -install && mkcert -ecdsa -cert-file fullchain.pem -key-file privkey.pem $(DOMAINS); \
		log "SSL 证书已写入: $(CERTS) $(PRIVKEY)"; \
		openssl x509 -in fullchain.pem -noout -subject -dates; \
	fi; \
	missing=""; \
	for d in $(DOMAINS); do \
		grep -Eq "[[:space:]]$$d([[:space:]]|$$)" /etc/hosts 2>/dev/null || missing="$$missing $$d"; \
	done; \
	if [ -z "$$missing" ]; then \
		log "/etc/hosts OK"; \
	else \
		line="127.0.0.1 $(DOMAINS)"; \
		log "/etc/hosts 缺少域名，正在写入:$$missing"; \
		if [ -w /etc/hosts ]; then echo "$$line" >> /etc/hosts; else echo "$$line" | sudo tee -a /etc/hosts >/dev/null; fi; \
		log "/etc/hosts 已更新"; \
	fi; \
	log "环境校验完成"

# ── full (全容器) ────────────────────────────────────

up: dev-check
	@command -v $(CTR) >/dev/null || { echo "[up] ERROR: 未找到 $(CTR)"; exit 1; }
	@$(CTR) info >/dev/null 2>&1 || { echo "[up] ERROR: $(CTR) daemon 未运行"; exit 1; }
	$(COMPOSE_FULL) up --build -d
	@echo ""
	@echo "Helios 已启动: https://aegis.heliannuuthus.com"
	@echo "直连: aegis :18000 | hermes :8081/:50051 | zwei :18001 | chaos :18002"

down:
	-$(COMPOSE_FULL) down
	-$(COMPOSE_DEV) down

reset:
	@echo "[reset] 停止容器并删除数据卷（MySQL + Redis 数据全部清空）"
	-$(COMPOSE_FULL) down -v
	-$(COMPOSE_DEV) down -v
	-$(COMPOSE) down -v
	@echo "[reset] 完成，下次 make dev/up 会重新初始化数据库"

logs:
	$(COMPOSE_FULL) logs -f

ps:
	$(COMPOSE_FULL) ps

# ── dev (容器基础组件 + 本地进程) ────────────────────

dev: dev-check build
	@command -v $(CTR) >/dev/null || { echo "[dev] ERROR: 未找到 $(CTR)"; exit 1; }
	@$(CTR) info >/dev/null 2>&1 || { echo "[dev] ERROR: $(CTR) daemon 未运行"; exit 1; }
	@echo "[dev] 启动 db + cache"
	@$(COMPOSE) up -d
	@set -e; \
	wait_mysql() { i=0; while [ $$i -lt 60 ]; do $(CTR) exec helios-db mysqladmin ping -h127.0.0.1 -uroot -proot --silent >/dev/null 2>&1 && return 0; i=$$((i+1)); sleep 0.5; done; return 1; }; \
	wait_redis() { i=0; while [ $$i -lt 30 ]; do $(CTR) exec helios-cache redis-cli -a helios ping 2>/dev/null | grep -q PONG && return 0; i=$$((i+1)); sleep 0.5; done; return 1; }; \
	echo "[dev] 等待 MySQL..."; wait_mysql || { echo "[dev] ERROR: MySQL 超时"; $(CTR) logs --tail 20 helios-db; exit 1; }; echo "[dev] MySQL OK"; \
	echo "[dev] 等待 Redis..."; wait_redis || { echo "[dev] ERROR: Redis 超时"; $(CTR) logs --tail 20 helios-cache; exit 1; }; echo "[dev] Redis OK"
	@echo "[dev] 启动 gateway + https-proxy (dev)"
	@$(COMPOSE_DEV) up -d
	@mkdir -p $(DEV_PID)
	@set -e; \
	log() { echo "[dev] $$*"; }; \
	for s in hermes aegis zwei chaos; do \
		if [ -f "$(DEV_PID)/$$s.pid" ] && kill -0 "$$(cat "$(DEV_PID)/$$s.pid")" 2>/dev/null; then \
			log "$$s 已在运行 (pid $$(cat $(DEV_PID)/$$s.pid))，跳过"; continue; \
		fi; \
	done; \
	wait_port() { i=0; while [ $$i -lt 50 ]; do nc -z 127.0.0.1 $$1 >/dev/null 2>&1 && return 0; i=$$((i+1)); sleep 0.2; done; return 1; }; \
	log "启动 hermes (:8081 + gRPC :50051)"; \
	BASE_SERVER_PORT=8081 ./bin/hermes & echo $$! > "$(DEV_PID)/hermes.pid"; \
	wait_port 50051 || { log "ERROR: hermes 超时"; exit 1; }; \
	log "启动 aegis (:18000)"; \
	HERMES_GRPC_ADDR=127.0.0.1:50051 ./bin/aegis & echo $$! > "$(DEV_PID)/aegis.pid"; \
	wait_port 18000 || { log "ERROR: aegis 超时"; exit 1; }; \
	log "启动 zwei (:18001)"; \
	BASE_SERVER_PORT=18001 ./bin/zwei & echo $$! > "$(DEV_PID)/zwei.pid"; \
	log "启动 chaos (:18002)"; \
	BASE_SERVER_PORT=18002 ./bin/chaos & echo $$! > "$(DEV_PID)/chaos.pid"; \
	sleep 0.5; \
	log "全部就绪 (Ctrl+C 停止前台输出, make dev-down 停进程)"; \
	log "  https://aegis.heliannuuthus.com"; \
	log "  hermes :8081 + gRPC :50051 | aegis :18000 | zwei :18001 | chaos :18002"; \
	wait

dev-down:
	@log() { echo "[dev] $$*"; }; \
	for s in chaos zwei aegis hermes; do \
		if [ -f "$(DEV_PID)/$$s.pid" ]; then \
			pid=$$(cat "$(DEV_PID)/$$s.pid"); \
			kill "$$pid" 2>/dev/null && log "停止 $$s (pid $$pid)" || true; \
			rm -f "$(DEV_PID)/$$s.pid"; \
		fi; \
	done; \
	for port in 8081 50051 18000 18001 18002; do \
		pids=$$(lsof -ti:$$port 2>/dev/null || true); \
		if [ -n "$$pids" ]; then kill $$pids 2>/dev/null && log "清理端口 :$$port (pid $$pids)" || true; fi; \
	done
	-$(COMPOSE_DEV) down
	-$(COMPOSE) down

dev-ps:
	@for s in hermes aegis zwei chaos; do \
		if [ -f "$(DEV_PID)/$$s.pid" ] && kill -0 "$$(cat "$(DEV_PID)/$$s.pid")" 2>/dev/null; then \
			echo "$$s  running  pid=$$(cat $(DEV_PID)/$$s.pid)"; \
		else \
			echo "$$s  stopped"; \
		fi; \
	done

# ── help ─────────────────────────────────────────────

help:
	@echo "开发模式（容器基础组件 + 本地服务进程）:"
	@echo "  make dev          一键启动（日志直接打印到终端，Ctrl+C 断开）"
	@echo "  make dev-down     停止全部进程和容器"
	@echo "  make dev-ps       查看进程状态"
	@echo ""
	@echo "全容器模式:"
	@echo "  make up           全部容器化启动"
	@echo "  make down         全部停止"
	@echo "  make reset        停止并清空所有数据（MySQL + Redis 卷删除）"
	@echo "  make logs         跟踪容器日志"
	@echo "  make ps           查看容器状态"
	@echo ""
	@echo "构建 & 工具:"
	@echo "  make build [svc]  编译 (hermes/aegis/zwei/chaos)"
	@echo "  make run <svc>    编译并运行单个服务"
	@echo "  make test         测试"
	@echo "  make lint         检查"
	@echo "  make tidy         整理依赖"
	@echo "  make generate     codegen (proto + swag)"
	@echo "  make clean        清理"
