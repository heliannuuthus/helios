SHELL := /bin/zsh
export PATH := $(HOME)/.asdf/shims:$(HOME)/.go/bin:$(HOME)/.cargo/bin:$(PATH)

.PHONY: all build run test lint fmt generate proto swag clean help tidy \
       up down logs ps dev dev-up dev-down dev-logs dev-ps dev-check reset \
       _dev-stop-processes _clean-compose-data _wait-infra _wait-prod-core _wait-aegis

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
COMPOSE_PROD := $(COMPOSE) -f compose.yaml -f compose.prod.yaml
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

clean: _clean-compose-data
	rm -rf bin/ coverage.out dist/
	@echo "[clean] 构建产物与 MySQL/Redis 持久化卷已清理"

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

# ── prod (全容器，不含本地 HTTPS Proxy) ─────────────

up: _dev-stop-processes
	@command -v $(CTR) >/dev/null || { echo "[up] ERROR: 未找到 $(CTR)"; exit 1; }
	@$(CTR) info >/dev/null 2>&1 || { echo "[up] ERROR: $(CTR) daemon 未运行"; exit 1; }
	@if $(CTR) container inspect helios-https-proxy >/dev/null 2>&1; then \
		echo "[up] 停止开发 HTTPS Proxy"; \
		$(COMPOSE_DEV) stop https-proxy; \
		$(COMPOSE_DEV) rm -f https-proxy; \
	fi
	@echo "[up] 启动 db + cache（已运行则跳过）"
	@if [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-db 2>/dev/null || true)" = running ] && \
	    [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-cache 2>/dev/null || true)" = running ]; then \
		echo "[up] MySQL + Redis 已在运行，跳过"; \
	else \
		$(COMPOSE_PROD) up -d db cache; \
	fi
	@$(MAKE) --no-print-directory _wait-infra LOG_PREFIX=up
	@echo "[up] 构建生产服务镜像"
	@$(COMPOSE_PROD) build hermes aegis zwei chaos
	@echo "[up] 启动 hermes + zwei + chaos"
	@$(COMPOSE_PROD) up -d hermes zwei chaos
	@$(MAKE) --no-print-directory _wait-prod-core
	@echo "[up] 启动 aegis"
	@$(COMPOSE_PROD) up -d aegis
	@$(MAKE) --no-print-directory _wait-aegis
	@echo "[up] 启动 gateway"
	@$(COMPOSE_PROD) up -d --force-recreate gateway
	@echo ""
	@echo "Helios 生产容器已启动: Gateway http://127.0.0.1"
	@echo "直连: aegis :18000 | hermes :8081/:50051 | zwei :18001 | chaos :18002"

_wait-infra:
	@set -e; \
	wait_mysql() { i=0; while [ $$i -lt 60 ]; do $(CTR) exec helios-db mysqladmin ping -h127.0.0.1 -uroot -proot --silent >/dev/null 2>&1 && return 0; i=$$((i+1)); sleep 0.5; done; return 1; }; \
	wait_redis() { i=0; while [ $$i -lt 30 ]; do $(CTR) exec helios-cache redis-cli -a helios ping 2>/dev/null | grep -q PONG && return 0; i=$$((i+1)); sleep 0.5; done; return 1; }; \
	echo "[$(or $(LOG_PREFIX),dev)] 等待 MySQL..."; wait_mysql || { echo "[$(or $(LOG_PREFIX),dev)] ERROR: MySQL 超时"; $(CTR) logs --tail 20 helios-db; exit 1; }; echo "[$(or $(LOG_PREFIX),dev)] MySQL OK"; \
	echo "[$(or $(LOG_PREFIX),dev)] 等待 Redis..."; wait_redis || { echo "[$(or $(LOG_PREFIX),dev)] ERROR: Redis 超时"; $(CTR) logs --tail 20 helios-cache; exit 1; }; echo "[$(or $(LOG_PREFIX),dev)] Redis OK"

_wait-prod-core:
	@set -e; \
	wait_http() { name=$$1; port=$$2; i=0; while [ $$i -lt 60 ]; do curl -fsS --max-time 1 "http://127.0.0.1:$$port/health" >/dev/null 2>&1 && { echo "[up] $$name OK"; return 0; }; i=$$((i+1)); sleep 0.5; done; echo "[up] ERROR: $$name 健康检查超时"; $(CTR) logs --tail 30 "helios-$$name"; return 1; }; \
	wait_http hermes 8081; \
	wait_http zwei 18001; \
	wait_http chaos 18002

_wait-aegis:
	@set -e; \
	i=0; while [ $$i -lt 60 ]; do curl -fsS --max-time 1 http://127.0.0.1:18000/health >/dev/null 2>&1 && { echo "[up] aegis OK"; exit 0; }; i=$$((i+1)); sleep 0.5; done; \
	echo "[up] ERROR: aegis 健康检查超时"; $(CTR) logs --tail 30 helios-aegis; exit 1

down:
	@if $(CTR) info >/dev/null 2>&1; then \
		$(COMPOSE_PROD) down; \
	else \
		echo "[down] $(CTR) daemon 未运行，跳过容器清理"; \
	fi

_clean-compose-data: _dev-stop-processes
	@echo "[clean] 停止容器并删除数据卷（MySQL + Redis 数据全部清空）"
	@if $(CTR) info >/dev/null 2>&1; then \
		dev_rc=0; prod_rc=0; \
		$(COMPOSE_DEV) down -v || dev_rc=$$?; \
		$(COMPOSE_PROD) down -v || prod_rc=$$?; \
		if [ $$dev_rc -ne 0 ] || [ $$prod_rc -ne 0 ]; then \
			echo "[clean] ERROR: Compose 数据卷清理失败 (dev=$$dev_rc prod=$$prod_rc)"; \
			exit 1; \
		fi; \
	else \
		echo "[clean] $(CTR) daemon 未运行，无法删除容器数据卷"; \
		exit 1; \
	fi

reset: _clean-compose-data
	@echo "[reset] 持久化数据已清空，下次 make dev-up/up 会重新初始化数据库"

logs:
	$(COMPOSE_PROD) logs -f

ps:
	$(COMPOSE_PROD) ps

# ── dev (容器基础组件 + 本地进程 + HTTPS Proxy) ─────

dev: dev-up

dev-up: dev-check _dev-stop-processes build
	@command -v $(CTR) >/dev/null || { echo "[dev] ERROR: 未找到 $(CTR)"; exit 1; }
	@$(CTR) info >/dev/null 2>&1 || { echo "[dev] ERROR: $(CTR) daemon 未运行"; exit 1; }
	@has_prod=false; for s in aegis hermes zwei chaos; do \
		if $(CTR) container inspect "helios-$$s" >/dev/null 2>&1; then has_prod=true; break; fi; \
	done; \
	if $$has_prod; then \
		echo "[dev] 停止生产后端容器"; \
		$(COMPOSE_PROD) stop aegis hermes zwei chaos; \
		$(COMPOSE_PROD) rm -f aegis hermes zwei chaos; \
	fi
	@echo "[dev] 启动 db + cache + gateway + https-proxy（已运行的服务会跳过）"
	@if [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-db 2>/dev/null || true)" = running ] && \
	    [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-cache 2>/dev/null || true)" = running ]; then \
		echo "[dev] MySQL + Redis 已在运行，跳过"; \
	else \
		$(COMPOSE_DEV) up -d db cache; \
	fi
	@$(MAKE) --no-print-directory _wait-infra LOG_PREFIX=dev
	@if [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-gateway 2>/dev/null || true)" = running ] && \
	    [ "$$($(CTR) container inspect -f '{{.State.Status}}' helios-https-proxy 2>/dev/null || true)" = running ]; then \
		echo "[dev] Gateway + HTTPS Proxy 已在运行，跳过"; \
	else \
		$(COMPOSE_DEV) up -d gateway; \
		$(COMPOSE_DEV) up -d https-proxy; \
	fi
	@mkdir -p $(DEV_PID)
	@set -e; \
	log() { echo "[dev] $$*"; }; \
	fail_start() { \
		log "ERROR: $$*"; \
		$(MAKE) --no-print-directory _dev-stop-processes; \
		exit 1; \
	}; \
	wait_service() { pid=$$1; port=$$2; i=0; while [ $$i -lt 50 ]; do kill -0 "$$pid" 2>/dev/null || return 1; nc -z 127.0.0.1 "$$port" >/dev/null 2>&1 && return 0; i=$$((i+1)); sleep 0.2; done; return 1; }; \
	for port in 50051 8081 18000 18001 18002; do \
		nc -z 127.0.0.1 "$$port" >/dev/null 2>&1 && fail_start "端口 :$$port 已被其他进程占用"; \
	done; \
	log "启动 hermes (:8081 + gRPC :50051)"; HERMES_SERVER_PORT=8081 ./bin/hermes & pid=$$!; echo "$$pid" > "$(DEV_PID)/hermes.pid"; \
	wait_service "$$pid" 50051 || fail_start "hermes gRPC 启动失败"; \
	wait_service "$$pid" 8081 || fail_start "hermes HTTP 启动失败"; \
	log "启动 aegis (:18000)"; HERMES_GRPC_ADDR=127.0.0.1:50051 ./bin/aegis & pid=$$!; echo "$$pid" > "$(DEV_PID)/aegis.pid"; \
	wait_service "$$pid" 18000 || fail_start "aegis 启动失败"; \
	log "启动 zwei (:18001)"; ZWEI_SERVER_PORT=18001 ./bin/zwei & pid=$$!; echo "$$pid" > "$(DEV_PID)/zwei.pid"; \
	wait_service "$$pid" 18001 || fail_start "zwei 启动失败"; \
	log "启动 chaos (:18002)"; CHAOS_SERVER_PORT=18002 ./bin/chaos & pid=$$!; echo "$$pid" > "$(DEV_PID)/chaos.pid"; \
	wait_service "$$pid" 18002 || fail_start "chaos 启动失败"; \
	log "全部就绪 (Ctrl+C 停止前台输出, make dev-down 停进程)"; \
	log "  https://aegis.heliannuuthus.com"; \
	log "  hermes :8081 + gRPC :50051 | aegis :18000 | zwei :18001 | chaos :18002"; \
	wait

_dev-stop-processes:
	@log() { echo "[dev] $$*"; }; \
	for s in chaos zwei aegis hermes; do \
		expected=$$(realpath -m "./bin/$$s" 2>/dev/null || true); \
		tracked_pid=""; \
		pid_file="$(DEV_PID)/$$s.pid"; \
		if [ -f "$$pid_file" ]; then \
			pid=$$(cat "$$pid_file" 2>/dev/null || true); \
			rm -f "$$pid_file"; \
			case "$$pid" in \
				''|*[!0-9]*) log "忽略无效 PID 文件: $$pid_file" ;; \
				*) \
					tracked_pid="$$pid"; \
					actual=$$(readlink "/proc/$$pid/exe" 2>/dev/null || true); \
					normalized=$${actual%\ \(deleted\)}; \
					if [ -n "$$expected" ] && [ "$$normalized" = "$$expected" ]; then \
						kill "$$pid" 2>/dev/null && log "停止 $$s (pid $$pid)" || true; \
					elif kill -0 "$$pid" 2>/dev/null; then \
						log "WARN: PID $$pid 不属于 ./bin/$$s，拒绝停止 ($${actual:-unknown})"; \
					else \
						log "清理已失效的 PID: $$s (pid $$pid)"; \
					fi ;; \
			esac; \
		fi; \
		for exe_link in /proc/[0-9]*/exe; do \
			pid=$${exe_link#/proc/}; pid=$${pid%/exe}; \
			[ "$$pid" = "$$tracked_pid" ] && continue; \
			actual=$$(readlink "$$exe_link" 2>/dev/null || true); \
			normalized=$${actual%\ \(deleted\)}; \
			if [ -n "$$expected" ] && [ "$$normalized" = "$$expected" ]; then \
				kill "$$pid" 2>/dev/null && log "停止孤儿 $$s (pid $$pid)" || true; \
			fi; \
		done; \
	done

dev-down: _dev-stop-processes
	@if $(CTR) info >/dev/null 2>&1; then \
		$(COMPOSE_DEV) down; \
		for port in 3306 6379 80 443; do \
			i=0; while [ $$i -lt 50 ] && nc -z 127.0.0.1 "$$port" >/dev/null 2>&1; do i=$$((i+1)); sleep 0.1; done; \
			if nc -z 127.0.0.1 "$$port" >/dev/null 2>&1; then echo "[dev] ERROR: 容器端口 :$$port 未释放"; exit 1; fi; \
		done; \
	else \
		echo "[dev] $(CTR) daemon 未运行，跳过容器清理"; \
	fi

dev-logs:
	$(COMPOSE_DEV) logs -f

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
	@echo "开发模式（基础组件 + 本地服务 + Gateway + HTTPS Proxy）:"
	@echo "  make dev-up       一键启动（日志直接打印到终端，Ctrl+C 断开）"
	@echo "  make dev          dev-up 的兼容别名"
	@echo "  make dev-down     停止本地进程与 compose.dev.yaml 服务"
	@echo "  make dev-logs     跟踪开发容器日志"
	@echo "  make dev-ps       查看进程状态"
	@echo ""
	@echo "生产容器模式（Gateway HTTP，不含 HTTPS Proxy）:"
	@echo "  make up           使用 compose.prod.yaml 启动"
	@echo "  make down         停止 compose.prod.yaml 服务"
	@echo "  make reset        停止服务并清空持久化数据（保留构建产物）"
	@echo "  make logs         跟踪生产容器日志"
	@echo "  make ps           查看生产容器状态"
	@echo ""
	@echo "构建 & 工具:"
	@echo "  make build [svc]  编译 (hermes/aegis/zwei/chaos)"
	@echo "  make run <svc>    编译并运行单个服务"
	@echo "  make test         测试"
	@echo "  make lint         检查"
	@echo "  make tidy         整理依赖"
	@echo "  make generate     codegen (proto + swag)"
	@echo "  make clean        停止服务，清理构建产物和 MySQL/Redis 持久化卷"
