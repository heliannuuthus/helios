.PHONY: all build run test lint fmt generate wire swag proto clean help
.PHONY: up down infra restart logs

SERVICES := hermes aegis zwei chaos
INFRA    := db cache gateway https-proxy
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date +%Y%m%d)
IMAGE_TAG := $(VERSION)-$(BUILD_DATE)
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"
COMPOSE := nerdctl compose

all: generate build

# ─── 本地编译 ────────────────────────────────────────
build: $(addprefix build-,$(SERVICES))

build-aegis:
	go build $(LDFLAGS) -o bin/aegis ./aegis

build-%:
	go build $(LDFLAGS) -o bin/$* ./$*/cmd

run-%: build-%
	./bin/$*

# ─── 测试 & 质量 ────────────────────────────────────
test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run --fix ./...

fmt:
	go fmt ./...
	goimports -w .

# ─── 代码生成 ────────────────────────────────────────
generate: proto wire swag

proto:
	cd proto && buf generate

wire:
	go install github.com/google/wire/cmd/wire@latest
	wire ./...

swag:
	go install github.com/swaggo/swag/cmd/swag@latest
	swag init --parseDependency --parseInternal

check-generate: generate
	@if [ -n "$$(git status --porcelain docs/ wire_gen.go gen/)" ]; then \
		echo "生成的代码有变更，请先运行 make generate 并提交"; \
		git diff docs/ wire_gen.go gen/; \
		exit 1; \
	fi

clean:
	rm -rf bin/ coverage.out dist/

# ─── Compose 操作 ───────────────────────────────────
infra:
	$(COMPOSE) up -d $(INFRA)

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

restart: restart-hermes restart-aegis restart-zwei restart-chaos

restart-%:
	$(COMPOSE) up -d --build --no-deps $*

logs-%:
	$(COMPOSE) logs -f $*

ps:
	$(COMPOSE) ps

# ─── 镜像构建 ────────────────────────────────────────
docker-build: $(addprefix docker-build-,$(SERVICES))

docker-build-%:
	nerdctl build -f $*/Dockerfile -t helios-$*:$(IMAGE_TAG) -t helios-$*:latest .

help:
	@echo "可用命令:"
	@echo ""
	@echo "  本地编译:"
	@echo "    make build          - 编译所有服务"
	@echo "    make build-hermes   - 编译指定服务"
	@echo "    make run-hermes     - 编译并运行指定服务"
	@echo ""
	@echo "  Compose 操作:"
	@echo "    make infra          - 仅启动基础设施 (db/cache/gateway)"
	@echo "    make up             - 启动全部服务 (含构建)"
	@echo "    make down           - 停止全部服务"
	@echo "    make restart        - 重建并重启所有 app 服务"
	@echo "    make restart-hermes - 重建并重启指定服务 (不影响其他)"
	@echo "    make logs-hermes    - 查看指定服务日志"
	@echo "    make ps             - 查看服务状态"
	@echo ""
	@echo "  质量 & 生成:"
	@echo "    make test           - 运行测试"
	@echo "    make lint           - 代码检查"
	@echo "    make fmt            - 格式化代码"
	@echo "    make generate       - 生成所有代码 (proto + wire + swag)"
	@echo "    make docker-build   - 构建所有 Docker 镜像"
	@echo "    make clean          - 清理构建产物"
