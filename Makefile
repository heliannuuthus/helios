.PHONY: all build run test lint fmt generate wire swag proto clean help

SERVICES := hermes aegis zwei chaos
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_DATE := $(shell date +%Y%m%d)
IMAGE_TAG := $(VERSION)-$(BUILD_DATE)
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

all: generate build

build: $(addprefix build-,$(SERVICES))

build-%:
	go build $(LDFLAGS) -o bin/$* ./cmd/$*

run-%: build-%
	./bin/$*

test:
	go test -v -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run --fix ./...

fmt:
	go fmt ./...
	goimports -w .

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

docker-build: $(addprefix docker-build-,$(SERVICES))

docker-build-%:
	docker build --build-arg SERVICE=$* -t helios-$*:$(IMAGE_TAG) -t helios-$*:latest .

help:
	@echo "可用命令:"
	@echo "  make build          - 编译所有服务"
	@echo "  make build-hermes   - 编译 hermes 服务"
	@echo "  make build-aegis    - 编译 aegis 服务"
	@echo "  make build-zwei     - 编译 zwei 服务"
	@echo "  make build-chaos    - 编译 chaos 服务"
	@echo "  make run-hermes     - 运行 hermes 服务"
	@echo "  make test           - 运行测试"
	@echo "  make lint           - 代码检查"
	@echo "  make fmt            - 格式化代码"
	@echo "  make proto          - 生成 proto 代码"
	@echo "  make generate       - 生成所有代码 (proto + wire + swag)"
	@echo "  make clean          - 清理构建产物"
	@echo "  make docker-build   - 构建所有 Docker 镜像"
