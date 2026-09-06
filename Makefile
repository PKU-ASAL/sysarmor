.DEFAULT_GOAL := help

.PHONY: api api-go api-python build build-agent-binary build-agent-tools build-binary install-agent uninstall-agent test test-help test-doctor test-unit test-postgres-integration test-functional test-detection test-performance test-distribution test-release test-opensearch-lifecycle up deploy down status reset clean clean-bin pki auth-init doctor release release-rc release-stable check-github-release-inputs web-install web-dev web-up web-build web-preview web-status web-stop help

PROTO_FILES := $(shell find packages/contracts/proto -name '*.proto' | sort)
GOCACHE ?= /tmp/sysarmor-go-cache
GOBIN_PATH := $(shell go env GOPATH)/bin
PYTHON_PROTO_OUT := apps/streaming/src
BIN_DIR ?= dist/bin
RELEASE_DIR ?= dist/release
PACKAGE_BASE_URL ?= http://packages
RELEASE_VERSION ?= dev
RELEASE_OS ?= linux
RELEASE_ARCH ?= amd64
RELEASE_CHANNELS ?= dev-agent linux-systemd-dev linux-container-dev
RELEASE_AGENT_BIN ?= $(BIN_DIR)/sysarmor-agent
RELEASE_SIGNING_KEY ?= $(PKI_RUNTIME_DIR)/artifact-signing-key.pem
RELEASE_PUBLIC_KEY ?= $(PKI_RUNTIME_DIR)/artifact-public.pem
TETRAGON_ARCHIVE_CANDIDATE := $(wildcard .cache/tetragon-v1.7.0-amd64.tar.gz)
TETRAGON_ARCHIVE ?= $(or $(SYSARMOR_TETRAGON_ARCHIVE),$(if $(TETRAGON_ARCHIVE_CANDIDATE),$(abspath $(TETRAGON_ARCHIVE_CANDIDATE))))
# Preserve release inputs as data instead of recursively expanding Make syntax.
override VERSION := $(value VERSION)
override RC := $(value RC)
export VERSION RC
FUNCTIONAL_TARGET_endpoint := functional-endpoint
FUNCTIONAL_TARGET_platform := functional-platform
FUNCTIONAL_TARGET_topology := functional-topology
FUNCTIONAL_TARGET_all := functional-core
FUNCTIONAL_TARGET := $(FUNCTIONAL_TARGET_$(DOMAIN))
PERFORMANCE_TARGET_endpoint := performance-endpoint
PERFORMANCE_TARGET_learning := performance-learning
PERFORMANCE_TARGET_platform := performance-platform
PERFORMANCE_TARGET_modules := performance-modules
PERFORMANCE_TARGET_all := performance-endpoint performance-platform performance-modules
PERFORMANCE_TARGET := $(PERFORMANCE_TARGET_$(DOMAIN))
DISTRIBUTION_TARGET_local := distribution-package
DISTRIBUTION_TARGET_published := distribution-published
DISTRIBUTION_TARGET := $(DISTRIBUTION_TARGET_$(SOURCE))
RELEASE_TARGET_pre-publish := release-candidate
RELEASE_TARGET_post-publish := release-published
RELEASE_TARGET := $(RELEASE_TARGET_$(STAGE))
PROFILE ?= quick
WORKLOAD ?= business-normal
SCENARIO ?=
POLICIES ?=
COMPOSE ?= docker compose
PLATFORM_COMPOSE ?= deployments/compose.platform.yaml
PKI_RUNTIME_DIR ?= deployments/pki/agent-plane-mtls/runtime
WEB_DIR ?= apps/console
WEB_HOST ?= 127.0.0.1
WEB_DEV_PORT ?= 5173
WEB_PREVIEW_PORT ?= 4173
WEB_DEV_FLAGS ?= --webpack
WEB_RUN_DIR ?= .run
WEB_LOG ?= $(WEB_RUN_DIR)/manager-console.log
WEB_PID ?= $(WEB_RUN_DIR)/manager-console.pid

api: api-go api-python

api-go:
	PATH="$(GOBIN_PATH):$$PATH" protoc --go_out=. --go_opt=paths=source_relative $(PROTO_FILES)
	PATH="$(GOBIN_PATH):$$PATH" protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative $(PROTO_FILES)

api-python:
	mkdir -p $(PYTHON_PROTO_OUT)
	PYTHONWARNINGS=ignore::DeprecationWarning uv run --project apps/streaming --group dev python -m grpc_tools.protoc -I . --python_out=$(PYTHON_PROTO_OUT) $(PROTO_FILES)

build:
	@if [ -z "$(SERVICE)" ]; then \
		echo "usage: make build SERVICE=manager"; \
		exit 2; \
	elif [ "$(SERVICE)" = "packages" ]; then \
		echo "service packages uses image nginx:alpine; no build needed"; \
	else \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) build $(SERVICE); \
	fi

build-agent-binary:
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-agent ./apps/agent/cmd/sysarmor-agent

build-agent-tools: build-agent-binary
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmorctl ./apps/cli/cmd/sysarmorctl
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-content-sign ./apps/agent/cmd/sysarmor-content-sign
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-model-sign ./apps/agent/cmd/sysarmor-model-sign

install-agent: build-agent-tools
	sudo SYSARMOR_AGENT_BIN=$(BIN_DIR)/sysarmor-agent SYSARMOR_CTL_BIN=$(BIN_DIR)/sysarmorctl SYSARMOR_CONTENT_SIGN_BIN=$(BIN_DIR)/sysarmor-content-sign deployments/agent/install-agent.sh

uninstall-agent:
	sudo systemctl disable --now sysarmor-agent 2>/dev/null || true
	sudo rm -f /etc/systemd/system/sysarmor-agent.service /usr/local/bin/sysarmorctl
	sudo rm -rf /opt/sysarmor/agent /run/sysarmor/agent
	@if [ "$(PURGE)" = "1" ]; then sudo rm -rf /etc/sysarmor/agent /var/lib/sysarmor/agent; fi
	sudo systemctl daemon-reload

build-binary: build-agent-binary
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-gateway ./apps/manager/cmd/sysarmor-gateway
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-manager ./apps/manager/cmd/sysarmor-manager
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmorctl ./apps/cli/cmd/sysarmorctl
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-content-sign ./apps/agent/cmd/sysarmor-content-sign
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go build -o $(BIN_DIR)/sysarmor-model-sign ./apps/agent/cmd/sysarmor-model-sign

test:
	CGO_ENABLED=0 GOCACHE=$(GOCACHE) go test ./...

test-help:
	$(MAKE) -C test help

test-doctor:
	$(MAKE) -C test doctor SYSARMOR_TETRAGON_ARCHIVE="$(TETRAGON_ARCHIVE)"

test-unit:
	$(MAKE) -C test test-unit

test-postgres-integration:
	bash test/suites/functional/platform/postgres-worker-concurrency.sh

test-functional:
ifeq ($(FUNCTIONAL_TARGET),)
	@echo "usage: make test-functional DOMAIN=endpoint|platform|topology|all" >&2
	@exit 2
else
	$(MAKE) -C test $(FUNCTIONAL_TARGET) SYSARMOR_TETRAGON_ARCHIVE="$(TETRAGON_ARCHIVE)"
endif

test-detection:
	$(MAKE) -C test detection-topology SYSARMOR_TETRAGON_ARCHIVE="$(TETRAGON_ARCHIVE)"

test-performance:
ifeq ($(PERFORMANCE_TARGET),)
	@echo "usage: make test-performance DOMAIN=endpoint|platform|modules|all" >&2
	@exit 2
else
	$(MAKE) -C test $(PERFORMANCE_TARGET) \
		SYSARMOR_TETRAGON_ARCHIVE="$(TETRAGON_ARCHIVE)" \
		SYSARMOR_BENCH_PROFILE=$(PROFILE) \
		SYSARMOR_BENCH_WORKLOAD=$(WORKLOAD) \
		SYSARMOR_BENCH_SCENARIO=$(SCENARIO) \
		SYSARMOR_BENCH_POLICIES="$(POLICIES)" \
		TRAINING_DATA="$(TRAINING_DATA)" \
		CALIBRATION_DATA="$(CALIBRATION_DATA)"
endif

test-distribution:
ifeq ($(DISTRIBUTION_TARGET),)
	@echo "usage: make test-distribution SOURCE=local|published" >&2
	@exit 2
else
	$(MAKE) -C test $(DISTRIBUTION_TARGET)
endif

test-release:
ifeq ($(RELEASE_TARGET),)
	@echo "usage: make test-release STAGE=pre-publish|post-publish" >&2
	@exit 2
else
	$(MAKE) -C test $(RELEASE_TARGET) SYSARMOR_TETRAGON_ARCHIVE="$(TETRAGON_ARCHIVE)"
endif

test-opensearch-lifecycle:
	bash test/suites/functional/platform/opensearch-alias-lifecycle.sh

pki:
	@if [ ! -f "$(PKI_RUNTIME_DIR)/gateway.pem" ] || [ ! -f "$(PKI_RUNTIME_DIR)/gateway-key.pem" ] || [ ! -f "$(PKI_RUNTIME_DIR)/ca.pem" ]; then \
		echo "Generating local agent-plane mTLS material in $(PKI_RUNTIME_DIR)"; \
		SYSARMOR_GATEWAY_IPS=127.0.0.1 tools/pki/gen-agent-plane-mtls.sh "$(PKI_RUNTIME_DIR)" default agent-prod-001 localhost; \
	fi
	@bash tools/pki/gen-manager-jwt.sh "$(PKI_RUNTIME_DIR)"

auth-init: pki
	@bash tools/auth/init-bootstrap-admin.sh "$(PKI_RUNTIME_DIR)"

doctor:
	@PLATFORM_COMPOSE="$(PLATFORM_COMPOSE)" PKI_RUNTIME_DIR="$(PKI_RUNTIME_DIR)" bash tools/doctor.sh

release: build-agent-tools pki
	bash deployments/packages/build-release.sh \
	  --version "$(RELEASE_VERSION)" \
	  --os "$(RELEASE_OS)" \
	  --arch "$(RELEASE_ARCH)" \
	  --output-dir "$(RELEASE_DIR)" \
	  --base-url "$(PACKAGE_BASE_URL)" \
	  --channels "$(RELEASE_CHANNELS)" \
	  --agent-bin "$(RELEASE_AGENT_BIN)" \
	  --tetragon-archive "$(TETRAGON_ARCHIVE)" \
	  --signing-key "$(RELEASE_SIGNING_KEY)" \
	  --public-key "$(RELEASE_PUBLIC_KEY)"

check-github-release-inputs:
	@if ! printf '%s\n' "$${VERSION:-}" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$'; then \
		echo "VERSION must use MAJOR.MINOR.PATCH, for example VERSION=1.0.0" >&2; \
		exit 2; \
	fi
	@if ! printf '%s\n' "$${RC:-}" | grep -Eq '^[1-9][0-9]*$$'; then \
		echo "RC must be a positive integer, for example RC=1" >&2; \
		exit 2; \
	fi
	@command -v gh >/dev/null 2>&1 || { \
		echo "GitHub CLI is required; install gh before publishing" >&2; \
		exit 2; \
	}
	@gh auth status >/dev/null 2>&1 || { \
		echo "GitHub CLI is not authenticated; run gh auth login" >&2; \
		exit 2; \
	}

release-rc: check-github-release-inputs
	gh workflow run release-candidate.yml --ref "release/v$${VERSION}" -f "rc_number=$${RC}"

release-stable: check-github-release-inputs
	gh workflow run release-stable.yml --ref main -f "version=$${VERSION}" -f "accepted_rc_tag=v$${VERSION}-rc.$${RC}"

up: release auth-init
	@if [ -n "$(SERVICE)" ]; then \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) up -d --remove-orphans $(SERVICE); \
	else \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) up -d --remove-orphans; \
	fi

deploy: build-binary release auth-init
	$(COMPOSE) -f $(PLATFORM_COMPOSE) up -d --build --remove-orphans

down:
	@if [ -n "$(SERVICE)" ]; then \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) stop $(SERVICE); \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) rm -f $(SERVICE); \
	else \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) down --remove-orphans; \
	fi

status:
	@if [ -n "$(SERVICE)" ]; then \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) ps $(SERVICE); \
	else \
		$(COMPOSE) -f $(PLATFORM_COMPOSE) ps; \
	fi

clean:
	$(COMPOSE) -f $(PLATFORM_COMPOSE) down -v --remove-orphans

reset: clean up status

clean-bin:
	rm -rf $(BIN_DIR)

web-install:
	cd $(WEB_DIR) && pnpm install

web-dev:
	cd $(WEB_DIR) && pnpm exec next dev $(WEB_DEV_FLAGS) --hostname $(WEB_HOST) --port $(WEB_DEV_PORT)

web-up: web-build
	@WEB_DIR="$(CURDIR)/$(WEB_DIR)" WEB_HOST="$(WEB_HOST)" WEB_DEV_PORT="$(WEB_DEV_PORT)" WEB_PREVIEW_PORT="$(WEB_PREVIEW_PORT)" WEB_MODE=preview WEB_RUN_DIR="$(CURDIR)/$(WEB_RUN_DIR)" bash tools/web-console.sh up

web-build:
	cd $(WEB_DIR) && pnpm build

web-preview: web-build
	cd $(WEB_DIR) && pnpm start --hostname $(WEB_HOST) --port $(WEB_PREVIEW_PORT)

web-status:
	@WEB_HOST="$(WEB_HOST)" WEB_DEV_PORT="$(WEB_DEV_PORT)" WEB_PREVIEW_PORT="$(WEB_PREVIEW_PORT)" WEB_RUN_DIR="$(CURDIR)/$(WEB_RUN_DIR)" bash tools/web-console.sh status

web-stop:
	@WEB_HOST="$(WEB_HOST)" WEB_DEV_PORT="$(WEB_DEV_PORT)" WEB_PREVIEW_PORT="$(WEB_PREVIEW_PORT)" WEB_RUN_DIR="$(CURDIR)/$(WEB_RUN_DIR)" bash tools/web-console.sh stop

help:
	@echo "SysArmor project commands:"
	@echo "  make api        generate protobuf code"
	@echo "  make build SERVICE=manager  build a compose service image"
	@echo "  make build-binary           build agent/gateway/manager/worker/sysarmorctl"
	@echo "  make install-agent          build and install a standalone Agent plus sysarmorctl"
	@echo "  make uninstall-agent        remove binaries; add PURGE=1 to remove config and local data"
	@echo "  make test       run Go tests"
	@echo "  make release    build a local signed agent package and index"
	@echo "  make release-rc VERSION=1.0.0 RC=1      publish v1.0.0-rc.1"
	@echo "  make release-stable VERSION=1.0.0 RC=1  publish v1.0.0 from the accepted RC"
	@echo "  make up         build release and start local platform"
	@echo "  make up SERVICE=packages    build release and start one service"
	@echo "  make deploy     build release, build images, and start local platform"
	@echo "  make down       stop local platform"
	@echo "  make down SERVICE=packages  stop and remove one service"
	@echo "  make status     show local platform service status"
	@echo "  make reset      DESTRUCTIVE: recreate data volumes and platform; preserve PKI"
	@echo "  make auth-init  create bootstrap admin and BFF secrets once"
	@echo "  make doctor     verify secrets, services, login, BFF, and Manager"
	@echo "  make clean      stop local platform and remove volumes/orphans"
	@echo "  make clean-bin  remove built binaries"
	@echo ""
	@echo "Web console:"
	@echo "  make web-install  install web dependencies"
	@echo "  make web-dev      start manager console dev server"
	@echo "  make web-up       build and start manager console preview in background"
	@echo "  make web-build    build manager console"
	@echo "  make web-preview  build and preview manager console"
	@echo "  make web-status   show manager console dev/preview status"
	@echo "  make web-stop     stop manager console dev/preview server"
	@echo "  WEB_DEV_FLAGS= make web-dev  use Next.js default dev bundler"
	@echo ""
	@echo "Test suites:"
	@echo "  make test-help         show all test suite commands"
	@echo "  make test-doctor       verify the complete test environment"
	@echo "  make test-unit         run local Go tests"
	@echo "  make test-postgres-integration  run real PostgreSQL worker concurrency tests"
	@echo "  make test-functional DOMAIN=endpoint|platform|topology|all"
	@echo "  make test-detection    run truth-labeled detection tests"
	@echo "  make test-performance DOMAIN=endpoint|learning|platform|modules|all PROFILE=medium"
	@echo "  make test-distribution SOURCE=local|published URL=https://..."
	@echo "  make test-release STAGE=pre-publish|post-publish URL=https://..."
