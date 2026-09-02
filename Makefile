.PHONY: all help \
	build build-strip deps generate \
	db-create db-migrate db-reset \
	format check-format lint check-go-version test \
	dev down docker-test docker-build docker-clean \
	release release-test \
	hooks clean

.DEFAULT_GOAL := help

CHECK_FILES ?= ./...

DB_NAME ?= postgres_test
ENV_FILE ?= hack/test.env

POSTGRES_HOST ?= localhost
POSTGRES_PORT ?= 5432
POSTGRES_USER ?= postgres
POSTGRES_PASSWORD ?= root

PSQL = PGPASSWORD=$(POSTGRES_PASSWORD) psql \
	-X \
	-h $(POSTGRES_HOST) \
	-p $(POSTGRES_PORT) \
	-U $(POSTGRES_USER) \
	-v ON_ERROR_STOP=1

ifdef RELEASE_VERSION
	VERSION=v$(RELEASE_VERSION)
else
	VERSION=$(shell git describe --tags)
endif

ifneq ($(shell docker compose version 2>/dev/null),)
	DOCKER_COMPOSE = docker compose
else
	DOCKER_COMPOSE = docker-compose
endif

DEV_DOCKER_COMPOSE = docker-compose-dev.yml

BUILD_VERSION_PKG = github.com/supabase/auth/internal/utilities
BUILD_LD_FLAGS = -X $(BUILD_VERSION_PKG).Version=$(VERSION)
BUILD_CMD = go build \
	-o $(1) \
	-buildvcs=false \
	-ldflags "$(BUILD_LD_FLAGS)$(2)"

RELEASE_TARGETS = x86 amd64 arm64 darwin-arm64 amd64-strip arm64-strip
RELEASE_ARCHIVES = \
	auth-$(VERSION)-x86.tar.gz \
	auth-$(VERSION)-arm64.tar.gz \
	auth-$(VERSION)-darwin-arm64.tar.gz \
	auth-$(VERSION)-amd64.tar.xz \
	auth-$(VERSION)-arm64.tar.xz

TOOL_BIN_DIR = tools/bin
TOOL_TARGETS = \
	$(TOOL_BIN_DIR)/golangci-lint \
	$(TOOL_BIN_DIR)/govulncheck

##@ Build

build: auth auth-amd64 auth-arm64 auth-darwin-arm64 ## Build the binaries.

build-strip: auth-amd64-strip auth-arm64-strip ## Build a stripped binary, for which the version file needs to be rewritten.

auth: deps
	CGO_ENABLED=0 $(call BUILD_CMD,$(@),)

auth-x86: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@),)

auth-amd64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@),)

auth-arm64: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@),)

auth-darwin-arm64: deps
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(call BUILD_CMD,$(@),)

auth-amd64-strip: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(call BUILD_CMD,$(@), -s)

auth-arm64-strip: deps
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(call BUILD_CMD,$(@), -s)

deps: ## Install dependencies.
	@go mod download
	@go mod verify

generate: ## Regenerate code from openapi.yaml.
	go generate ./...

##@ Database

db-create: ## Create $(DB_NAME) if absent and apply hack/init_postgres.sql. Idempotent.
	@if [ -z "$$($(PSQL) -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$(DB_NAME)'")" ]; then \
		$(PSQL) -d postgres -c 'CREATE DATABASE $(DB_NAME)'; \
	fi
	$(PSQL) -d $(DB_NAME) -v dbname=$(DB_NAME) -f hack/init_postgres.sql

db-migrate: ## Apply migrations to $(DB_NAME).
	go run . migrate -c $(ENV_FILE)

db-reset: ## Drop, recreate and migrate $(DB_NAME).
	$(PSQL) -d postgres -c 'DROP DATABASE IF EXISTS $(DB_NAME)'
	$(MAKE) db-create db-migrate

##@ Quality

.NOTPARALLEL: $(TOOL_TARGETS)
$(TOOL_TARGETS): tools/go.mod tools/go.sum
	$(MAKE) -C tools

format: ## Rewrite the tree with gofmt.
	gofmt -s -w .

check-format: ## Verify gofmt formatting. Pass FILES="..." to scope the check.
	@files=$$(gofmt -s -l $(or $(FILES),.)); \
	if [ -n "$$files" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$files"; \
		echo 'Run "make format" and re-stage the changes.'; \
		exit 1; \
	fi

lint: check-go-version | $(TOOL_TARGETS) ## Run golangci-lint and govulncheck.
	$(TOOL_BIN_DIR)/golangci-lint run
	$(TOOL_BIN_DIR)/govulncheck $(CHECK_FILES) | go run ./hack/vulncheck-filter

check-go-version: ## Verify the pinned Go version matches across go.mod, Dockerfiles, and submodules.
	./hack/check-go-version.sh

test: ## Run the tests against $(DB_NAME) with -race and enforce the coverage gate.
	go test -failfast -race -p 1 -count=1 -coverprofile=coverage.out -coverpkg=./... $(CHECK_FILES)
	./hack/coverage.sh

##@ Docker

dev: ## Run the development containers.
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) up

down: ## Shut down the development containers.
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) down

docker-test: ## Run the tests using the development containers.
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) up -d postgres
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make db-create db-migrate"
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make test"
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) down -v

docker-build: ## Force a full rebuild of the development containers.
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) build --no-cache
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) up -d postgres
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make db-migrate"
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) down

docker-clean: ## Remove the development containers and volumes.
	$(DOCKER_COMPOSE) -f $(DEV_DOCKER_COMPOSE) rm -fsv

##@ Release

release: $(RELEASE_ARCHIVES) ## Build every release archive.

release-test: lint test ## Run the full quality gate the way CI does.

auth-$(VERSION)-%.tar.gz: \
		release-%/auth \
		release-%/gotrue | migrations
	tar -C $(<D) -czvf $(@) auth gotrue -C ../ migrations/

auth-$(VERSION)-amd64.tar.xz: \
		release-amd64-strip/auth \
		release-amd64-strip/gotrue | migrations
	tar -C $(<D) -cf - auth gotrue -C ../ migrations/ \
		| xz -T0 -9e -C crc64 > $(@)

auth-$(VERSION)-arm64.tar.xz: \
		release-arm64-strip/auth \
		release-arm64-strip/gotrue | migrations
	tar -C $(<D) -cf - auth gotrue -C ../ migrations/ \
		| xz -T0 -9e -C crc64 > $(@)

release-%/auth: auth-%
	mkdir -p $(@D)
	cp -a $(<) $(@)

release-%/gotrue: release-%/auth
	ln -sf $(<F) $(@)

##@ Meta

all: lint test build ## Lint, test and build.

hooks: ## Install the git hooks defined in lefthook.yml (requires: brew install lefthook).
	lefthook install
	$(MAKE) -C tools

clean: ## Remove build artifacts.
	$(MAKE) -C tools clean
	rm -rf \
		$(addprefix release-,$(RELEASE_TARGETS)) \
		$(addprefix auth-,$(RELEASE_TARGETS)) \
		$(RELEASE_ARCHIVES) \
		coverage.out \
		auth

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} \
		/^##@ / { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
		/^[a-zA-Z_-]+:.*?## / { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)
