.PHONY: all build deps image migrate test test-coverage vet sec vulncheck format unused release
.PHONY: check-gosec check-govulncheck check-oapi-codegen check-staticcheck check-go-version
.PHONY: db-up db-down db-status db-create db-drop db-migrate db-setup db-reset db-psql db-schema server
CHECK_FILES ?= ./...

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

RELEASE_TARGETS = x86 arm64 darwin-arm64 amd64-strip arm64-strip
RELEASE_ARCHIVES = \
	auth-$(VERSION)-x86.tar.gz \
	auth-$(VERSION)-arm64.tar.gz \
	auth-$(VERSION)-darwin-arm64.tar.gz \
	auth-$(VERSION)-amd64.tar.xz \
	auth-$(VERSION)-arm64.tar.xz

TOOL_BIN_DIR = tools/bin
TOOL_TARGETS = \
	$(TOOL_BIN_DIR)/gosec \
	$(TOOL_BIN_DIR)/staticcheck \
	$(TOOL_BIN_DIR)/govulncheck

# Database used by the db-* targets and by "make test".
#
# By default these manage a repo-local PostgreSQL in $(PGDATA_DIR) and need no
# Docker. Point PGHOST/PGPORT at a server you already run and they will use
# that instead -- but note that the test suite reads hack/test.env, and
# confload loads it with godotenv.Overload, so the file wins over the
# environment: changing PGPORT alone will not move the tests.
PGHOST ?= 127.0.0.1
PGPORT ?= 5432
PGSUPERUSER ?= postgres
PGDATA_DIR ?= .postgres
PG_ENV = PGHOST=$(PGHOST) PGPORT=$(PGPORT) PGDATA_DIR=$(PGDATA_DIR)
PG_SUPERUSER_URL = postgres://$(PGSUPERUSER)@$(PGHOST):$(PGPORT)/postgres
# psql is not on PATH on every platform, so ask the script where it lives.
PSQL = "$$(./hack/postgres.sh bindir)/psql"

SCHEMA_FILE ?= schema.sql

# Set to 0 to stop "make test" and "make server" preparing a database first.
DB_AUTO_SETUP ?= 1
DB_SETUP_DEP = $(if $(filter 1,$(DB_AUTO_SETUP)),db-setup)

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {sub("\\\\n",sprintf("\n%22c"," "), $$2);printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check-go-version vet sec static build ## Run the tests and build the binary.

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

# What CI runs. Uses test-coverage rather than test: it needs coverage.out for
# coveralls and the coverage gate, and it brings its own database, so it must
# not depend on the db-* targets.
release-test: \
	check-go-version \
	vet \
	static \
	sec \
	vulncheck \
	test-coverage

release: $(RELEASE_ARCHIVES)

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

migrate_dev: ## Run database migrations for development.
	hack/migrate.sh postgres

migrate_test: ## Run database migrations for test.
	hack/migrate.sh postgres

db-up: ## Start PostgreSQL for development (no Docker needed).
	@$(PG_ENV) ./hack/postgres.sh start

db-down: ## Stop the PostgreSQL started by db-up.
	@$(PG_ENV) ./hack/postgres.sh stop

db-status: ## Report whether PostgreSQL is running.
	@$(PG_ENV) ./hack/postgres.sh status

db-create: db-up ## Create the auth schema and the roles it needs.
	@$(PSQL) -v ON_ERROR_STOP=1 -q -f hack/init_postgres.sql "$(PG_SUPERUSER_URL)"

db-drop: db-up ## Drop the auth schema and the roles it needs.
	@$(PSQL) -v ON_ERROR_STOP=1 -q -f hack/drop_postgres.sql "$(PG_SUPERUSER_URL)"

db-migrate: db-create ## Apply database migrations.
	@hack/migrate.sh postgres

db-setup: db-migrate ## Start PostgreSQL, create the schema and migrate it.

db-reset: db-drop db-setup ## Drop everything and rebuild from the migrations.

db-psql: db-up ## Open a psql shell on the development database.
	@$(PSQL) "$(PG_SUPERUSER_URL)"

# The dump is committed, so it has to be reproducible. Two things in pg_dump's
# output are not: the "Dumped from/by" banner changes with the server and
# client patch version, and \restrict carries a token that is randomly
# generated on every run. Both are noise here, so drop them.
db-schema: db-migrate ## Dump the auth schema to $(SCHEMA_FILE).
	@"$$(./hack/postgres.sh bindir)/pg_dump" \
		--schema-only --schema=auth "$(PG_SUPERUSER_URL)" \
		| grep -vE '^(-- Dumped |\\(un)?restrict )' > $(SCHEMA_FILE)
	@echo "wrote $(SCHEMA_FILE)"

test: $(DB_SETUP_DEP) ## Run tests.
	go test -failfast $(CHECK_FILES) -p 1 -race -count=1

test-coverage: auth ## Run tests with coverage and enforce the coverage gate.
	go test -failfast $(CHECK_FILES) -coverprofile=coverage.out -coverpkg ./... -p 1 -race -v -count=1
	./hack/coverage.sh

server: auth $(DB_SETUP_DEP) ## Run the auth server against .env.
	@test -f .env || { echo 'No .env found. Run: cp example.env .env'; exit 1; }
	./auth

vet: # Vet the code
	go vet $(CHECK_FILES)

check-go-version: ## Verify the pinned Go version matches across go.mod, Dockerfiles, and submodules.
	./hack/check-go-version.sh

.NOTPARALLEL: $(TOOL_TARGETS)
$(TOOL_TARGETS):
	$(MAKE) -C tools

sec: | $(TOOL_BIN_DIR)/gosec # Check for security vulnerabilities
	$(TOOL_BIN_DIR)/gosec \
		-quiet \
		-exclude-generated \
		-exclude=G117,G120,G704 \
		$(CHECK_FILES)
	$(TOOL_BIN_DIR)/gosec \
		-quiet \
		-tests \
		-exclude-generated \
		-exclude=G101,G104,G117,G120,G704 \
		$(CHECK_FILES)

vulncheck: $(TOOL_BIN_DIR)/govulncheck # Check for known vulnerabilities
	$(TOOL_BIN_DIR)/govulncheck $(CHECK_FILES) | go run ./hack/vulncheck-filter

unused: | $(TOOL_BIN_DIR)/staticcheck # Look for unused code
	@echo "Unused code:"
	$(TOOL_BIN_DIR)/staticcheck -checks U1000 $(CHECK_FILES)
	@echo
	@echo "Code used only in _test.go (do move it in those files):"
	$(TOOL_BIN_DIR)/staticcheck -checks U1000 -tests=false $(CHECK_FILES)

static: | $(TOOL_BIN_DIR)/staticcheck
	$(TOOL_BIN_DIR)/staticcheck ./...

generate: | check-oapi-codegen
	go generate ./...

check-oapi-codegen:
	@command -v oapi-codegen >/dev/null 2>&1 \
		|| go install github.com/deepmap/oapi-codegen/cmd/oapi-codegen@latest

dev: ## Run the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up

down: ## Shutdown the development containers
	# Start postgres first and apply migrations
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-test: ## Run the tests using the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make migrate_test"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make test"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down -v

docker-build: ## Force a full rebuild of the development containers
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) build --no-cache
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) up -d postgres
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) run auth sh -c "make migrate_dev"
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) down

docker-clean: ## Remove the development containers and volumes
	${DOCKER_COMPOSE} -f $(DEV_DOCKER_COMPOSE) rm -fsv

format:
	gofmt -s -w .

clean:
	$(MAKE) -C tools clean
	rm -rf \
		$(addprefix release-,$(RELEASE_TARGETS)) \
		$(addprefix auth-,$(RELEASE_TARGETS)) \
		$(RELEASE_ARCHIVES) \
		auth
