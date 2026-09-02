BIN_DIR := $(CURDIR)/bin
BIN_TARGETS := \
	$(BIN_DIR)/golangci-lint \
	$(BIN_DIR)/govulncheck

.PHONY: all
all: $(BIN_TARGETS)

$(BIN_DIR)/golangci-lint: go.mod go.sum | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint

$(BIN_DIR)/govulncheck: go.mod go.sum | $(BIN_DIR)
	GOBIN=$(BIN_DIR) go install golang.org/x/vuln/cmd/govulncheck

$(BIN_DIR):
	mkdir -p $(@)

.PHONY: clean
clean:
	rm -f $(BIN_TARGETS)
