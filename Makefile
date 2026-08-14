GO ?= go
CGO_ENABLED ?= 0

BINARY := bin/elastic-maintainer
PACKAGE := ./cmd/elastic-maintainer
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf dev)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf none)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)

.PHONY: all build test vet version clean

all: test vet build

build:
	@mkdir -p $(dir $(BINARY))
	CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(PACKAGE)

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...

version: build
	./$(BINARY) --version

clean:
	rm -rf bin
