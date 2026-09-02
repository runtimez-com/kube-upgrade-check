BINARY  := kube-upgrade-check
PKG     := github.com/runtimez-com/kube-upgrade-check
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.Commit=$(COMMIT) \
	-X $(PKG)/internal/version.Date=$(DATE)

.PHONY: build test lint fmt vet tidy install clean snapshot checksums

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/kube-upgrade-check

install:
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/kube-upgrade-check

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run

tidy:
	go mod tidy

# The catalog is vendored into the runtimez backend as well; this file is what the backend's
# parity test compares against, so regenerate it whenever a catalog file changes.
checksums:
	@cd catalog && find . -name '*.json' | sort | xargs shasum -a 256 > CHECKSUMS && \
	  sed -i.bak 's|  \./|  |' CHECKSUMS && rm -f CHECKSUMS.bak && \
	  echo "wrote catalog/CHECKSUMS ($$(wc -l < CHECKSUMS | tr -d ' ') files)"

# Builds every release target locally without publishing — the same check CI runs on a PR.
snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf bin dist
