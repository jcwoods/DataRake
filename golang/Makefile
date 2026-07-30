BINARY  := datarake
BINDIR  := bin
PKG     := github.com/jcwoods/datarake/golang
VERSION := $(shell sed -n 's/^version=//p' ../project.properties)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: all build test race vet fmt fmt-check lint tidy clean install cross

all: build

build:
	@mkdir -p $(BINDIR)
	go build $(LDFLAGS) -o $(BINDIR)/$(BINARY) ./cmd/datarake

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint: vet fmt-check

tidy:
	go mod tidy

install:
	go install $(LDFLAGS) ./cmd/datarake

clean:
	rm -rf $(BINDIR)
	go clean -testcache

cross:
	@mkdir -p $(BINDIR)
	@for os in linux darwin windows; do \
	  for arch in amd64 arm64; do \
	    ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	    echo "building $$os/$$arch"; \
	    GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) \
	      -o $(BINDIR)/$(BINARY)-$$os-$$arch$$ext ./cmd/datarake || exit 1; \
	  done; \
	done
