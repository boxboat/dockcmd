PKGS := $(shell go list ./... | grep -v /vendor)

.PHONY: test
test:
	CGO_ENABLED=0 go test $(PKGS)

BINARY := dockcmd
VERSION := develop

# for travis-ci builds
ifdef TRAVIS_BRANCH
VERSION := $(TRAVIS_BRANCH)
endif

# for tagged travis-ci builds
ifdef TRAVIS_TAG
VERSION := $(TRAVIS_TAG)
endif

ifdef CI_VERSION
VERSION := $(CI_VERSION)
endif

DEBUG ?= false
PLATFORMS := linux darwin
os = $(word 1, $@)

.DEFAULT_GOAL := local

local:
	go build

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	mkdir -p release/$(os)-amd64/$(VERSION)
	GOOS=$(os) GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-X main.Version=$(VERSION) -X github.com/boxboat/dockcmd/cmd.EnableDebug=$(DEBUG)" -o release/$(os)-amd64/$(VERSION)/$(BINARY)

windows:
	mkdir -p release/windows-amd64/$(VERSION)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-X main.Version=$(VERSION) -X github.com/boxboat/dockcmd/cmd.EnableDebug=$(DEBUG)" -o release/windows-amd64/$(VERSION)/$(BINARY).exe

.PHONY: release
release: windows linux darwin

clean:
	rm -rf release/*
	rm -f $(BINARY)
