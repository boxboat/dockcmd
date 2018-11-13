PKGS := $(shell go list ./... | grep -v /vendor)

.PHONY: test
test:
	CGO_ENABLED=0 go test $(PKGS)

BINARY := boxcmd
VERSION ?= $(shell git describe --always --long --dirty)
PLATFORMS := windows linux darwin
os = $(word 1, $@)

.DEFAULT_GOAL := local

local:
	go build

.PHONY: $(PLATFORMS)
$(PLATFORMS):
	mkdir -p release/$(os)-amd64
	GOOS=$(os) GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-X main.Version=$(VERSION)" -o release/$(os)-amd64/$(BINARY)
	tar -zcf release/$(os)-amd64/$(BINARY)-$(os)-amd64-$(VERSION).tgz -C release/$(os)-amd64/ $(BINARY)

.PHONY: release
release: windows linux darwin

clean:
	rm -rf release/*
	rm -f $(BINARY)
