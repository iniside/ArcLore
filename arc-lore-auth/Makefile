# arc-lore-auth — build & cross-compile
# Pure Go (no cgo), so cross-compiling needs only the Go toolchain — no C cross-compiler.

BINARY := arc-lore-auth
PKG    := .

.PHONY: build linux linux-arm64 windows darwin all clean

# Native build for the current host.
build:
	go build -o $(BINARY) $(PKG)

# Static Linux binary for a typical x86-64 server (CGO disabled = no libc dependency).
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 $(PKG)

linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 $(PKG)

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o $(BINARY).exe $(PKG)

darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 $(PKG)

# Build every target.
all: linux linux-arm64 windows darwin

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)-linux-amd64 $(BINARY)-linux-arm64 $(BINARY)-darwin-arm64
