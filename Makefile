.PHONY: build release dashboard test fmt fmt-check lint go-lint dashboard-lint clean install

# Clawpatrol.app's bundle-ID prefix, so `clawpatrol doctor` looks for
# the system extension a fork signed under its own team. The default
# comes from macos/Signing.xcconfig; see macos/README.md.
MAC_LDFLAGS = -X main.macBundleIDPrefix=$(shell macos/signing-value.sh CLAWPATROL_BUNDLE_ID_PREFIX)

build: dashboard
	go build -ldflags "$(MAC_LDFLAGS)" -o clawpatrol ./cmd/clawpatrol

# release mirrors .github/workflows/release.yml: strip the symbol
# table and DWARF (-s -w) and rewrite source paths (-trimpath). On
# this tree that drops the binary from ~88 MB to ~62 MB without
# changing runtime behaviour. Use this when packaging for users —
# `make build` stays unstripped so panics keep file:line info.
release: dashboard
	go build -ldflags "-s -w $(MAC_LDFLAGS)" -trimpath -o clawpatrol ./cmd/clawpatrol

dashboard:
	cd dashboard && deno install && deno task build

test:
	go test ./...

# Our tracked Go sources, excluding the vendored upstream copy under
# third_party/ (a verbatim tailscale.com tree that must not be
# reformatted — see third_party/tailscale/PATCH.md).
GO_SRC = $(shell git ls-files '*.go' | grep -v '^third_party/')

fmt:
	gofmt -w $(GO_SRC)
	cd dashboard && deno task format

fmt-check:
	test -z "$$(gofmt -l $(GO_SRC))"
	cd dashboard && deno task format:check

lint: go-lint dashboard-lint

# `go-lint` requires the dashboard bundle so the //go:embed in
# dashboard/embed.go resolves at compile time. Depending on
# `dashboard` here makes a clean checkout work without manual ordering.
go-lint: dashboard
	golangci-lint run --timeout 5m ./...

dashboard-lint:
	cd dashboard && deno task lint

clean:
	rm -f clawpatrol
	rm -rf dashboard/dist dashboard/node_modules

install: build
	install -m 0755 clawpatrol $${PREFIX:-$$HOME/.local/bin}/clawpatrol
