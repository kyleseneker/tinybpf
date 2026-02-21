.PHONY: build test bench cover vet fmt lint check clean doctor setup vm sync e2e

BIN := tinybpf
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/kyleseneker/tinybpf/internal/cli.Version=$(VERSION)

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o $(BIN) ./cmd/tinybpf

test:
	go test ./...

bench:
	go test -bench=. -benchmem ./internal/transform/

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	golangci-lint run ./...

check: lint test

clean:
	rm -f $(BIN) coverage.out
	rm -rf build/ dist/

doctor: build
	./$(BIN) doctor

setup:
	@./scripts/setup.sh

vm:
	@./scripts/create-vm.sh

sync:
	tar czf /tmp/tinybpf.tar.gz --exclude=.git --exclude=build --exclude=dist .
	scp -P 2222 /tmp/tinybpf.tar.gz ubuntu@localhost:/tmp/
	ssh -p 2222 ubuntu@localhost 'export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"; mkdir -p ~/tinybpf && cd ~/tinybpf && tar xzf /tmp/tinybpf.tar.gz'

e2e:
	sudo ./scripts/e2e.sh
