SOURCES := $(shell find . -name '*.go')
BINARY := scanner-trivy
IMAGE_TAG := 0.30.23-dev
IMAGE := aquasec/harbor-scanner-trivy:$(IMAGE_TAG)

.PHONY: build test test-integration test-component docker-build setup dev debug run

build:
	hack/build_binary.sh

test: build
	GO111MODULE=on go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

test-integration: build
	GO111MODULE=on go test -count=1 -v -tags=integration ./test/integration/...

.PHONY: test-component
test-component: docker-build
	GO111MODULE=on go test -count=1 -v -tags=component ./test/component/...

$(BINARY): $(SOURCES)
    GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/scanner-trivy/main.go

.PHONY: docker-build
docker-build: build
	docker build --no-cache -t $(IMAGE) .

lint:
	./bin/golangci-lint --build-tags component,integration run -v

setup:
	curl -sfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh| sh -s v1.21.0

submodule:
	git submodule update --init --recursive

dev:
	skaffold dev --tolerate-failures-until-deadline=true

debug:
	skaffold debug --tolerate-failures-until-deadline=true

run: export SCANNER_TRIVY_CACHE_DIR = $(TMPDIR)harbor-scanner-trivy/.cache/trivy
run: export SCANNER_TRIVY_REPORTS_DIR=$(TMPDIR)harbor-scanner-trivy/.cache/reports
run: export SCANNER_LOG_LEVEL=debug
run:
	@mkdir -p $(SCANNER_TRIVY_CACHE_DIR) $(SCANNER_TRIVY_REPORTS_DIR)
	@go run cmd/scanner-trivy/main.go
