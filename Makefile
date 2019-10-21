SOURCES := $(shell find . -name '*.go')
BINARY := scanner-trivy
IMAGE_TAG := dev
IMAGE := aquasec/harbor-scanner-trivy:$(IMAGE_TAG)

build: $(BINARY)

test: build
	GO111MODULE=on go test -v -short -race -coverprofile=coverage.txt -covermode=atomic ./...

test-integration: build
	GO111MODULE=on go test -v -tags=integration ./test/integration/...

test-component: build
	GO111MODULE=on go test -v -tags=component ./test/component/...

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o $(BINARY) cmd/scanner-trivy/main.go

container: build
	docker build --no-cache -t $(IMAGE) .

container-run: container
	docker run --name scanner-trivy --rm -d -p 8080:8080 $(IMAGE)
