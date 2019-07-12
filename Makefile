SOURCES := $(shell find . -name '*.go')
BINARY := trivy-adapter
IMAGE := aquasec/harbor-trivy-adapter:poc

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/trivy-adapter/main.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name trivy-adapter --rm -d -p 8080:8080 $(IMAGE)
