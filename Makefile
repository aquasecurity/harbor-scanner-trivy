SOURCES := $(shell find . -name '*.go')
BINARY := scanner-trivy
IMAGE_TAG := poc
IMAGE := aquasec/harbor-scanner-trivy:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/scanner-trivy/main.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name scanner-trivy --rm -d -p 8080:8080 $(IMAGE)
