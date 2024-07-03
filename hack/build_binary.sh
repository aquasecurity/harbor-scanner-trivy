#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

BUILD_GOOS=${GOOS:-linux}
BUILD_GOARCH=${GOARCH:-amd64}
GOBINARY=${GOBINARY:-go}

BINARY="scanner-trivy"

GOOS=${BUILD_GOOS} CGO_ENABLED=0 GO111MODULE=on GOARCH=${BUILD_GOARCH} \
${GOBINARY} build -o ${BINARY} cmd/scanner-trivy/main.go