FROM alpine

RUN apk add --no-cache git bash ca-certificates && update-ca-certificates

ADD trivy /usr/local/bin

ADD bin/trivy-adapter /app/trivy-adapter

# TODO This is just for testing (remote it later on).
RUN mkdir -p /tmp/trivy

ENTRYPOINT ["/app/trivy-adapter"]
