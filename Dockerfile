FROM alpine

RUN apk add --no-cache git bash ca-certificates && update-ca-certificates

ADD trivy /usr/local/bin

ADD bin/trivy-adapter /app/trivy-adapter

ENTRYPOINT ["/app/trivy-adapter"]
