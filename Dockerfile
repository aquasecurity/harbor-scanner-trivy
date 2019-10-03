FROM alpine:3.10

RUN apk add --no-cache rpm git bash ca-certificates && update-ca-certificates

ADD trivy /usr/local/bin

ADD scanner-trivy /app/scanner-trivy

ENTRYPOINT ["/app/scanner-trivy"]
