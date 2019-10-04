FROM alpine:3.10.2

RUN apk update && apk add --no-cache rpm git bash ca-certificates && update-ca-certificates

COPY trivy /usr/local/bin

COPY scanner-trivy /app/scanner-trivy

ENTRYPOINT ["/app/scanner-trivy"]
