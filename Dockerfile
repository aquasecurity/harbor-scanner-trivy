# That's the only place where you're supposed to specify version of Trivy.
ARG TRIVY_VERSION=0.19.2

FROM aquasec/trivy:${TRIVY_VERSION}

# Fix CVE-2021-36159 and CVE-2021-3711 in Trivy base image v0.19.2.
RUN apk update && apk upgrade apk-tools libcrypto1.1 libssl1.1

# An ARG declared before a FROM is outside of a build stage, so it can't be used in any
# instruction after a FROM. To use the default value of an ARG declared before the first
# FROM use an ARG instruction without a value inside of a build stage.
ARG TRIVY_VERSION

RUN adduser -u 10000 -D -g '' scanner scanner

COPY scanner-trivy /home/scanner/bin/scanner-trivy

ENV TRIVY_VERSION=${TRIVY_VERSION}

USER scanner

ENTRYPOINT ["/home/scanner/bin/scanner-trivy"]
