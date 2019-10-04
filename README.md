[![GitHub release][release-img]][release]
[![Build Status][ci-img]][ci]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# harbor-scanner-trivy

The Harbor Scanner Adapter for [Trivy][trivy-url].
See [Pluggable Image Vulnerability Scanning Proposal][image-vulnerability-scanning-proposal] for more details.

## TOC

- [Deploy to Kubernetes (minikube)](#deploy-to-kubernetes-minikube)
- [Configuration](#configuration)
- [Documentation](#documentation)

## Deploy to Kubernetes (minikube)

```
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl apply -f kube/harbor-scanner-trivy.yaml
```

```
kubectl port-forward service/harbor-scanner-trivy 8080:8080 &> /dev/null &

curl -v http://localhost:8080/api/v1/metadata
```

## Configuration

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL` | `info` | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`          | `:8080` | Binding address for the API server. |
| `SCANNER_API_SERVER_READ_TIMEOUT`  | `15s`   | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s`   | The maximum duration before timing out writes of the response. |
| `SCANNER_TRIVY_CACHE_DIR` | `/root/.cache`/ | Trivy cache directory. |
| `SCANNER_STORE_REDIS_URL`       | `redis://localhost:6379`          | Redis server URI for a redis store. |
| `SCANNER_STORE_REDIS_NAMESPACE` | `harbor.scanner.trivy:data-store` | A namespace for keys in a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE` | `5`  | The max number of connections allocated by the pool for a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`   | `5`  | The max number of idle connections in the pool for a redis store. |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`    | `1h` | The time to live for persisting scan jobs and associated scan reports. |
| `SCANNER_JOB_QUEUE_REDIS_URL`         | `redis://localhost:6379`         | Redis server URI for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_NAMESPACE`   | `harbor.scanner.trivy:job-queue` | A namespace for keys in a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_ACTIVE` | `5` | The max number of connections allocated by the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_IDLE`   | `5` | The max number of idle connections in the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY`    | `1` | The number of workers to spin-up for a jobs queue. |

## Documentation

- [Architecture](./docs/ARCHITECTURE.md): architectural decisions behind designing harbor-scanner-trivy.
- [Releases](./docs/RELEASES.md): how to release a new version of harbor-scanner-trivy.

[release-img]: https://img.shields.io/github/release/aquasecurity/harbor-scanner-trivy.svg
[release]: https://github.com/aquasecurity/harbor-scanner-trivy/releases
[ci-img]: https://travis-ci.org/aquasecurity/harbor-scanner-trivy.svg?branch=master
[ci]: https://travis-ci.org/aquasecurity/harbor-scanner-trivy
[cov-img]: https://codecov.io/github/aquasecurity/harbor-scanner-trivy/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/harbor-scanner-trivy
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/harbor-scanner-trivy
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/harbor-scanner-trivy
[license-img]: https://img.shields.io/github/license/aquasecurity/harbor-scanner-trivy.svg
[license]: https://github.com/aquasecurity/harbor-scanner-trivy/blob/master/LICENSE

[trivy-url]: https://github.com/aquasecurity/trivy
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/pull/98
