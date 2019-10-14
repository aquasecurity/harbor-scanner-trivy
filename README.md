[![GitHub release][release-img]][release]
[![Build Status][ci-img]][ci]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# Harbor Scanner Adapter for Trivy

The Harbor Scanner Adapter for [Trivy][trivy-url] is a service that translates the [Harbor][harbor-url] scanning API
into Trivy commands and allows Harbor to use Trivy for providing vulnerability reports on images stored in
Harbor registry as part of its vulnerability scan feature.

> See [Pluggable Image Vulnerability Scanning Proposal][image-vulnerability-scanning-proposal] for more details.

## TOC

- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
  - [Running on minikube](#running-on-minikubeminikube-url)
- [Testing](#testing)
- [Deployment](#deployment)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## Getting started

These instructions will get you a copy of the adapter service up and running on your local machine for development
and testing purposes. See [deployment](#deployment) for notes on how to deploy on a live system.

### Prerequisites

* [Go (version 1.13)](https://golang.org/doc/devel/release.html#go1.13)
* Docker

### Build

Run `make` to build the binary in `./scanner-trivy`:

```
make
```

To build into a Docker container:

```
make container
```

### Running on [minikube][minikube-url]

1. Set up environment for the Docker client:
   ```
   $ eval $(minikube docker-env)
   ```
2. Build a Docker image `aquasec/harbor-scanner-trivy:dev`:
   ```
   $ make container
   ```
3. Create deployment and service for the scanner adapter:
   ```
   $ kubectl apply -f kube/harbor-scanner-trivy.yaml
   ```
4. Update deployment's image to `aquasec/harbor-scanner-trivy:dev`.
   ```
   $ kubectl set image deployment harbor-scanner-trivy \
     main=aquasec/harbor-scanner-trivy:poc
   ```
   > By default the deployment's image is the [latest release][latest-release-url] image published to Docker Hub.

## Testing

Run `make test` to run all unit tests:

```
make test
```

Run `make test-integration` to run integration tests:

```
make test-integration
```

## Deployment

### Kubernetes

1. Create deployment and service for the scanner adapter:
   ```
   $ kubectl apply -f kube/harbor-scanner-trivy.yaml
   ```
   > By default the deployment's image is the [latest release][latest-release-url] image published to Docker Hub.
2. Configure the scanner adapter in Harbor web console.
   1. Navigate to **Configuration** and select the **Scanners** tab and then click **+ NEW SCANNER**.
   2. Enter http://harbor-scanner-trivy:8080 as the Endpoint URL and click **TEST CONNECTION**.
      ![Add scanner](docs/images/harbor_ui_add_scanner.png)
   3. If everything is fine click **ADD** to save the configuration.
3. Select the **trivy** scanner and set it as default by clicking **SET AS DEFAULT**.
   ![Set Trivy as default scanner](docs/images/harbor_ui_set_trivy_as_default_scanner.png)
   Make sure that the **Default** label is displayed next to the **trivy** scanner name.

## Configuration

Configuration of the adapter is done via environment variables at startup.

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

## Contributing

Please read [CODE_OF_CONDUCT.md][coc-url] for details on our code of conduct, and the process for submitting pull
requests.

## License

This project is licensed under the Apache 2.0 license - see the [LICENSE](LICENSE) file for details.

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

[minikube-url]: https://github.com/kubernetes/minikube
[harbor-url]: https://github.com/goharbor/harbor
[trivy-url]: https://github.com/aquasecurity/trivy
[latest-release-url]: https://hub.docker.com/r/aquasec/harbor-scanner-trivy/tags
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/pull/98
[coc-url]: https://github.com/aquasecurity/.github/blob/master/CODE_OF_CONDUCT.md
