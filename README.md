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
  - [Running on minikube](#running-on-minikube)
- [Testing](#testing)
  - [Unit testing](#unit-testing)
  - [Integration testing](#integration-testing)
  - [Component testing](#component-testing)
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
2. Configure adapter to handle TLS traffic:
   1. Generate certificate and private key files:
      ```
      $ openssl genrsa -out tls.key 2048
      $ openssl req -new -x509 \
        -key tls.key \
        -out tls.crt \
        -days 365 \
        -subj /CN=harbor-scanner-trivy
      ```
   2. Create a `tls` Secret from the two generated files:
      ```
      $ kubectl create secret tls harbor-scanner-trivy-tls \
        --cert=tls.crt \
        --key=tls.key
      ```
3. Create StatefulSet and Service for the scanner adapter:
   ```
   $ kubectl apply -f kube/harbor-scanner-trivy.yaml
   ```
   > By default the StatefulSet refers to the latest release image published to [Docker Hub][latest-release-url].
4. Scale down the StatefulSet:
   ```
   $ kubectl scale sts harbor-scanner-trivy --replicas=0
   ```
5. Build a Docker image `aquasec/harbor-scanner-trivy:dev`:
   ```
   $ make container
   ```
6. Update StatefulSet's image to `aquasec/harbor-scanner-trivy:dev`
   ```
   $ kubectl set image sts harbor-scanner-trivy \
     main=aquasec/harbor-scanner-trivy:dev
   ```
7. Scale up the StatefulSet:
   ```
   $ kubectl scale sts harbor-scanner-trivy --replicas=1
   ```

## Testing

Unit testing alone doesn't provide guarantees about the behaviour of the adapter. To verify that each Go module
correctly interacts with its collaborators, more coarse grained testing is required as described in
[Testing Strategies in a Microservice Architecture][fowler-testing-strategies].

### Unit testing

> A *unit test* exercises the smallest piece of testable software in the application to determine whether it behaves
> as expected.

Run `make test` to run all unit tests:

```
make test
```

### Integration testing

> An *integration* test verifies the communication paths and interactions between components to detect interface defects.

Run `make test-integration` to run integration tests:

```
make test-integration
```

### Component testing

> A *component test* limits the scope of the exercised software to a portion of the system under test, manipulating the
> system through internal code interfaces and using test doubles to isolate the code under test from other components.
> In a microservice architecture, the components are the services themselves.

Running out of process component tests is not fully automated yet (see [#38][issue-38]). However, you can run them
as follows:

```
docker-compose -f test/component/docker-compose.yaml up -d
make test-component
docker-compose -f test/component/docker-compose.yaml down
```

## Deployment

### Kubernetes

1. Configure adapter to handle TLS traffic:
   1. Create a `tls` Secret from the private kay and certificate files:
      ```
      $ kubectl create secret tls harbor-scanner-trivy-tls \
        --cert=tls.cert \
        --key=tls.key
      ```
2. Create StatefulSet and Service for the scanner adapter:
   ```
   $ kubectl apply -f kube/harbor-scanner-trivy.yaml
   ```
   > By default the StatefulSet refers to the latest release image published to [Docker Hub][latest-release-url].
3. Configure the scanner adapter in Harbor web console.
   1. Navigate to **Configuration** and select the **Scanners** tab and then click **+ NEW SCANNER**.
      ![Scanners config](docs/images/harbor_ui_scanners_config.png)
   2. Enter https://harbor-scanner-trivy:8443 as the Endpoint URL and click **TEST CONNECTION**.
      ![Add scanner](docs/images/harbor_ui_add_scanner.png)
   3. If everything is fine click **ADD** to save the configuration.
4. Select the **trivy** scanner and set it as default by clicking **SET AS DEFAULT**.
   ![Set Trivy as default scanner](docs/images/harbor_ui_set_trivy_as_default_scanner.png)
   Make sure that the **Default** label is displayed next to the **trivy** scanner name.

## Configuration

Configuration of the adapter is done via environment variables at startup.

| Name | Default Value | Description |
|------|---------------|-------------|
| `SCANNER_LOG_LEVEL` | `info` | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`          | `:8080` | Binding address for the API server. |
| `SCANNER_API_SERVER_TLS_CERTIFICATE` | | The absolute path to the x509 certificate file. |
| `SCANNER_API_SERVER_TLS_KEY`         | | The absolute path to the x509 private key file. |
| `SCANNER_API_SERVER_READ_TIMEOUT`  | `15s`   | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_SERVER_WRITE_TIMEOUT` | `15s`   | The maximum duration before timing out writes of the response. |
| `SCANNER_TRIVY_CACHE_DIR`   | `/root/.cache/trivy`   | Trivy cache directory.   |
| `SCANNER_TRIVY_REPORTS_DIR` | `/root/.cache/reports` | Trivy reports directory. |
| `SCANNER_TRIVY_DEBUG_MODE`  | `false` | The flag to enable or disable Trivy debug mode. |
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
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
[coc-url]: https://github.com/aquasecurity/.github/blob/master/CODE_OF_CONDUCT.md
[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
[issue-38]: https://github.com/aquasecurity/harbor-scanner-trivy/issues/38
