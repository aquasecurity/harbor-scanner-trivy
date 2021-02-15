[![GitHub Release][release-img]][release]
[![GitHub Build Actions][build-action-img]][actions]
[![GitHub Release Actions][release-action-img]][actions]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]
![Docker Pulls / Aqua][docker-pulls-aqua]
![Docker Pulls / Harbor][docker-pulls-harbor]

# Harbor Scanner Adapter for Trivy

The Harbor [Scanner Adapter][harbor-pluggable-scanners] for [Trivy][trivy] is a service that translates
the [Harbor][harbor] scanning API into Trivy commands and allows Harbor to use Trivy for providing vulnerability
reports on images stored in Harbor registry as part of its vulnerability scan feature.

## TOC

- [Deployment](#deployment)
  - [Harbor >= 2.0 on Kubernetes](#harbor--20-on-kubernetes)
  - [Harbor 1.10 on Kubernetes](#harbor-110-on-kubernetes)
- [Configuration](#configuration)
- [Documentation](#documentation)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)


## Deployment

### Harbor >= 2.0 on Kubernetes

In Harbor >= 2.0 Trivy can be configured as the default vulnerability scanner, therefore you can install it with the
official Harbor [Helm chart][harbor-helm-chart], where `HARBOR_CHART_VERSION` >= 1.4:

```
$ helm repo add harbor https://helm.goharbor.io
```

```
$ HARBOR_CHART_VERSION=<chart version>
$
$ helm install harbor harbor/harbor \
    --version=$HARBOR_CHART_VERSION \
    --namespace harbor \
    --set clair.enabled=false \
    --set trivy.enabled=true
```

The adapter service is automatically registered under the **Interrogation Service** in the Harbor interface and
designated as the default scanner.

### Harbor 1.10 on Kubernetes

1. Generate certificate and private key files:
   ```
   $ openssl genrsa -out tls.key 2048
   $ openssl req -new -x509 \
       -key tls.key \
       -out tls.crt \
       -days 365 \
       -subj /CN=harbor-scanner-trivy.harbor
   ```
   > **NOTE:** The Common Name (CN) is the fully qualified domain name of the
   > adapter service. In this example we assumed that it is exposed as the
   > `harbor-scanner-trivy` service in the `harbor` namespace.
2. Install the `harbor-scanner-trivy` chart:
   ```
   $ helm repo add aqua https://helm.aquasec.com
   ```
   ```
   $ helm install harbor-scanner-trivy aqua/harbor-scanner-trivy \
       --namespace harbor \
       --set service.port=8443 \
       --set scanner.api.tlsEnabled=true \
       --set scanner.api.tlsCertificate="$(cat tls.crt)" \
       --set scanner.api.tlsKey="$(cat tls.key)"
   ```
3. Configure the scanner adapter in the Harbor interface.
   1. Navigate to **Interrogation Services** and click **+ NEW SCANNER**.
      ![Scanners config](docs/images/harbor_ui_scanners_config.png)
   2. Enter https://harbor-scanner-trivy.harbor:8443 as the **Endpoint** URL and click **TEST CONNECTION**.
      ![Add scanner](docs/images/harbor_ui_add_scanner.png)
   3. If everything is fine click **ADD** to save the configuration.
4. Select the **Trivy** scanner and set it as default by clicking **SET AS DEFAULT**.
   ![Set Trivy as default scanner](docs/images/harbor_ui_set_trivy_as_default_scanner.png)
   Make sure the **Default** label is displayed next to the **Trivy** scanner's name.

## Configuration

Configuration of the adapter is done via environment variables at startup.

|                  Name                     |                  Default           | Description |
|-------------------------------------------|------------------------------------|-------------|
| `SCANNER_LOG_LEVEL`                       | `info`                             | The log level of `trace`, `debug`, `info`, `warn`, `warning`, `error`, `fatal` or `panic`. The standard logger logs entries with that level or anything above it. |
| `SCANNER_API_SERVER_ADDR`                 | `:8080`                            | Binding address for the API server                                                   |
| `SCANNER_API_SERVER_TLS_CERTIFICATE`      | N/A                                | The absolute path to the x509 certificate file                                       |
| `SCANNER_API_SERVER_TLS_KEY`              | N/A                                | The absolute path to the x509 private key file                                       |
| `SCANNER_API_SERVER_CLIENT_CAS`           | N/A                                | A list of absolute paths to x509 root certificate authorities that the api use if required to verify a client certificate |
| `SCANNER_API_SERVER_READ_TIMEOUT`         | `15s`                              | The maximum duration for reading the entire request, including the body              |
| `SCANNER_API_SERVER_WRITE_TIMEOUT`        | `15s`                              | The maximum duration before timing out writes of the response                        |
| `SCANNER_API_SERVER_IDLE_TIMEOUT`         | `60s`                              | The maximum amount of time to wait for the next request when keep-alives are enabled |
| `SCANNER_TRIVY_CACHE_DIR`                 | `/home/scanner/.cache/trivy`       | Trivy cache directory                                                                |
| `SCANNER_TRIVY_REPORTS_DIR`               | `/home/scanner/.cache/reports`     | Trivy reports directory                                                              |
| `SCANNER_TRIVY_DEBUG_MODE`                | `false`                            | The flag to enable or disable Trivy debug mode                                       |
| `SCANNER_TRIVY_VULN_TYPE`                 | `os,library`                       | Comma-separated list of vulnerability types. Possible values are `os` and `library`. |
| `SCANNER_TRIVY_SEVERITY`                  | `UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL` | Comma-separated list of vulnerabilities severities to be displayed                   |
| `SCANNER_TRIVY_IGNORE_UNFIXED`            | `false`                            | The flag to display only fixed vulnerabilities                                       |
| `SCANNER_TRIVY_SKIP_UPDATE`               | `false`                            | The flag to enable or disable [Trivy DB][trivy-db] downloads from GitHub             |
| `SCANNER_TRIVY_GITHUB_TOKEN`              | N/A                                | The GitHub access token to download [Trivy DB][trivy-db] (see [GitHub rate limiting][gh-rate-limit]) |
| `SCANNER_TRIVY_INSECURE`                  | `false`                            | The flag to skip verifying registry certificate                                      |
| `SCANNER_STORE_REDIS_NAMESPACE`           | `harbor.scanner.trivy:store`       | The namespace for keys in the Redis store                                            |
| `SCANNER_STORE_REDIS_SCAN_JOB_TTL`        | `1h`                               | The time to live for persisting scan jobs and associated scan reports                |
| `SCANNER_JOB_QUEUE_REDIS_NAMESPACE`       | `harbor.scanner.trivy:job-queue`   | The namespace for keys in the scan jobs queue backed by Redis                        |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY`    | `1`                                | The number of workers to spin-up for the scan jobs queue                             |
| `SCANNER_REDIS_URL`                       | `redis://harbor-harbor-redis:6379` | The Redis server URI. The URI supports schemas to connect to a standalone Redis server, i.e. `redis://:password@standalone_host:port/db-number` and Redis Sentinel deployment, i.e. `redis+sentinel://:password@sentinel_host1:port1,sentinel_host2:port2/monitor-name/db-number`. |
| `SCANNER_REDIS_POOL_MAX_ACTIVE`           | `5`                                | The max number of connections allocated by the Redis connection pool                 |
| `SCANNER_REDIS_POOL_MAX_IDLE`             | `5`                                | The max number of idle connections in the Redis connection pool                      |
| `SCANNER_REDIS_POOL_IDLE_TIMEOUT`         | `5m`                               | The duration after which idle connections to the Redis server are closed. If the value is zero, then idle connections are not closed. |
| `SCANNER_REDIS_POOL_CONNECTION_TIMEOUT`   | `1s`                               | The timeout for connecting to the Redis server                                       |
| `SCANNER_REDIS_POOL_READ_TIMEOUT`         | `1s`                               | The timeout for reading a single Redis command reply                                 |
| `SCANNER_REDIS_POOL_WRITE_TIMEOUT`        | `1s`                               | The timeout for writing a single Redis command.                                      |
| `HTTP_PROXY`                              | N/A                                | The URL of the HTTP proxy server                                                     |
| `HTTPS_PROXY`                             | N/A                                | The URL of the HTTPS proxy server                                                    |
| `NO_PROXY`                                | N/A                                | The URLs that the proxy settings do not apply to                                     |

## Documentation

- [Architecture](./docs/ARCHITECTURE.md) - architectural decisions behind designing harbor-scanner-trivy.
- [Releases](./docs/RELEASES.md) - how to release a new version of harbor-scanner-trivy.

## Troubleshooting

### Error: database error: --skip-update cannot be specified on the first run

If you set the value of the `SCANNER_TRIVY_SKIP_UPDATE` to `true`, make sure that you download the Trivy DB
from [GitHub][trivy-db] and mount it in the `/home/scanner/.cache/trivy/db/trivy.db` path.

### Error: failed to list releases: GET https://api.github.com/repos/aquasecurity/trivy-db/releases: 403 API rate limit exceeded

Trivy DB downloads from GitHub are subject to [rate limiting][gh-rate-limit]. Make sure that the Trivy DB is mounted
and cached in the `/home/scanner/.cache/trivy/db/trivy.db` path. If, for any reason, it's not enough you can set the
value of the `SCANNER_TRIVY_GITHUB_TOKEN` environment variable (authenticated requests get a higher rate limit).

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct, and the process for submitting pull
requests.

[release-img]: https://img.shields.io/github/release/aquasecurity/harbor-scanner-trivy.svg?logo=github
[release]: https://github.com/aquasecurity/harbor-scanner-trivy/releases
[build-action-img]: https://github.com/aquasecurity/harbor-scanner-trivy/workflows/build/badge.svg
[release-action-img]: https://github.com/aquasecurity/harbor-scanner-trivy/workflows/release/badge.svg
[actions]: https://github.com/aquasecurity/harbor-scanner-trivy/actions
[cov-img]: https://codecov.io/github/aquasecurity/harbor-scanner-trivy/branch/main/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/harbor-scanner-trivy
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/harbor-scanner-trivy
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/harbor-scanner-trivy
[docker-pulls-aqua]: https://img.shields.io/docker/pulls/aquasec/harbor-scanner-trivy?logo=docker&label=docker%20pulls%20%2F%20aquasec
[docker-pulls-harbor]: https://img.shields.io/docker/pulls/goharbor/trivy-adapter-photon?logo=docker&label=docker%20pulls%20%2F%20goharbor
[license-img]: https://img.shields.io/github/license/aquasecurity/harbor-scanner-trivy.svg
[license]: https://github.com/aquasecurity/harbor-scanner-trivy/blob/main/LICENSE

[harbor]: https://github.com/goharbor/harbor
[harbor-helm-chart]: https://github.com/goharbor/harbor-helm
[trivy]: https://github.com/aquasecurity/trivy
[trivy-db]: https://github.com/aquasecurity/trivy-db
[latest-release-url]: https://hub.docker.com/r/aquasec/harbor-scanner-trivy/tags
[harbor-pluggable-scanners]: https://github.com/goharbor/community/blob/master/proposals/pluggable-image-vulnerability-scanning_proposal.md
[gh-rate-limit]: https://github.com/aquasecurity/trivy#github-rate-limiting
