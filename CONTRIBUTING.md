# Contributing

## Table of Contents

* [Set up your Development Environment](#set-up-your-development-environment)
* [Build Binaries](#build-binaries)
* [Test Scanner Adapter](#test-scanner-adapter)
  * [Prerequisites](#prerequisites)
  * [Update Container Image](#update-container-image)
* [Run Tests](#run-tests)
  * [Run Unit Tests](#run-unit-tests)
  * [Run Integration Tests](#run-integration-tests)
  * [Run Component Tests](#run-component-tests)

## Set up your Development Environment

1. Install Go

   The project requires [Go 1.14][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Get the source code:

   ```
   $ git clone https://github.com/aquasecurity/harbor-scanner-trivy.git
   $ cd harbor-scanner-trivy
   ```
3. Install Docker and Docker Compose

## Build Binaries

Run `make` to build the binary in `./scanner-trivy`:

```
$ make
```

To build into a Docker container `aquasec/harbor-scanner-trivy:dev`:

```
$ make docker-build
```

## Test Scanner Adapter

### Prerequisites

Install Harbor with [Harbor installer](https://goharbor.io/docs/2.1.0/install-config/download-installer/).
Make sure that you install Harbor with Trivy, i.e. `sudo ./install.sh --with-trivy`.

```
$ docker ps
CONTAINER ID   IMAGE                                  COMMAND                  CREATED              STATUS                        PORTS                       NAMES
d9f49e0f6e91   goharbor/harbor-jobservice:v2.1.1      "/harbor/entrypoint.…"   About a minute ago   Up About a minute (healthy)                               harbor-jobservice
599b2a030413   goharbor/nginx-photon:v2.1.1           "nginx -g 'daemon of…"   About a minute ago   Up About a minute (healthy)   0.0.0.0:80->8080/tcp        nginx
dfc40b34a5b9   goharbor/harbor-core:v2.1.1            "/harbor/entrypoint.…"   About a minute ago   Up About a minute (healthy)                               harbor-core
ef409cf2e131   goharbor/trivy-adapter-photon:v2.1.1   "/home/scanner/entry…"   About a minute ago   Up About a minute (healthy)                               trivy-adapter
d580ffa61f80   goharbor/harbor-registryctl:v2.1.1     "/home/harbor/start.…"   About a minute ago   Up About a minute (healthy)                               registryctl
45f0c9c877bd   goharbor/registry-photon:v2.1.1        "/home/harbor/entryp…"   About a minute ago   Up About a minute (healthy)                               registry
55e123d51250   goharbor/harbor-portal:v2.1.1          "nginx -g 'daemon of…"   About a minute ago   Up About a minute (healthy)                               harbor-portal
2afdf3ad0d35   goharbor/redis-photon:v2.1.1           "redis-server /etc/r…"   About a minute ago   Up About a minute (healthy)                               redis
e473ae5119b1   goharbor/harbor-db:v2.1.1              "/docker-entrypoint.…"   About a minute ago   Up About a minute (healthy)                               harbor-db
c302f3cd1907   goharbor/harbor-log:v2.1.1             "/bin/sh -c /usr/loc…"   About a minute ago   Up About a minute (healthy)   127.0.0.1:1514->10514/tcp   harbor-log
```

### Update Container Image

1. Navigate to Harbor installation directory.
2. Stop Harbor services:
   ```
   $ docker-compose down
   ```
3. Build a new version of the adapter service into a Docker container `aquasec/harbor-scanner-trivy:dev`:
   ```
   $ make docker-build
   ```
4. Edit the `docker-compose.yml` file and replace the adapter's image with the one that we've just built:
   ```yaml
   version: '2.3'
   services:
     trivy-adapter:
       container_name: trivy-adapter
       # image: goharbor/trivy-adapter-photon:v2.1.1
       image: aquasec/harbor-scanner-trivy:dev
       restart: always
   ```
5. Restart Harbor services:
   ```
   $ docker-compose up -d
   ```

## Run Tests

Unit testing alone doesn't provide guarantees about the behaviour of the adapter. To verify that each Go module
correctly interacts with its collaborators, more coarse grained testing is required as described in
[Testing Strategies in a Microservice Architecture][fowler-testing-strategies].

### Run Unit Tests

Run `make test` to run all unit tests:

```
$ make test
```

### Run Integration Tests

Run `make test-integration` to run integration tests:

```
$ make test-integration
```

### Run Component Tests

Run `make test-component` to run component tests:

```
$ make test-component
```

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
