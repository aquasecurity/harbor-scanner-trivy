# Contributing

## Table of Contents

* [Set up Local Development Environment](#set-up-local-development-environment)
* [Set up Development Environment with Vagrant](#setup-development-environment-with-vagrant)
* [Build Binaries](#build-binaries)
* [Test Scanner Adapter](#test-scanner-adapter)
  * [Prerequisites](#prerequisites)
  * [Update Container Image](#update-container-image)
* [Run Tests](#run-tests)
  * [Run Unit Tests](#run-unit-tests)
  * [Run Integration Tests](#run-integration-tests)
  * [Run Component Tests](#run-component-tests)

## Set up Local Development Environment

1. Install Go.

   The project requires [Go 1.16][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Install Docker, Docker Compose, and Make.
3. Get the source code.
   ```
   git clone https://github.com/aquasecurity/harbor-scanner-trivy.git
   cd harbor-scanner-trivy
   ```

## Setup Development Environment with Vagrant

1. Get the source code.
   ```
   git clone https://github.com/aquasecurity/harbor-scanner-trivy.git
   cd harbor-scanner-trivy
   ```
2. Create and configure a guest development machine, which is based on Ubuntu 20.4 LTS and has Go, Docker, Docker Compose,
   Make, and Harbor v2.3.2 preinstalled. Harbor is installed in the `/opt/harbor` directory.
   ```
   vagrant up
   ```
   If everything goes well Harbor will be accessible at http://localhost:8181 (admin/Harbor12345).

   To SSH into a running Vagrant machine.
   ```
   vagrant ssh
   ```
   The `/vagrant` directory in the development machine is shared between host and guest. This, for example, allows you
   to rebuild a container image for testing.
   ```
   vagrant@ubuntu-focal:~$ cd /vagrant
   vagrant@ubuntu-focal:/vagrant$ make docker-build
   ```

## Build Binaries

Run `make` to build the binary in `./scanner-trivy`:

```
make
```

To build into a Docker container `aquasec/harbor-scanner-trivy:dev`:

```
make docker-build
```

## Test Scanner Adapter

### Prerequisites

Install Harbor with [Harbor installer](https://goharbor.io/docs/2.3.0/install-config/download-installer/).
Make sure that you install Harbor with Trivy, i.e. `sudo ./install.sh --with-trivy`.

```console
$ docker ps
CONTAINER ID   IMAGE                                  COMMAND                  CREATED          STATUS                    PORTS                                   NAMES
c4acd5694606   goharbor/nginx-photon:v2.3.2           "nginx -g 'daemon of…"   32 seconds ago   Up 31 seconds (healthy)   0.0.0.0:80->8080/tcp, :::80->8080/tcp   nginx
c6060e31d2e3   goharbor/harbor-jobservice:v2.3.2      "/harbor/entrypoint.…"   32 seconds ago   Up 31 seconds (healthy)                                           harbor-jobservice
878cc280e634   goharbor/trivy-adapter-photon:v2.3.2   "/home/scanner/entry…"   32 seconds ago   Up 32 seconds (healthy)                                           trivy-adapter
377922e00aa1   goharbor/harbor-core:v2.3.2            "/harbor/entrypoint.…"   32 seconds ago   Up 32 seconds (healthy)                                           harbor-core
c8530be38c0c   goharbor/harbor-registryctl:v2.3.2     "/home/harbor/start.…"   33 seconds ago   Up 33 seconds (healthy)                                           registryctl
fa6015b28ea7   goharbor/harbor-db:v2.3.2              "/docker-entrypoint.…"   33 seconds ago   Up 32 seconds (healthy)                                           harbor-db
acb198e326f7   goharbor/registry-photon:v2.3.2        "/home/harbor/entryp…"   33 seconds ago   Up 32 seconds (healthy)                                           registry
fb445cb08b1c   goharbor/harbor-portal:v2.3.2          "nginx -g 'daemon of…"   33 seconds ago   Up 32 seconds (healthy)                                           harbor-portal
34f4ed9a3ac1   goharbor/redis-photon:v2.3.2           "redis-server /etc/r…"   33 seconds ago   Up 32 seconds (healthy)                                           redis
157a023611ae   goharbor/harbor-log:v2.3.2             "/bin/sh -c /usr/loc…"   34 seconds ago   Up 33 seconds (healthy)   127.0.0.1:1514->10514/tcp               harbor-log
```

### Update Container Image

1. Navigate to Harbor installation directory.
2. Stop Harbor services.
   ```
   sudo docker-compose down
   ```
3. Build a new version of the adapter service into a Docker container `aquasec/harbor-scanner-trivy:dev`.
   ```
   make docker-build
   ```
4. Edit the `docker-compose.yml` file and replace the adapter's image with the one that we've just built.
   ```yaml
   version: '2.3'
   services:
     trivy-adapter:
       container_name: trivy-adapter
       # image: goharbor/trivy-adapter-photon:v2.1.1
       image: aquasec/harbor-scanner-trivy:dev
       restart: always
   ```
5. Restart Harbor services.
   ```
   sudo docker-compose up --detach
   ```

## Run Tests

Unit testing alone doesn't provide guarantees about the behaviour of the adapter. To verify that each Go module
correctly interacts with its collaborators, more coarse grained testing is required as described in
[Testing Strategies in a Microservice Architecture][fowler-testing-strategies].

### Run Unit Tests

Run `make test` to run all unit tests:

```
make test
```

### Run Integration Tests

Run `make test-integration` to run integration tests.

```
make test-integration
```

### Run Component Tests

Run `make test-component` to run component tests.

```
make test-component
```

[go-download]: https://golang.org/dl/
[go-code]: https://golang.org/doc/code.html
[fowler-testing-strategies]: https://www.martinfowler.com/articles/microservice-testing/
