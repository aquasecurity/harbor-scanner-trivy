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

   The project requires [Go 1.21][go-download] or later. We also assume that you're familiar with
   Go's [GOPATH workspace][go-code] convention, and have the appropriate environment variables set.
2. Install Docker, Make, and Skaffold.
3. Get the source code.
   ```
   git clone https://github.com/aquasecurity/harbor-scanner-trivy.git
   cd harbor-scanner-trivy
   ```

## Set up Development Environment with Kubernetes

1. Get the source code.
   ```
   git clone --recursive https://github.com/aquasecurity/harbor-scanner-trivy.git
   cd harbor-scanner-trivy
   ```
2. Launch a Kubernetes cluster
   
   We recommend setting up a Kubernetes cluster with:

   - [kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
   - [minikube](https://minikube.sigs.k8s.io/docs/start/)
   - [Docker Desktop](https://docs.docker.com/desktop/)
   - [Rancher Desktop](https://docs.rancherdesktop.io/ui/preferences/kubernetes/)
    
   However, you can use any Kubernetes cluster you want.

   In case of kind, you can use the following command to create a cluster:
   ```
   kind create cluster --name harbor-scanner-trivy
   ```

3. Run Skaffold
 
   The following command will build the image and deploy Harbor with the scanner adapter to the Kubernetes cluster:
   ```
   make dev
   ```

4. Access Harbor UI

   After the Harbor chart is deployed, you can access `https://core.harbor.domain`.
   It depends on how you configure the Kubernetes cluster, but you may need to add a host entry to `/etc/hosts` file.
 
   ```
   echo "127.0.0.1\tcore.harbor.domain" | sudo tee -a /etc/hosts
   ```
   
   username: admin, password: Harbor12345

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

Install Harbor with [Harbor installer](https://goharbor.io/docs/2.4.0/install-config/download-installer/).
Make sure that you install Harbor with Trivy, i.e. `sudo ./install.sh --with-trivy`.

```console
$ docker ps
CONTAINER ID   IMAGE                                  COMMAND                  CREATED          STATUS                             PORTS                                   NAMES
776c0b424d23   goharbor/trivy-adapter-photon:v2.5.1   "/home/scanner/entry…"   22 seconds ago   Up 22 seconds (health: starting)                                           trivy-adapter
7d50e1196823   goharbor/harbor-jobservice:v2.5.1      "/harbor/entrypoint.…"   39 minutes ago   Up 39 minutes (healthy)                                                    harbor-jobservice
70d08da89eed   goharbor/nginx-photon:v2.5.1           "nginx -g 'daemon of…"   39 minutes ago   Up 39 minutes (healthy)            0.0.0.0:80->8080/tcp, :::80->8080/tcp   nginx
041d5fdae1fd   goharbor/harbor-core:v2.5.1            "/harbor/entrypoint.…"   39 minutes ago   Up 39 minutes (healthy)                                                    harbor-core
4601fbbee7ee   goharbor/harbor-registryctl:v2.5.1     "/home/harbor/start.…"   39 minutes ago   Up 39 minutes (healthy)                                                    registryctl
9c6dc4f126ca   goharbor/harbor-portal:v2.5.1          "nginx -g 'daemon of…"   39 minutes ago   Up 39 minutes (healthy)                                                    harbor-portal
b42391dd9b69   goharbor/registry-photon:v2.5.1        "/home/harbor/entryp…"   39 minutes ago   Up 39 minutes (healthy)                                                    registry
3ddd1913c9cb   goharbor/redis-photon:v2.5.1           "redis-server /etc/r…"   39 minutes ago   Up 39 minutes (healthy)                                                    redis
33ddb8a8e9b3   goharbor/harbor-db:v2.5.1              "/docker-entrypoint.…"   39 minutes ago   Up 39 minutes (healthy)                                                    harbor-db
dfaff72310c5   goharbor/harbor-log:v2.5.1             "/bin/sh -c /usr/loc…"   39 minutes ago   Up 39 minutes (healthy)            127.0.0.1:1514->10514/tcp               harbor-log
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
4. Edit the `docker-compose.yml` file and replace the adapter's image with the one that you've just built.
   ```yaml
   version: '2.3'
   services:
     trivy-adapter:
       container_name: trivy-adapter
       # image: goharbor/trivy-adapter-photon:v2.4.1
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
