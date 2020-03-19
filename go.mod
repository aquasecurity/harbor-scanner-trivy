module github.com/aquasecurity/harbor-scanner-trivy

go 1.13

require (
	github.com/caarlos0/env/v6 v6.0.0
	github.com/docker/docker v0.7.3-0.20190506211059-b20a14b54661
	github.com/docker/go-connections v0.4.0
	github.com/gocraft/work v0.5.1
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/gorilla/mux v1.7.3
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/prometheus/client_golang v1.2.1
	github.com/robfig/cron v1.2.0 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	github.com/testcontainers/testcontainers-go v0.3.1
	golang.org/x/net v0.0.0-20191108221443-4ba9e2ef068c
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898
)
