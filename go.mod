module github.com/aquasecurity/harbor-scanner-trivy

go 1.14

require (
	github.com/FZambia/sentinel v1.1.0
	github.com/caarlos0/env/v6 v6.6.2
	github.com/docker/docker v20.10.7+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/gocraft/work v0.5.1
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/prometheus/client_golang v1.11.0
	github.com/robfig/cron v1.2.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/testcontainers/testcontainers-go v0.11.1
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)
