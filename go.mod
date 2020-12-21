module github.com/aquasecurity/harbor-scanner-trivy

go 1.14

require (
	github.com/FZambia/sentinel v1.1.0
	github.com/caarlos0/env/v6 v6.3.0
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v17.12.0-ce-rc1.0.20200916142827-bd33bbf0497b+incompatible
	github.com/docker/go-connections v0.4.0
	github.com/gocraft/work v0.5.1
	github.com/gomodule/redigo v2.0.0+incompatible
	github.com/gorilla/mux v1.7.4
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/prometheus/client_golang v1.5.1
	github.com/robfig/cron v1.2.0 // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.6.1
	github.com/testcontainers/testcontainers-go v0.9.0
	golang.org/x/net v0.0.0-20190613194153-d28f0bde5980
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
)
