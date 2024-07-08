module github.com/aquasecurity/harbor-scanner-trivy

go 1.22

require (
	github.com/alicebob/miniredis/v2 v2.33.0
	github.com/aquasecurity/bolt-fixtures v0.0.0-20200903104109-d34e7f983986
	github.com/caarlos0/env/v6 v6.10.1
	github.com/docker/docker v27.0.3+incompatible
	github.com/docker/go-connections v0.5.0
	github.com/google/go-containerregistry v0.14.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/schema v1.4.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/prometheus/client_golang v1.19.0
	github.com/redis/go-redis/v9 v9.5.1
	github.com/samber/lo v1.39.0
	github.com/stretchr/testify v1.9.0
	github.com/testcontainers/testcontainers-go v0.31.0
	golang.org/x/net v0.25.0
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Microsoft/hcsshim v0.11.4 // indirect
	github.com/alicebob/gopher-json v0.0.0-20200520072559-a9ecdc9d1d3a // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.2.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/containerd v1.7.15 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.14.3 // indirect
	github.com/cpuguy83/dockercfg v0.3.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/docker/cli v24.0.0+incompatible // indirect
	github.com/docker/distribution v2.8.2+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/fatih/color v1.9.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/goccy/go-yaml v1.8.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.16.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mattn/go-colorable v0.1.7 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.48.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/shirou/gopsutil/v3 v3.23.12 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/vbatts/tar-split v0.11.3 // indirect
	github.com/yuin/gopher-lua v1.1.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.3 // indirect
	go.etcd.io/bbolt v1.3.7 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.49.0 // indirect
	go.opentelemetry.io/otel v1.24.0 // indirect
	go.opentelemetry.io/otel/metric v1.24.0 // indirect
	go.opentelemetry.io/otel/trace v1.24.0 // indirect
	golang.org/x/crypto v0.23.0 // indirect
	golang.org/x/exp v0.0.0-20230510235704-dd950f8aeaea // indirect
	golang.org/x/mod v0.16.0 // indirect
	golang.org/x/sync v0.3.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230731190214-cbb8c96f2d6d // indirect
	google.golang.org/grpc v1.58.3 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/google/go-containerregistry => github.com/knqyf263/go-containerregistry v0.16.2-0.20231101014841-fd95d0f749dd
