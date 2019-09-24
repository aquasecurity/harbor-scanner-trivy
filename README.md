# harbor-scanner-trivy

```bash
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl apply -f kube/harbor-scanner-trivy.yaml
```

```bash
kubectl port-forward service/harbor-scanner-trivy 8080:8080 &> /dev/null &

curl -v http://localhost:8080/api/v1
```

## Configuration

| Name                        | Default Value | Description |
|-----------------------------|---------------|-------------|
| `SCANNER_API_ADDR`          | `:8080`       | Binding address for the API server. |
| `SCANNER_API_READ_TIMEOUT`  | `15s`         | The maximum duration for reading the entire request, including the body. |
| `SCANNER_API_WRITE_TIMEOUT` | `15s`         | The maximum duration before timing out writes of the response. |
| `SCANNER_STORE_REDIS_URL`       | `redis://localhost:6379`          | Redis server URI for a redis store. |
| `SCANNER_STORE_REDIS_NAMESPACE` | `harbor.scanner.trivy:data-store` | A namespace for keys in a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE` | 5 | The max number of connections allocated by the pool for a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`   | 5 | The max number of idle connections in the pool for a redis store. |
| `SCANNER_JOB_QUEUE_REDIS_URL`         | `redis://localhost:6379`         | Redis server URI for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_NAMESPACE`   | `harbor.scanner.trivy:job-queue` | A namespace for keys in a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_ACTIVE` | 5 | The max number of connections allocated by the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_IDLE`   | 5 | The max number of idle connections in the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY`    | 1 | The number of workers to spin-up for a jobs queue. |
