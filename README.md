# harbor-scanner-trivy

```bash
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl -n harbor apply -f kube/harbor-scanner-trivy.yaml
```

```bash
kubectl port-forward service/harbor-scanner-trivy 8080:8080 &> /dev/null &

curl -v http://localhost:8080/api/v1
```
