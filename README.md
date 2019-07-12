# harbor-trivy-adapter

```
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl -n harbor apply -f kube/harbor-trivy-adapter.yaml
```

