#! /bin/bash

# Keep in sync with vagrant/harbor.yml.
HARBOR_HOSTNAME="harbor.dev.io"
HARBOR_USERNAME="admin"
HARBOR_PASSWORD="Harbor12345"

echo "$HARBOR_PASSWORD" | docker login --username=$HARBOR_USERNAME --password-stdin $HARBOR_HOSTNAME

for image in "alpine:3.14" "photon:3.0-20200202" "gcr.io/distroless/java:11" "debian:9" "amazonlinux:2.0.20200406.0"
do
  docker image pull $image
  docker image tag $image "$HARBOR_HOSTNAME/library/$image"
  docker image push "$HARBOR_HOSTNAME/library/$image"
done
