#! /bin/bash

# This script installs Docker CE on Ubuntu according to the official
# Docker documentation on https://docs.docker.com/engine/install/ubuntu/

# To list the available versions in the repo:
# apt-cache madison docker-ce containerd.io
DOCKER_VERSION="5:20.10.8~3-0~ubuntu-focal"
CONTAINERD_VERSION="1.4.9-1"

sudo apt-get update
sudo apt-get install --yes apt-transport-https ca-certificates curl gnupg lsb-release

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install --yes containerd.io=$CONTAINERD_VERSION docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION

# Add vagrant user to the docker group:
sudo usermod -aG docker vagrant

# Allow Trivy scanner adapter to resolve api.github.com.
echo '{"dns": ["192.168.1.1", "8.8.8.8"]}' > /etc/docker/daemon.json
service docker restart
