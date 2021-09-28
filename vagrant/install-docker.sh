#! /bin/bash

# This script installs Docker and Docker Compose on Ubuntu according to the official Docker documentation on
# https://docs.docker.com/engine/install/ubuntu/ and https://docs.docker.com/compose/install/.

# To list the available versions in the repo:
# apt-cache madison containerd.io docker-ce
CONTAINERD_VERSION="1.4.9-1"
DOCKER_VERSION="5:20.10.8~3-0~ubuntu-focal"
DOCKER_COMPOSE_VERSION="1.29.2"

sudo apt-get update
sudo apt-get install --yes apt-transport-https ca-certificates curl gnupg lsb-release

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

echo \
  "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install --yes containerd.io=$CONTAINERD_VERSION docker-ce=$DOCKER_VERSION docker-ce-cli=$DOCKER_VERSION

# Download the current stable release of Docker Compose:
sudo curl -L "https://github.com/docker/compose/releases/download/$DOCKER_COMPOSE_VERSION/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

# Apply executable permissions to the binary:
sudo chmod +x /usr/local/bin/docker-compose

# Add vagrant user to the docker group:
sudo usermod -aG docker vagrant

# Allow Trivy scanner adapter to resolve api.github.com.
echo '{"dns": ["192.168.1.1", "8.8.8.8"]}' > /etc/docker/daemon.json
service docker restart
