#! /bin/bash

wget --quiet https://golang.org/dl/go1.16.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.16.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile

sudo apt-get update
sudo apt-get install --yes build-essential
