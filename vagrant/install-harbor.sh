#! /bin/bash

HARBOR_VERSION="v2.5.1"

# Keep in sync with vagrant/harbor.yml.
HARBOR_HOSTNAME="harbor.dev.io"
HARBOR_USERNAME="admin"
HARBOR_PASSWORD="Harbor12345"

# Download the Harbor installer.
# The online installer downloads the Harbor images from DockerHub. For this reason, the installer is very small in size.
wget https://github.com/goharbor/harbor/releases/download/$HARBOR_VERSION/harbor-online-installer-$HARBOR_VERSION.tgz

# Download the corresponding *.asc file to verify that the package is genuine:
wget https://github.com/goharbor/harbor/releases/download/$HARBOR_VERSION/harbor-online-installer-$HARBOR_VERSION.tgz.asc

# Obtain the public key for the *.asc file:
gpg --keyserver hkps://keyserver.ubuntu.com --receive-keys 644FF454C0B4115C

# Verify that the package is genuine:
gpg --verbose --keyserver hkps://keyserver.ubuntu.com --verify harbor-online-installer-$HARBOR_VERSION.tgz.asc

tar -C /opt -xzf harbor-online-installer-$HARBOR_VERSION.tgz
rm harbor-online-installer-$HARBOR_VERSION.tgz
rm harbor-online-installer-$HARBOR_VERSION.tgz.asc

rm /opt/harbor/harbor.yml.tmpl
cp /vagrant/vagrant/harbor.yml /opt/harbor/harbor.yml

cat << EOF >> /etc/hosts
127.0.0.1  $HARBOR_HOSTNAME
EOF

cd /opt/harbor

./install.sh --with-trivy
