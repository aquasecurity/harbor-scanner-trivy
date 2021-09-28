# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "2096"
  end

  config.vm.provision "install-docker", type: "shell", path: "vagrant/install-docker.sh"
  config.vm.provision "install-harbor", type: "shell", path: "vagrant/install-harbor.sh"
  config.vm.provision "install-go", type: "shell", path: "vagrant/install-go.sh"

  config.vm.network :forwarded_port, guest: 80, host: 8181
end
