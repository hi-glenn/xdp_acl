#### Ubuntu
```
$ git clone https://github.com/mtompkins/linux-kernel-utilities.git
$ cd linux-kernel-utilities/
$ chmod 750 *.sh
$ git pull
$ ./update_ubuntu_kernel.sh
$ reboot
```

#### Fedora
```
$ curl -s https://repos.fedorapeople.org/repos/thl/kernel-vanilla.repo | sudo tee /etc/yum.repos.d/kernel-vanilla.repo
$ dnf config-manager --set-enabled kernel-vanilla-stable
$ dnf update -y
$ reboot
```