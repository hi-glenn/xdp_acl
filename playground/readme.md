## Environment ready
* Download and install [vagrant](https://www.vagrantup.com/downloads)

* Download and install [virtualbox](https://www.virtualbox.org/wiki/Downloads)


## Get started

#### Create VM

* Execute the following cmd under the path playground.(If it goes well, you will have two VMs called xdp-acl and trafgen.)
```
$ vagrant up
```

* Login VM xdp-acl as user vagrant
```
$ vagrant ssh xdp-acl
```

* Then switch account as root
```
$ sudo su -
```

#### Development

The project will be git clone to the following path of VM xdp-acl.
```
/root/workspace/golang/src/xdp_acl
```

Under project path, you can execute the following cmds(root privileges).

* Compile
```
$ make
```

* Clean the project
```
$ make clean
```

* Under the acl path, generate all necessary files for deploy. You can copy that path and run it on another machine
```
$ make pub
```

#### Get Started
```
# Get help
./xdp_acl -h

# Start
./xdp_acl -D eth1 -S

# Then you can view the configuration rules on the browser.
http://172.21.6.6:9090/
```

#### Test

* tcp

```
# Start tcp server on VM xdp-acl
$ /vagrant/socket/tcp/server 172.20.6.3:3333
# Start tcp client on VM trafgen
$ /vagrant/socket/tcp/client 172.20.6.3:3333 500 foo
```

* udp

```
# Start udp server on VM xdp-acl
$ /vagrant/socket/udp/server 172.20.6.3:4444
# Start udp client on VM trafgen
$ /vagrant/socket/udp/client 172.20.6.3:4444 500 bar
```

* icmp

```
# ping from VM trafgen
$ ping 172.20.6.6
```

##### Enjoy yourself ! 😄
