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

