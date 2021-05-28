### Ubuntu
```
# Create image (Under current path of this project)
$ make ubuntu

# Compile (Under the root path of this project)
$ docker run --rm -v `pwd`:/workspace xdp_acl_ubuntu:0.0.1 bash -c "make clean && make"
```


### Fedora
```
# Create image (Under current path of this project)
$ make fedora

# Compile (Under the root path of this project)
$ docker run --rm -v `pwd`:/workspace xdp_acl_fedora:0.0.1 bash -c "make clean && make"
```

