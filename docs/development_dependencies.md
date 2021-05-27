
### Install dependencies

##### Download and install [Golang](https://golang.org/dl/)

##### Platform dependencies

  - Ubuntu20.04 or later

  ```
  $ apt update
  $ apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential -y
  $ apt install linux-tools-$(uname -r) -y
  $ apt install linux-tools-common linux-tools-generic -y
  ```

  - Fedora31 or later

  ```
  $ dnf install clang llvm -y
  $ dnf install elfutils-libelf-devel libpcap-devel perf -y
  $ dnf install kernel-headers -y
  $ dnf install bpftool -y
  ```

### Compile
After the environment is ok, you can execute the following cmds(root privileges) under project path.

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