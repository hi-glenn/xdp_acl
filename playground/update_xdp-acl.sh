#!/bin/bash
set -e
# set -ex

echo "will update 🍏"

yes | cp -rf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

systemctl stop firewalld && systemctl disable firewalld

sleep 1s

echo "dnf update begin 🍎 It will take some time here, please be patient..."

mkdir -p /root/workspace/golang/src

echo -e "\n" >> /root/.bashrc
echo "export GOPROXY=https://goproxy.cn" >> /root/.bashrc
echo -e "\n" >> /root/.bashrc
echo "export GOPATH=~/workspace/golang" >> /root/.bashrc
echo "export GOBIN=$GOPATH/bin/" >> /root/.bashrc
echo "export PATH=$GOBIN:$PATH" >> /root/.bashrc
echo -e "\n" >> /root/.bashrc

source /root/.bashrc

dnf install golang -y -q
echo "🍊 golang version:" && go version

# dnf module install nodejs:16/default -y -q
# echo "🍊 node version:" && node -v

sleep 1s

dnf install clang -y -q
dnf install llvm -y -q
dnf install elfutils-libelf-devel -y -q
dnf install libpcap-devel -y -q
dnf install perf -y -q

dnf install kernel-headers -y -q
dnf install bpftool -y -q

# dnf install netsniff-ng -y -q

sleep 1s

dnf clean all -y

cd /root/workspace/golang/src && git clone https://github.com/glennWang/xdp_acl.git

echo "dnf update complete 😃"
