package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("params error")
		return
	}

	hostPort := strings.Split(os.Args[1], ":")

	if len(hostPort) != 2 {
		fmt.Println("params error")
		return
	}

	ip := net.ParseIP(hostPort[0])
	port, err := strconv.Atoi(hostPort[1])
	if err != nil {
		fmt.Println("port is invalid")
		return
	}

	// 建立 udp 服务器
	listen, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		fmt.Printf("listen failed error:%v\n", err)
		return
	} else {
		fmt.Printf("udp server listen on: %s\n", listen.LocalAddr())
	}
	defer listen.Close() // 使用完关闭服务

	num := 0
	for {
		// 接收数据
		var data [1024]byte
		n, addr, err := listen.ReadFromUDP(data[:])
		if err != nil {
			fmt.Printf("read data error:%v\n", err)
			return
		}
		fmt.Printf("from: %s; %v\n", addr, string(data[:n]))

		// 发送数据
		num++
		_, err = listen.WriteToUDP([]byte(fmt.Sprintf("%d", num)), addr)
		if err != nil {
			fmt.Printf("send data error:%v\n", err)
			return
		}
	}
}
