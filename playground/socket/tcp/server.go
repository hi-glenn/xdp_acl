package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
)

var num int

func process(conn net.Conn) {
	// 处理完关闭连接
	defer conn.Close()

	// 针对当前连接做发送和接受操作
	for {
		reader := bufio.NewReader(conn)
		var buf [128]byte
		n, err := reader.Read(buf[:])
		if err != nil {
			fmt.Printf("read from conn failed, err:%v\n", err)
			break
		}

		recv := string(buf[:n])
		fmt.Printf("rcv: %s %v\n", conn.RemoteAddr().String(), recv)

		// 将接受到的数据返回给客户端
		num++
		_, err = conn.Write([]byte(fmt.Sprintf("%d", num)))
		if err != nil {
			fmt.Printf("write from conn failed, err:%v\n", err)
			break
		}
	}
}

func main() {
	// 建立 tcp 服务

	if len(os.Args) != 2 {
		fmt.Println("params error")
		return
	}

	hostPort := os.Args[1]

	listen, err := net.Listen("tcp", hostPort)
	if err != nil {
		fmt.Printf("listen failed, err:%v\n", err)
		return
	} else {
		fmt.Printf("listen on: %s\n", listen.Addr())
	}
	defer listen.Close()

	for {
		// 等待客户端建立连接
		conn, err := listen.Accept()
		if err != nil {
			fmt.Printf("accept failed, err:%v\n", err)
			continue
		} else {
			fmt.Printf("%s connect\n", conn.RemoteAddr().String())
		}
		// 启动一个单独的 goroutine 去处理连接
		go process(conn)
	}
}
