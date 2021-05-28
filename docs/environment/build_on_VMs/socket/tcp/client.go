package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func readDadaFromConsoleAndSend(connPtr *net.Conn) {
	// 使用 conn 连接进行数据的发送和接收
	input := bufio.NewReader(os.Stdin)
	for {
		s, _ := input.ReadString('\n')
		s = strings.TrimSpace(s)
		if strings.ToUpper(s) == "Q" {
			return
		}

		_, err := (*connPtr).Write([]byte(s))
		if err != nil {
			fmt.Printf("send failed, err:%v\n", err)
			return
		}

		// 从服务端接收回复消息
		var buf [1024]byte
		n, err := (*connPtr).Read(buf[:])
		if err != nil {
			fmt.Printf("read failed:%v\n", err)
			return
		}
		fmt.Printf("收到服务端回复:%v\n", string(buf[:n]))
	}
}

func keepSend(connPtr *net.Conn, wgPtr *sync.WaitGroup, clientName string, interval int) {
	defer wgPtr.Done()

	var num int

	for range time.Tick(time.Duration(interval) * time.Millisecond) {
		num++

		str := fmt.Sprintf("client: %s; num: %d", clientName, num)

		_, err := (*connPtr).Write([]byte(str))
		if err != nil {
			fmt.Printf("send failed, err:%v\n", err)
			return
		}
	}
}

func keepReceive(connPtr *net.Conn, wgPtr *sync.WaitGroup) {
	defer wgPtr.Done()

	for {
		var buf [1024]byte
		n, err := (*connPtr).Read(buf[:])
		if err != nil {
			fmt.Printf("read failed:%v\n", err)
			return
		}
		fmt.Printf("rcv: %v\n", string(buf[:n]))
	}
}

func main() {

	if len(os.Args) != 4 {
		fmt.Println("params error")
		return
	}

	interval, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("interval is invalid")
		return
	}

	hostPort := os.Args[1]

	clientName := os.Args[3]

	fmt.Printf("will connect to: %s; clientName: %s; interval: %d\n", hostPort, clientName, interval)

	conn, err := net.Dial("tcp", hostPort)
	if err != nil {
		fmt.Printf("conn server failed, err:%v\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go keepSend(&conn, &wg, clientName, interval)
	go keepReceive(&conn, &wg)

	wg.Wait()

	// readDadaFromConsoleAndSend(conn)
}
