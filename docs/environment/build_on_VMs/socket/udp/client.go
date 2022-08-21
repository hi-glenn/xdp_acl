package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func keepReceive(wgPtr *sync.WaitGroup, udpConn *net.UDPConn) {
	defer wgPtr.Done()

	data := make([]byte, 4096)
	for {
		n, _, err := udpConn.ReadFromUDP(data) // 接收数据
		if err != nil {
			fmt.Println("接收数据失败，err:", err)
			continue
		}
		fmt.Printf("recv-len: %d; recv: %v\n", n, string(data[:n]))
	}
}

func keepSend(wgPtr *sync.WaitGroup, udpConn *net.UDPConn, clientName string, interval int) {
	defer wgPtr.Done()

	num := 0
	for range time.Tick(time.Duration(interval) * time.Millisecond) {
		num++
		sendData := []byte(fmt.Sprintf("client: %s; num: %d", clientName, num))
		_, err := udpConn.Write(sendData) // 发送数据
		if err != nil {
			fmt.Println("发送数据失败，err:", err)
			continue
		}
	}
}

func main() {
	if len(os.Args) != 4 {
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

	interval, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("interval is invalid")
		return
	}

	clientName := os.Args[3]

	// 建立服务
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		fmt.Printf("listen udp server error:%v\n", err)
	} else {
		fmt.Printf("connect to %s\n", udpConn.RemoteAddr().String())
	}
	defer udpConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go keepSend(&wg, udpConn, clientName, interval)

	go keepReceive(&wg, udpConn)

	wg.Wait()
}
