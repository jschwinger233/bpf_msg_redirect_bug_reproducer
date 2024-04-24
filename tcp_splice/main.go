package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
)

const SPLICE_F_NONBLOCK = 0x02

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <netloc>\ne.g. \"%s localhost:8000\"\n", os.Args[0], os.Args[0])
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", os.Args[1])
	if err != nil {
		log.Fatalf("Error resolving TCP address: %v", err)
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		log.Fatalf("Error dialing TCP: %v", err)
	}
	defer conn.Close()

	request := "GET / HTTP/1.1\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		log.Fatalf("Error writing to TCP connection: %v", err)
	}

	connFd, err := conn.File()
	if err != nil {
		log.Fatalf("Error getting file descriptor from TCP connection: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		log.Fatalf("Error creating pipe: %v", err)
	}
	n, err := syscall.Splice(int(connFd.Fd()), nil, int(w.Fd()), nil, 1048576, SPLICE_F_NONBLOCK)
	if err != nil {
		log.Fatalf("Error splicing: %v", err)
	}
	w.Close()
	io.Copy(os.Stdout, r)
	fmt.Printf("Splice reads %d bytes\n", n)
}
