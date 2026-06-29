package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/protocol"
)

func handleTCP(stream *quic.Stream, addr string) {
	targetConn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", addr, err)
		protocol.WriteResponse(stream, protocol.RespFailure)
		return
	}
	defer targetConn.Close()

	protocol.WriteResponse(stream, protocol.RespSuccess)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, stream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, targetConn)
	}()
	wg.Wait()
}
