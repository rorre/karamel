package main

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/protocol"
)

func runReverseProxy(c *Client) {
	for {
		stream, err := c.conn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Connection closed: %v", err)
			return
		}
		go handleStream(stream)
	}
}

func handleStream(stream *quic.Stream) {
	defer stream.Close()

	req, err := protocol.ReadRequest(stream)
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	var netStr string
	switch req.Network {
	case protocol.NetTCP:
		netStr = "tcp"
	case protocol.NetUDP:
		netStr = "udp"
	default:
		protocol.WriteResponse(stream, protocol.RespFailure)
		return
	}

	log.Printf("Proxying %s connection to %s", netStr, req.Address)

	switch req.Network {
	case protocol.NetTCP:
		handleTCP(stream, req.Address)
	case protocol.NetUDP:
		handleUDP(stream, req.Address)
	}
}

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

func handleUDP(stream *quic.Stream, addr string) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		log.Printf("Failed to resolve UDP addr %s: %v", addr, err)
		protocol.WriteResponse(stream, protocol.RespFailure)
		return
	}

	log.Printf("udp reverser: connecting to %s", udpAddr.String())
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("Failed to dial UDP %s: %v", addr, err)
		protocol.WriteResponse(stream, protocol.RespFailure)
		return
	}
	defer udpConn.Close()

	protocol.WriteResponse(stream, protocol.RespSuccess)

	data, err := protocol.ReadFramedPacket(stream)
	if err != nil {
		log.Printf("Failed to read UDP packet: %v", err)
		return
	}

	_, err = udpConn.Write(data)
	if err != nil {
		log.Printf("Failed to send UDP packet: %v", err)
		return
	}

	respBuf := make([]byte, 65535)
	udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := udpConn.Read(respBuf)
	if err != nil {
		log.Printf("Failed to read UDP response: %v", err)
		return
	}

	protocol.WriteFramedPacket(stream, respBuf[:n])
}
