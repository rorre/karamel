package client

import (
	"context"
	"log"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/protocol"
)

func RunReverseProxy(c *Client) {
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

	switch req.Network {
	case protocol.NetTCP:
		log.Printf("proxying %s connection to %s", netStr, req.Address)
		handleTCP(stream, req.Address)
	case protocol.NetUDP:
		log.Printf("starting UDP tunnel")
		handleUDPTunnel(stream)
	}
}
