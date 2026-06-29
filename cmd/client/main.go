package main

import (
	"context"
	"crypto/tls"
	"flag"
	"log"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/client"
	"github.com/rorre/karamel/protocol"
)

func main() {
	serverAddr := flag.String("server", "localhost:4433", "QUIC server address")
	socksAddr := flag.String("socks", ":1080", "SOCKS5 listen address")
	reverseMode := flag.Bool("reverse", false, "Reverse this machine's connection to server")
	username := flag.String("username", "karamel", "Authentication username")
	password := flag.String("password", "karamel", "Authentication password")
	flag.Parse()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"karamel"},
	}

	log.Printf("Connecting to QUIC server at %s", *serverAddr)
	conn, err := quic.DialAddr(context.Background(), *serverAddr, tlsConf, &quic.Config{
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to connect to QUIC server: %v", err)
	}
	log.Printf("Connected to QUIC server")
	defer conn.CloseWithError(0, "client shutting down")

	c := client.NewClient(conn, *username, *password)

	role := protocol.RoleClient
	if *reverseMode {
		role = protocol.RoleReverser
	}
	if err := c.Authenticate(role); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	if *reverseMode {
		client.RunReverseProxy(c)
	} else {
		client.NewSOCKS5Server(c).RunSOCKS5Server(*socksAddr)
	}
}
