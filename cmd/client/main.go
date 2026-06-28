package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/protocol"
)

type Client struct {
	conn        *quic.Conn
	socksServer *SOCKS5Server
	username    string
	password    string
}

func (c *Client) authenticate(role byte) error {
	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return err
	}
	defer stream.Close()

	auth := &protocol.Authenticate{
		Username: c.username,
		Password: c.password,
		Role:     role,
	}
	if err := protocol.WriteAuthenticate(stream, auth); err != nil {
		return err
	}
	resp, err := protocol.ReadResponse(stream)
	if err != nil {
		return err
	}
	if resp != protocol.RespSuccess {
		return fmt.Errorf("authentication rejected")
	}
	return nil
}

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

	c := &Client{
		conn:     conn,
		username: *username,
		password: *password,
	}
	c.socksServer = newSOCKS5Server(c)

	role := protocol.RoleClient
	if *reverseMode {
		role = protocol.RoleReverser
	}
	if err := c.authenticate(role); err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	if *reverseMode {
		runReverseProxy(c)
	} else {
		c.socksServer.runSOCKS5Server(*socksAddr)
	}
}
