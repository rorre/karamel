package main

import (
	"flag"

	"github.com/rorre/karamel/server"
)

func main() {
	quicAddr := flag.String("quic", ":4433", "QUIC listen address")
	username := flag.String("username", "karamel", "Authentication username")
	password := flag.String("password", "karamel", "Authentication password")
	flag.Parse()

	server.NewQUICServer(*username, *password).RunQUICServer(*quicAddr)
}
