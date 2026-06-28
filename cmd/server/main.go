package main

import "flag"

type Server struct {
	Quic     *QUICServer
	Username string
	Password string
}

func main() {
	quicAddr := flag.String("quic", ":4433", "QUIC listen address")
	username := flag.String("username", "karamel", "Authentication username")
	password := flag.String("password", "karamel", "Authentication password")
	flag.Parse()

	s := Server{
		Username: *username,
		Password: *password,
	}

	s.Quic = newQUICServer(&s)
	s.Quic.runQUICServer(*quicAddr)
}
