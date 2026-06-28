package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/protocol"
)

type QUICServer struct {
	reverserConn *quic.Conn
	server       *Server
	mu           sync.Mutex
	cond         *sync.Cond
}

func newQUICServer(s *Server) *QUICServer {
	q := &QUICServer{server: s}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
		NextProtos: []string{"karamel"},
	}, nil
}

func (q *QUICServer) runQUICServer(addr string) {
	tlsConf, err := generateTLSConfig()
	if err != nil {
		log.Fatalf("Failed to generate TLS config: %v", err)
	}

	listener, err := quic.ListenAddr(addr, tlsConf, &quic.Config{
		KeepAlivePeriod:    10 * time.Second,
		MaxIncomingStreams: 16384,
	})
	if err != nil {
		log.Fatalf("Failed to listen QUIC on %s: %v", addr, err)
	}
	log.Printf("QUIC server listening on %s", addr)

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Fatalf("Failed to accept QUIC connection: %v", err)
		}
		log.Printf("QUIC client connected from %s", conn.RemoteAddr())

		go q.handleAuthenticatedConn(conn)
	}
}

func (q *QUICServer) handleAuthenticatedConn(conn *quic.Conn) {
	defer conn.CloseWithError(0, "server closing connection")

	auth, err := q.authenticateConnection(conn)
	if err != nil {
		log.Printf("Authentication failed for %s: %v", conn.RemoteAddr(), err)
		return
	}

	switch auth.Role {
	case protocol.RoleReverser:
		q.setReverserConn(conn)
		log.Printf("Reverser authenticated from %s", conn.RemoteAddr())
		<-conn.Context().Done()
		q.setReverserConn(nil)
	case protocol.RoleClient:
		reverser := q.waitForReverserConn()
		if reverser == nil {
			log.Printf("No reverser available for %s", conn.RemoteAddr())
			return
		}
		log.Printf("Bridging client %s to reverser", conn.RemoteAddr())
		q.bridgeClientConn(conn, reverser)
	default:
		log.Printf("Unsupported role %d from %s", auth.Role, conn.RemoteAddr())
	}
}

func (q *QUICServer) authenticateConnection(conn *quic.Conn) (*protocol.Authenticate, error) {
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	auth, err := protocol.ReadAuthenticate(stream)
	if err != nil {
		return nil, err
	}
	if auth.Username != q.server.Username || auth.Password != q.server.Password {
		protocol.WriteResponse(stream, protocol.RespFailure)
		return nil, fmt.Errorf("invalid credentials")
	}
	if err := protocol.WriteResponse(stream, protocol.RespSuccess); err != nil {
		return nil, err
	}
	return auth, nil
}

func (q *QUICServer) setReverserConn(conn *quic.Conn) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.reverserConn = conn
	q.cond.Broadcast()
}

func (q *QUICServer) waitForReverserConn() *quic.Conn {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.reverserConn == nil {
		q.cond.Wait()
	}
	return q.reverserConn
}

func (q *QUICServer) bridgeClientConn(clientConn, reverserConn *quic.Conn) {
	for {
		clientStream, err := clientConn.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Client connection closed: %v", err)
			return
		}

		reverserStream, err := reverserConn.OpenStreamSync(context.Background())
		if err != nil {
			log.Printf("Failed to open reverser stream: %v", err)
			clientStream.Close()
			continue
		}

		go q.bridgeStreams(clientStream, reverserStream)
	}
}

func (q *QUICServer) bridgeStreams(left, right *quic.Stream) {
	defer left.Close()
	defer right.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
	}()
	wg.Wait()
}
