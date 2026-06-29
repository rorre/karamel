package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/pkg/protocol"
)

type Client struct {
	conn     *quic.Conn
	username string
	password string

	// For forever running UDP stream
	udpStream     *quic.Stream
	udpStreamMu   sync.Mutex
	udpWriteMu    sync.Mutex
	udpSessionMap map[uint32]*udpSession
	udpSessionMu  sync.Mutex
	nextSessionID uint32
}

type udpSession struct {
	udpListener *net.UDPConn
	clientAddr  *net.UDPAddr
}

func NewClient(conn *quic.Conn, username, password string) *Client {
	return &Client{
		conn:          conn,
		username:      username,
		password:      password,
		udpSessionMap: make(map[uint32]*udpSession),
	}
}

func (c *Client) getUDPStream() (*quic.Stream, error) {
	c.udpStreamMu.Lock()
	defer c.udpStreamMu.Unlock()

	if c.udpStream != nil {
		return c.udpStream, nil
	}

	stream, err := c.conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}

	req := &protocol.Request{
		Network: protocol.NetUDP,
		Address: "",
	}
	if err := protocol.WriteRequest(stream, req); err != nil {
		stream.Close()
		return nil, err
	}

	resp, err := protocol.ReadResponse(stream)
	if err != nil || resp != protocol.RespSuccess {
		stream.Close()
		return nil, fmt.Errorf("failed to init UDP stream on server: %v", err)
	}

	c.udpStream = stream

	// Start read loop for responses
	go c.readUDPResponses(stream)

	return stream, nil
}

func (c *Client) readUDPResponses(stream *quic.Stream) {
	defer func() {
		stream.Close()
		c.udpStreamMu.Lock()
		if c.udpStream == stream {
			c.udpStream = nil
		}
		c.udpStreamMu.Unlock()
	}()

	for {
		sessionID, fromAddr, payload, err := protocol.ReadUDPPacket(stream)
		if err != nil {
			log.Printf("UDP stream read error: %v", err)
			return
		}

		c.udpSessionMu.Lock()
		session, ok := c.udpSessionMap[sessionID]
		c.udpSessionMu.Unlock()

		if ok {
			header, err := buildSOCKS5UDPHeader(fromAddr)
			if err != nil {
				log.Printf("Failed to build SOCKS5 UDP header: %v", err)
				continue
			}
			response := make([]byte, len(header)+len(payload))
			copy(response, header)
			copy(response[len(header):], payload)

			if session.clientAddr != nil {
				_, err = session.udpListener.WriteToUDP(response, session.clientAddr)
				if err != nil {
					log.Printf("Failed to write UDP response to client: %v", err)
				}
			}
		}
	}
}

func (c *Client) registerSession(udpListener *net.UDPConn) (uint32, func()) {
	c.udpSessionMu.Lock()
	c.nextSessionID++
	sessionID := c.nextSessionID
	c.udpSessionMap[sessionID] = &udpSession{
		udpListener: udpListener,
	}
	c.udpSessionMu.Unlock()

	cleanup := func() {
		c.udpSessionMu.Lock()
		delete(c.udpSessionMap, sessionID)
		c.udpSessionMu.Unlock()
	}
	return sessionID, cleanup
}

func (c *Client) updateSessionClientAddr(sessionID uint32, clientAddr *net.UDPAddr) {
	c.udpSessionMu.Lock()
	if sess, ok := c.udpSessionMap[sessionID]; ok {
		sess.clientAddr = clientAddr
	}
	c.udpSessionMu.Unlock()
}

func (c *Client) relayUDPPacket(sessionID uint32, dstAddrStr string, payload []byte) {
	stream, err := c.getUDPStream()
	if err != nil {
		log.Printf("udp relay: failed to get UDP stream: %v", err)
		return
	}

	c.udpWriteMu.Lock()
	err = protocol.WriteUDPPacket(stream, sessionID, dstAddrStr, payload)
	c.udpWriteMu.Unlock()
	if err != nil {
		log.Printf("udp relay: failed to write UDP packet: %v", err)
		c.udpStreamMu.Lock()
		if c.udpStream == stream {
			c.udpStream = nil
		}
		c.udpStreamMu.Unlock()
	}
}

func (c *Client) Authenticate(role byte) error {
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
