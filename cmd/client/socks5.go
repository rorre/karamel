package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/rorre/karamel/protocol"
)

type SOCKS5Server struct {
	client *Client
}

func newSOCKS5Server(c *Client) *SOCKS5Server {
	return &SOCKS5Server{client: c}
}

func (s *SOCKS5Server) runSOCKS5Server(addr string) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen SOCKS5 on %s: %v", addr, err)
	}
	log.Printf("SOCKS5 server listening on %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("SOCKS5 accept error: %v", err)
			continue
		}
		go s.handleSOCKS5(conn)
	}
}

func (s *SOCKS5Server) authenticate(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("failed to read greeting: %v", err)
	}
	if buf[0] != 0x05 {
		return fmt.Errorf("unsupported version: %d", buf[0])
	}
	nMethods := int(buf[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %v", err)
	}
	// Reply: no auth required
	conn.Write([]byte{0x05, 0x00})
	return nil
}

func (s *SOCKS5Server) parseRequest(conn net.Conn) (byte, string, error) {
	reqBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqBuf); err != nil {
		return 0, "", fmt.Errorf("failed to read request: %v", err)
	}
	cmd := reqBuf[1]
	atyp := reqBuf[3]

	var dstAddr string
	switch atyp {
	case 0x01: // IPv4
		ipBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return 0, "", errors.New("failed to read IPv4")
		}
		dstAddr = net.IP(ipBuf).String()
	case 0x03: // Domain
		domLenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, domLenBuf); err != nil {
			return 0, "", errors.New("failed to read domain length")
		}
		domBuf := make([]byte, domLenBuf[0])
		if _, err := io.ReadFull(conn, domBuf); err != nil {
			return 0, "", errors.New("failed to read domain")
		}
		dstAddr = string(domBuf)
	case 0x04: // IPv6
		ipBuf := make([]byte, 16)
		if _, err := io.ReadFull(conn, ipBuf); err != nil {
			return 0, "", errors.New("failed to read IPv6")
		}
		dstAddr = net.IP(ipBuf).String()
		// HACK: Because there will be port later on, put the brackets so it wont get confused lol
		dstAddr = fmt.Sprintf("[%s]", dstAddr)
	default:
		sendSOCKS5Reply(conn, 0x08, nil)
		return 0, "", fmt.Errorf("unsupported atyp: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return 0, "", errors.New("failed to read port")
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := fmt.Sprintf("%s:%d", dstAddr, port)

	return cmd, target, nil
}

func (s *SOCKS5Server) handleSOCKS5(conn net.Conn) {
	defer conn.Close()

	err := s.authenticate(conn)
	if err != nil {
		log.Printf("socks5: %v", err)
		return
	}

	cmd, target, err := s.parseRequest(conn)
	if err != nil {
		return
	}

	switch cmd {
	case 0x01: // TCP
		s.handleTCPConnect(conn, target)
	case 0x03: // UDP ASSOCIATE
		s.handleUDPAssociate(conn)
	default:
		log.Printf("socks5: unsupported command: %d", cmd)
		sendSOCKS5Reply(conn, 0x07, nil)
	}
}

func sendSOCKS5Reply(conn net.Conn, rep byte, bindAddr net.Addr) {
	reply := []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			ip := tcpAddr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
			}
			binary.BigEndian.PutUint16(reply[8:10], uint16(tcpAddr.Port))
		} else if udpAddr, ok := bindAddr.(*net.UDPAddr); ok {
			ip := udpAddr.IP.To4()
			if ip != nil {
				copy(reply[4:8], ip)
			}
			binary.BigEndian.PutUint16(reply[8:10], uint16(udpAddr.Port))
		}
	}
	conn.Write(reply)
}

func (s *SOCKS5Server) handleTCPConnect(conn net.Conn, target string) {
	qc := s.client.conn
	if qc == nil {
		log.Printf("socks5: no QUIC client connected")
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}

	stream, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("socks5: failed to open QUIC stream: %v", err)
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}
	defer stream.Close()

	req := &protocol.Request{
		Network: protocol.NetTCP,
		Address: target,
	}
	if err := protocol.WriteRequest(stream, req); err != nil {
		log.Printf("socks5: failed to write request to QUIC: %v", err)
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}

	resp, err := protocol.ReadResponse(stream)
	if err != nil {
		log.Printf("socks5: failed to read response from QUIC: %v", err)
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}
	if resp != protocol.RespSuccess {
		log.Printf("socks5: QUIC client failed to connect to %s", target)
		sendSOCKS5Reply(conn, 0x05, nil)
		return
	}

	sendSOCKS5Reply(conn, 0x00, nil)

	// Bidirectional copy
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, conn)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, stream)
	}()
	wg.Wait()
}

func parseUDPRequest(udpListener *net.UDPConn) (*net.UDPAddr, string, []byte, []byte, error) {
	buf := make([]byte, 65535)
	udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, clientAddr, err := udpListener.ReadFromUDP(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, "", nil, nil, fmt.Errorf("failed to read request")
		}
		return nil, "", nil, nil, fmt.Errorf("failed to read request")

	}

	log.Printf("received udp packet from associated port")
	// +----+------+------+----------+----------+----------+
	// |RSV (2 bytes) | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	if n < 4 {
		return nil, "", nil, nil, fmt.Errorf("invalid request")
	}
	frag := buf[2]
	if frag != 0 {
		return nil, "", nil, nil, fmt.Errorf("no fragmented stuff pls")
	}

	atyp := buf[3]
	var dstAddrStr string
	var headerLen int
	switch atyp {
	case 0x01: // IPv4
		if n < 10 {
			return nil, "", nil, nil, fmt.Errorf("invalid request")
		}
		ip := net.IP(buf[4:8]).String()
		port := binary.BigEndian.Uint16(buf[8:10])
		dstAddrStr = fmt.Sprintf("%s:%d", ip, port)
		headerLen = 10
	case 0x03: // Domain
		domLen := int(buf[4])
		if n < 5+domLen+2 {
			return nil, "", nil, nil, fmt.Errorf("invalid request")
		}
		dom := string(buf[5 : 5+domLen])
		port := binary.BigEndian.Uint16(buf[5+domLen : 7+domLen])
		dstAddrStr = fmt.Sprintf("%s:%d", dom, port)
		headerLen = 7 + domLen
	case 0x04: // IPv6
		if n < 22 {
			return nil, "", nil, nil, fmt.Errorf("invalid request")
		}
		ip := net.IP(buf[4:20]).String()
		port := binary.BigEndian.Uint16(buf[20:22])
		// bracketing it so that the resolver wont freak out
		dstAddrStr = fmt.Sprintf("[%s]:%d", ip, port)
		headerLen = 22
	default:
		return nil, "", nil, nil, fmt.Errorf("invalid request")
	}

	payload := make([]byte, n-headerLen)
	copy(payload, buf[headerLen:n])
	socksHdr := make([]byte, headerLen)
	copy(socksHdr, buf[:headerLen])

	return clientAddr, dstAddrStr, payload, socksHdr, nil
}

func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("socks5: failed to listen UDP: %v", err)
		sendSOCKS5Reply(conn, 0x01, nil)
		return
	}
	defer udpListener.Close()

	boundAddr := udpListener.LocalAddr().(*net.UDPAddr)
	serverIP := conn.LocalAddr().(*net.TCPAddr).IP
	replyAddr := &net.UDPAddr{IP: serverIP, Port: boundAddr.Port}
	log.Printf("listening to udp requests on %s", replyAddr.String())
	sendSOCKS5Reply(conn, 0x00, replyAddr)

	// when TCP closes, stop UDP relay
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		conn.Read(buf)
		close(done)
		log.Printf("closing UDP channel %s", replyAddr)
	}()

	go func() {
		for {
			select {
			case <-done:
				return
			default:
			}

			clientAddr, dstAddrStr, payload, socksHdr, err := parseUDPRequest(udpListener)
			if err != nil {
				return
			}

			go s.relayUDPPacket(conn, udpListener, clientAddr, dstAddrStr, payload, socksHdr)
		}
	}()

	<-done
}

func (s *SOCKS5Server) relayUDPPacket(conn net.Conn, udpListener *net.UDPConn, clientAddr *net.UDPAddr, dstAddr string, payload []byte, socksHeader []byte) {
	qc := s.client.conn
	if qc == nil {
		return
	}

	stream, err := qc.OpenStreamSync(context.Background())
	if err != nil {
		log.Printf("udp relay: failed to open QUIC stream: %v", err)
		return
	}
	defer stream.Close()

	req := &protocol.Request{
		Network: protocol.NetUDP,
		Address: dstAddr,
	}
	if err := protocol.WriteRequest(stream, req); err != nil {
		return
	}

	resp, err := protocol.ReadResponse(stream)
	if err != nil || resp != protocol.RespSuccess {
		return
	}

	if err := protocol.WriteFramedPacket(stream, payload); err != nil {
		return
	}

	respData, err := protocol.ReadFramedPacket(stream)
	if err != nil {
		return
	}

	response := make([]byte, len(socksHeader)+len(respData))
	copy(response, socksHeader)
	copy(response[len(socksHeader):], respData)

	udpListener.WriteToUDP(response, clientAddr)

	// idk just close it early i guess, we dont need to deal with the rest anyway
	// not sure if its gonna fuck up clients or not
	conn.Close()
}
