package client

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/rorre/karamel/pkg/protocol"
)

type SessionKey struct {
	sessionID uint32
	dstAddr   string
}

type UDPSession struct {
	conn       *net.UDPConn
	lastActive time.Time
}

type UDPMux struct {
	stream   *quic.Stream
	mu       sync.Mutex
	writeMu  sync.Mutex
	sessions map[SessionKey]*UDPSession
}

func newUDPMux(stream *quic.Stream) *UDPMux {
	return &UDPMux{
		stream:   stream,
		sessions: make(map[SessionKey]*UDPSession),
	}
}

const IDLE_TIMEOUT = 60 * time.Second
const CLEANUP_INTERVAL = 10 * time.Second

func (m *UDPMux) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sess := range m.sessions {
		sess.conn.Close()
	}
	m.sessions = make(map[SessionKey]*UDPSession)
}

func (m *UDPMux) runCleanupLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(CLEANUP_INTERVAL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.sweepIdleSessions(IDLE_TIMEOUT)
		case <-stop:
			return
		}
	}
}

func (m *UDPMux) sweepIdleSessions(idleTimeout time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, sess := range m.sessions {
		if now.Sub(sess.lastActive) > idleTimeout {
			sess.conn.Close()
			delete(m.sessions, k)
			log.Printf("cleaned up idle UDP session %d -> %s", k.sessionID, k.dstAddr)
		}
	}
}

func (m *UDPMux) getOrCreateSession(key SessionKey) (*UDPSession, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[key]
	if ok {
		sess.lastActive = time.Now()
		return sess, nil
	}

	targetAddr, err := net.ResolveUDPAddr("udp", key.dstAddr)
	if err != nil {
		return nil, err
	}

	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		return nil, err
	}

	sess = &UDPSession{
		conn:       udpConn,
		lastActive: time.Now(),
	}
	m.sessions[key] = sess

	go m.readFromSession(key, udpConn)

	return sess, nil
}

func (m *UDPMux) readFromSession(key SessionKey, conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		m.mu.Lock()
		if s, ok := m.sessions[key]; ok {
			s.lastActive = time.Now()
		}
		m.mu.Unlock()

		m.writeMu.Lock()
		err = protocol.WriteUDPPacket(m.stream, key.sessionID, key.dstAddr, buf[:n])
		m.writeMu.Unlock()
		if err != nil {
			log.Printf("failed to write UDP response over stream: %v", err)
			return
		}
	}
}

func (m *UDPMux) runStreamReader() {
	for {
		sessionID, dstAddrStr, payload, err := protocol.ReadUDPPacket(m.stream)
		if err != nil {
			log.Printf("failed to read UDP tunnel: %v", err)
			return
		}

		key := SessionKey{sessionID: sessionID, dstAddr: dstAddrStr}
		sess, err := m.getOrCreateSession(key)
		if err != nil {
			log.Printf("failed to get/create UDP session: %v", err)
			continue
		}

		go func() {
			_, err = sess.conn.Write(payload)
			if err != nil {
				log.Printf("failed to write UDP packet to target %s: %v", dstAddrStr, err)
			}
		}()
	}
}

func handleUDPTunnel(stream *quic.Stream) {
	defer stream.Close()

	if err := protocol.WriteResponse(stream, protocol.RespSuccess); err != nil {
		log.Printf("Failed to write UDP tunnel RespSuccess: %v", err)
		return
	}

	mux := newUDPMux(stream)
	defer mux.closeAll()

	stopCleanup := make(chan struct{})
	defer close(stopCleanup)

	go mux.runCleanupLoop(stopCleanup)

	mux.runStreamReader()
}
