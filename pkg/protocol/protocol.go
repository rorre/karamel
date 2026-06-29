package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	NetTCP byte = 0x01
	NetUDP byte = 0x02

	RespSuccess byte = 0x00
	RespFailure byte = 0x01

	RoleReverser byte = 0x00
	RoleClient   byte = 0x01
)

// Authenticate carries credentials and the role for a QUIC connection.
type Authenticate struct {
	Username string
	Password string
	Role     byte
}

// Request represents a proxy request header.
type Request struct {
	Network byte
	Address string
}

func writeString(w io.Writer, value string) error {
	buf := []byte(value)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(buf)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(buf)
	return err
}

func readString(r io.Reader) (string, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return "", err
	}
	buf := make([]byte, binary.BigEndian.Uint16(lenBuf))
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// WriteAuthenticate writes an authentication record to w.
func WriteAuthenticate(w io.Writer, auth *Authenticate) error {
	if auth == nil {
		return fmt.Errorf("nil authenticate")
	}
	if auth.Role != RoleReverser && auth.Role != RoleClient {
		return fmt.Errorf("unknown role: 0x%02x", auth.Role)
	}
	if _, err := w.Write([]byte{auth.Role}); err != nil {
		return err
	}
	if err := writeString(w, auth.Username); err != nil {
		return err
	}
	return writeString(w, auth.Password)
}

// ReadAuthenticate reads an authentication record from r.
func ReadAuthenticate(r io.Reader) (*Authenticate, error) {
	roleBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, roleBuf); err != nil {
		return nil, err
	}
	if roleBuf[0] != RoleReverser && roleBuf[0] != RoleClient {
		return nil, fmt.Errorf("unknown role: 0x%02x", roleBuf[0])
	}
	username, err := readString(r)
	if err != nil {
		return nil, err
	}
	password, err := readString(r)
	if err != nil {
		return nil, err
	}
	return &Authenticate{
		Username: username,
		Password: password,
		Role:     roleBuf[0],
	}, nil
}

// WriteRequest writes a proxy request to w.
func WriteRequest(w io.Writer, req *Request) error {
	if _, err := w.Write([]byte{req.Network}); err != nil {
		return err
	}
	addrBytes := []byte(req.Address)
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(addrBytes)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(addrBytes)
	return err
}

// ReadRequest reads a proxy request from r.
func ReadRequest(r io.Reader) (*Request, error) {
	netBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, netBuf); err != nil {
		return nil, err
	}
	if netBuf[0] != NetTCP && netBuf[0] != NetUDP {
		return nil, fmt.Errorf("unknown network type: 0x%02x", netBuf[0])
	}
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	addrLen := binary.BigEndian.Uint16(lenBuf)
	addrBuf := make([]byte, addrLen)
	if _, err := io.ReadFull(r, addrBuf); err != nil {
		return nil, err
	}
	return &Request{
		Network: netBuf[0],
		Address: string(addrBuf),
	}, nil
}

// WriteResponse writes a single response byte.
func WriteResponse(w io.Writer, resp byte) error {
	_, err := w.Write([]byte{resp})
	return err
}

// ReadResponse reads a single response byte.
func ReadResponse(r io.Reader) (byte, error) {
	buf := make([]byte, 1)
	_, err := io.ReadFull(r, buf)
	return buf[0], err
}

// WriteFramedPacket writes a length-prefixed UDP packet.
func WriteFramedPacket(w io.Writer, data []byte) error {
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(data)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// ReadFramedPacket reads a length-prefixed UDP packet.
func ReadFramedPacket(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf)
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	return data, err
}

// WriteUDPPacket writes a multiplexed UDP packet: SessionID (4 bytes), Address (string with 2 bytes length), Payload (2 bytes length + data).
func WriteUDPPacket(w io.Writer, sessionID uint32, addr string, payload []byte) error {
	idBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(idBuf, sessionID)
	if _, err := w.Write(idBuf); err != nil {
		return err
	}
	if err := writeString(w, addr); err != nil {
		return err
	}
	return WriteFramedPacket(w, payload)
}

// ReadUDPPacket reads a multiplexed UDP packet.
func ReadUDPPacket(r io.Reader) (uint32, string, []byte, error) {
	idBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, idBuf); err != nil {
		return 0, "", nil, err
	}
	sessionID := binary.BigEndian.Uint32(idBuf)
	addr, err := readString(r)
	if err != nil {
		return 0, "", nil, err
	}
	payload, err := ReadFramedPacket(r)
	if err != nil {
		return 0, "", nil, err
	}
	return sessionID, addr, payload, nil
}
