package hysteria2

import (
	"net"

	"github.com/metacubex/sing/common/buf"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/exp/slices"
)

const salamanderSaltLen = 8

const ObfsTypeSalamander = "salamander"

type SalamanderPacketConn struct {
	net.PacketConn
	password []byte
}

func NewSalamanderConn(conn net.PacketConn, password []byte) net.PacketConn {
	return &SalamanderPacketConn{
		PacketConn: conn,
		password:   slices.Clip(password),
	}
}

func (s *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = s.PacketConn.ReadFrom(p)
	if err != nil {
		return
	}
	if n <= salamanderSaltLen {
		return
	}
	key := blake2b.Sum256(append(s.password, p[:salamanderSaltLen]...))
	xorRepeating32(p[:n-salamanderSaltLen], p[salamanderSaltLen:n], &key)
	return n - salamanderSaltLen, addr, nil
}

func (s *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	buffer := buf.NewSize(len(p) + salamanderSaltLen)
	defer buffer.Release()
	buffer.WriteRandom(salamanderSaltLen)
	key := blake2b.Sum256(append(s.password, buffer.Bytes()...))
	body := buffer.Extend(len(p))
	xorRepeating32(body, p, &key)
	_, err = s.PacketConn.WriteTo(buffer.Bytes(), addr)
	if err != nil {
		return
	}
	return len(p), nil
}
