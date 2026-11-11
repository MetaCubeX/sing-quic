package hysteria2

import (
	"errors"
	"net"
	"syscall"
	"testing"
)

func TestSalamanderPreservesNativeSocketAccess(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wrapped := NewSalamanderConn(conn, []byte("lab-password"))
	native, ok := wrapped.(syscall.Conn)
	if !ok {
		t.Fatal("obfuscation hid native socket access required for QUIC DF")
	}
	raw, err := native.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	called := false
	if err := raw.Control(func(fd uintptr) { called = true }); err != nil || !called {
		t.Fatalf("native socket control failed: called=%v err=%v", called, err)
	}
}

type genericPacketConn struct{ net.PacketConn }

func TestSalamanderDoesNotInventNativeSocketAccess(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wrapped := NewSalamanderConn(genericPacketConn{conn}, []byte("lab-password"))
	if _, ok := wrapped.(syscall.Conn); ok {
		t.Fatal("generic transport incorrectly advertised native socket access")
	}
}

type unsupportedNativePacketConn struct{ net.PacketConn }

func (unsupportedNativePacketConn) SyscallConn() (syscall.RawConn, error) {
	return nil, errors.New("native socket access is unsupported")
}

func TestSalamanderDoesNotExposeUnsupportedNativeSocketAccess(t *testing.T) {
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wrapped := NewSalamanderConn(unsupportedNativePacketConn{conn}, []byte("lab-password"))
	if _, ok := wrapped.(syscall.Conn); ok {
		t.Fatal("transport with unsupported native socket access advertised syscall.Conn")
	}
}
