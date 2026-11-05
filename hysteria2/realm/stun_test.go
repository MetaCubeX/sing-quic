package realm

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/sing-quic/hysteria2/internal/stun"
)

// startSTUNServer answers every binding request with the sender's address.
func startSTUNServer(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			request, err := stun.Decode(buffer[:n])
			if err != nil {
				continue
			}
			_, _ = conn.WriteToUDPAddrPort(bindingSuccess(request.TransactionID, from), from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func bindingSuccess(transactionID stun.TransactionID, mapped netip.AddrPort) []byte {
	const magicCookie = 0x2112A442
	ip := mapped.Addr().Unmap().As4()
	message := make([]byte, stun.HeaderSize+12)
	binary.BigEndian.PutUint16(message[0:2], 0x0101)
	binary.BigEndian.PutUint16(message[2:4], 12)
	binary.BigEndian.PutUint32(message[4:8], magicCookie)
	copy(message[8:stun.HeaderSize], transactionID[:])
	attribute := message[stun.HeaderSize:]
	binary.BigEndian.PutUint16(attribute[0:2], 0x0020)
	binary.BigEndian.PutUint16(attribute[2:4], 8)
	attribute[5] = 0x01
	binary.BigEndian.PutUint16(attribute[6:8], mapped.Port()^uint16(magicCookie>>16))
	var cookie [4]byte
	binary.BigEndian.PutUint32(cookie[:], magicCookie)
	for i := range ip {
		attribute[8+i] = ip[i] ^ cookie[i]
	}
	return message
}

// closedUDPPort returns a loopback address nothing listens on.
func closedUDPPort(t *testing.T) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	_ = conn.Close()
	return address
}

func listenClient(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestDiscoverSkipsUnresponsiveServer(t *testing.T) {
	working := startSTUNServer(t)
	dead := closedUDPPort(t)
	conn := listenClient(t)
	local := conn.LocalAddr().(*net.UDPAddr).AddrPort()

	// mihomo dials with a 5s timeout; discovery must leave time for the
	// realm exchange and the punch that follow it.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, servers := range [][]netip.AddrPort{{dead, working}, {working, dead}} {
		start := time.Now()
		addresses, err := Discover(ctx, conn, servers)
		elapsed := time.Since(start)
		if err != nil {
			t.Fatalf("servers %v: %v", servers, err)
		}
		if len(addresses) != 1 || addresses[0] != local {
			t.Fatalf("servers %v: got %v, want [%v]", servers, addresses, local)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("servers %v: discovery took %v waiting for the unresponsive server", servers, elapsed)
		}
	}
}

func TestDiscoverAllServersFail(t *testing.T) {
	first := closedUDPPort(t)
	second := closedUDPPort(t)
	conn := listenClient(t)
	_, err := Discover(context.Background(), conn, []netip.AddrPort{first, second})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, server := range []netip.AddrPort{first, second} {
		if !strings.Contains(err.Error(), server.String()) {
			t.Fatalf("error %q does not name %v", err, server)
		}
	}
}

func TestResolveSTUNServersSkipsUnresolvable(t *testing.T) {
	resolver := func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
		if host == "good.example" {
			return []netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil
		}
		return nil, errors.New("no such host")
	}
	resolved, err := ResolveSTUNServers(context.Background(), []string{"bad.example:3478", "good.example:3478"}, resolver, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 || resolved[0] != netip.MustParseAddrPort("192.0.2.1:3478") {
		t.Fatalf("got %v", resolved)
	}

	_, err = ResolveSTUNServers(context.Background(), []string{"bad.example:3478", "worse.example:3478"}, resolver, true, true)
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, server := range []string{"bad.example:3478", "worse.example:3478"} {
		if !strings.Contains(err.Error(), server) {
			t.Fatalf("error %q does not name %s", err, server)
		}
	}
}
