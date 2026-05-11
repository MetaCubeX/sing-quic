package realm

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/metacubex/sing-quic/hysteria2/internal/stun"
	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

const stunTimeout = 4 * time.Second

type addrFamily int

const (
	addrFamilyBoth addrFamily = iota
	addrFamilyIPv4
	addrFamilyIPv6
)

func localAddrFamily(addr net.Addr) addrFamily {
	udpAddr, isUDP := addr.(*net.UDPAddr)
	if !isUDP || udpAddr.IP == nil || udpAddr.IP.IsUnspecified() {
		return addrFamilyBoth
	}
	if udpAddr.IP.To4() != nil {
		return addrFamilyIPv4
	}
	return addrFamilyIPv6
}

func resolveSTUNServers(ctx context.Context, servers []string, family addrFamily) ([]*net.UDPAddr, error) {
	var resolved []*net.UDPAddr
	resolver := net.DefaultResolver
	for _, server := range servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			host = server
			port = "3478"
		}
		addresses, err := resolver.LookupNetIP(ctx, networkForFamily(family), host)
		if err != nil {
			return nil, E.Cause(err, "resolve STUN server: ", server)
		}
		portNumber, err := net.LookupPort(N.NetworkUDP, port)
		if err != nil {
			return nil, E.Cause(err, "resolve STUN port: ", port)
		}
		for _, address := range addresses {
			resolved = append(resolved, net.UDPAddrFromAddrPort(netip.AddrPortFrom(address, uint16(portNumber))))
		}
	}
	if len(resolved) == 0 {
		return nil, E.New("no STUN servers resolved")
	}
	return resolved, nil
}

func networkForFamily(family addrFamily) string {
	switch family {
	case addrFamilyIPv4:
		return "ip4"
	case addrFamilyIPv6:
		return "ip6"
	default:
		return N.NetworkIP
	}
}

func Discover(ctx context.Context, conn net.PacketConn, servers []string) ([]netip.AddrPort, error) {
	resolved, err := resolveSTUNServers(ctx, servers, localAddrFamily(conn.LocalAddr()))
	if err != nil {
		return nil, err
	}
	pending, err := sendSTUNRequests(conn, resolved)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(stunTimeout)
	buffer := make([]byte, 1500)
	seen := make(map[netip.AddrPort]bool)
	var result []netip.AddrPort
	for time.Now().Before(deadline) && len(pending) > 0 {
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return nil, E.Cause(err, "set read deadline")
		}
		n, _, readErr := conn.ReadFrom(buffer)
		if readErr != nil {
			if E.IsTimeout(readErr) {
				break
			}
			return nil, E.Cause(readErr, "read STUN response")
		}
		message, parseErr := stun.Decode(buffer[:n])
		if parseErr != nil {
			continue
		}
		if _, exists := pending[message.TransactionID]; !exists {
			continue
		}
		delete(pending, message.TransactionID)
		address, parseErr := message.XORMappedAddress()
		if parseErr != nil {
			continue
		}
		if !seen[address] {
			seen[address] = true
			result = append(result, address)
		}
	}
	err = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, E.Cause(err, "clear read deadline")
	}
	if len(result) == 0 {
		return nil, E.New("no STUN responses received")
	}
	return result, nil
}

func DiscoverDemuxed(ctx context.Context, conn *PunchPacketConn, servers []string) ([]netip.AddrPort, error) {
	resolved, err := resolveSTUNServers(ctx, servers, localAddrFamily(conn.LocalAddr()))
	if err != nil {
		return nil, err
	}
	pending, err := sendSTUNRequests(conn, resolved)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(stunTimeout)
	defer timer.Stop()
	stunEvents := conn.STUNEvents()
	seen := make(map[netip.AddrPort]bool)
	var result []netip.AddrPort
	for {
		if len(pending) == 0 {
			if len(result) == 0 {
				return nil, E.New("no STUN responses received")
			}
			return result, nil
		}
		select {
		case <-ctx.Done():
			if len(result) > 0 {
				return result, nil
			}
			return nil, ctx.Err()
		case <-timer.C:
			if len(result) == 0 {
				return nil, E.New("no STUN responses received")
			}
			return result, nil
		case event := <-stunEvents:
			if _, exists := pending[event.Message.TransactionID]; !exists {
				continue
			}
			delete(pending, event.Message.TransactionID)
			address, parseErr := event.Message.XORMappedAddress()
			if parseErr != nil {
				continue
			}
			if !seen[address] {
				seen[address] = true
				result = append(result, address)
			}
		}
	}
}

func sendSTUNRequests(conn net.PacketConn, servers []*net.UDPAddr) (map[stun.TransactionID]struct{}, error) {
	pending := make(map[stun.TransactionID]struct{}, len(servers))
	var sendErr error
	for _, server := range servers {
		request, err := stun.NewBindingRequest()
		if err != nil {
			return nil, E.Cause(err, "build STUN request")
		}
		_, err = conn.WriteTo(request.Raw, server)
		if err != nil {
			sendErr = E.Errors(sendErr, E.Cause(err, "send STUN request to ", server))
			continue
		}
		pending[request.TransactionID] = struct{}{}
	}
	if len(pending) == 0 {
		if sendErr != nil {
			return nil, sendErr
		}
		return nil, E.New("no STUN requests sent")
	}
	return pending, nil
}
