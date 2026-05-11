package realm

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/metacubex/sing-quic/hysteria2/internal/stun"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
)

const stunTimeout = 4 * time.Second

func resolveSTUNServers(ctx context.Context, servers []string, resolver Resolver, ipv4, ipv6 bool) ([]netip.AddrPort, error) {
	if resolver == nil {
		return nil, E.New("realm: resolver is required")
	}
	var resolved []netip.AddrPort
	for _, server := range servers {
		host, port, err := net.SplitHostPort(server)
		if err != nil {
			host = server
			port = "3478"
		}
		addresses, err := resolver(ctx, host, ipv4, ipv6)
		if err != nil {
			return nil, E.Cause(err, "resolve STUN server: ", server)
		}
		portNumber, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, E.Cause(err, "resolve STUN port: ", port)
		}
		for _, address := range addresses {
			resolved = append(resolved, netip.AddrPortFrom(address, uint16(portNumber)))
		}
	}
	if len(resolved) == 0 {
		return nil, E.New("no STUN servers resolved")
	}
	return resolved, nil
}

func Discover(ctx context.Context, conn net.PacketConn, servers []string, resolver Resolver) ([]netip.AddrPort, error) {
	var ipv4, ipv6 bool
	localAddrPort := M.SocksaddrFromNet(conn.LocalAddr()).Unwrap().AddrPort()
	switch {
	case !localAddrPort.IsValid() || localAddrPort.Addr().IsUnspecified():
		ipv4 = true
		ipv6 = true
	case localAddrPort.Addr().Is4():
		ipv4 = true
	default:
		ipv6 = true
	}
	resolved, err := resolveSTUNServers(ctx, servers, resolver, ipv4, ipv6)
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

func DiscoverDemuxed(ctx context.Context, conn *PunchPacketConn, servers []string, resolver Resolver) ([]netip.AddrPort, error) {
	var ipv4, ipv6 bool
	localAddrPort := M.SocksaddrFromNet(conn.LocalAddr()).Unwrap().AddrPort()
	switch {
	case !localAddrPort.IsValid() || localAddrPort.Addr().IsUnspecified():
		ipv4 = true
		ipv6 = true
	case localAddrPort.Addr().Is4():
		ipv4 = true
	default:
		ipv6 = true
	}
	resolved, err := resolveSTUNServers(ctx, servers, resolver, ipv4, ipv6)
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

func sendSTUNRequests(conn net.PacketConn, servers []netip.AddrPort) (map[stun.TransactionID]struct{}, error) {
	pending := make(map[stun.TransactionID]struct{}, len(servers))
	var sendErr error
	for _, server := range servers {
		request, err := stun.NewBindingRequest()
		if err != nil {
			return nil, E.Cause(err, "build STUN request")
		}
		_, err = conn.WriteTo(request.Raw, net.UDPAddrFromAddrPort(server))
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
