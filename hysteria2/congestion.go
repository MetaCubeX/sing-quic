package hysteria2

import "github.com/metacubex/quic-go"

var SetCongestionController = func(quicConn *quic.Conn, cc string, cwnd int) {
	// do nothing
	// clash.meta will replace this function after init
}
