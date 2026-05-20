package hysteria2

import (
	"context"
	"net"
	"testing"

	"github.com/metacubex/quic-go"
	qtls "github.com/metacubex/sing-quic"
	"github.com/metacubex/tls"
)

// TestOfferNewNilQuicConn verifies that offerNew returns an error instead of
// crashing when the QUIC dialer returns a nil *quic.Conn together with a nil
// error.
//
// A QuicDialer must return a non-nil connection whenever it returns a nil
// error. When an implementation violates that contract, the nil conn used to
// be captured by the http3.Transport Dial closure and later dereferenced in
// http3.newClientConn (conn.QlogTrace()), crashing the whole process with a
// nil-pointer panic in a goroutine spawned by http3.Transport.getClient.
func TestOfferNewNilQuicConn(t *testing.T) {
	c := &Client{
		ctx: context.Background(),
		quicDialer: qtls.QuicDialerFunc(func(ctx context.Context, addr string, listener qtls.PacketDialer, tlsCfg *tls.Config, cfg *quic.Config, early bool) (net.PacketConn, *quic.Conn, error) {
			return nil, nil, nil // contract violation: nil conn, nil error
		}),
	}

	conn, err := c.offerNew(context.Background())
	if err == nil {
		t.Fatal("offerNew with nil quicConn: got nil error, want a non-nil error")
	}
	if conn != nil {
		t.Fatalf("offerNew with nil quicConn: got non-nil connection %v, want nil", conn)
	}
}
