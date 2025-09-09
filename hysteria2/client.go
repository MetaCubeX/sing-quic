package hysteria2

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/metacubex/randv2"
	tls "github.com/metacubex/utls"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	qtls "github.com/metacubex/sing-quic"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/sing-quic/hysteria2/internal/protocol"
	"github.com/metacubex/sing/common/baderror"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ClientOptions struct {
	Context            context.Context
	Dialer             N.Dialer
	Logger             logger.Logger
	BrutalDebug        bool
	ServerAddress      func(ctx context.Context) (*net.UDPAddr, error)
	ServerPorts        []uint16
	HopInterval        time.Duration
	SendBPS            uint64
	ReceiveBPS         uint64
	SalamanderPassword string
	Password           string
	TLSConfig          *tls.Config
	QUICConfig         *quic.Config
	UDPDisabled        bool
	CWND               int
	UdpMTU             int
}

type Client struct {
	ctx                context.Context
	dialer             N.Dialer
	logger             logger.Logger
	brutalDebug        bool
	serverAddress      func(ctx context.Context) (*net.UDPAddr, error)
	serverPorts        []uint16
	hopInterval        time.Duration
	sendBPS            uint64
	receiveBPS         uint64
	salamanderPassword string
	password           string
	tlsConfig          *tls.Config
	quicConfig         *quic.Config
	udpDisabled        bool
	cwnd               int
	udpMTU             int

	connAccess sync.Mutex
	connErr    error
	conn       *clientQUICConnection
}

func NewClient(options ClientOptions) (*Client, error) {
	quicConfig := &quic.Config{}
	if options.QUICConfig != nil {
		quicConfig = options.QUICConfig
	}
	quicConfig.DisablePathMTUDiscovery = !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin")
	quicConfig.EnableDatagrams = !options.UDPDisabled
	if quicConfig.InitialStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if quicConfig.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = DefaultStreamReceiveWindow
	}
	if quicConfig.InitialConnectionReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = DefaultConnReceiveWindow
	}
	if quicConfig.MaxConnectionReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = DefaultConnReceiveWindow
	}
	if quicConfig.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = DefaultMaxIdleTimeout
	}
	if quicConfig.KeepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = DefaultKeepAlivePeriod
	}
	if len(options.TLSConfig.NextProtos) == 0 {
		options.TLSConfig.NextProtos = []string{http3.NextProtoH3}
	}
	client := &Client{
		ctx:                options.Context,
		dialer:             options.Dialer,
		logger:             options.Logger,
		brutalDebug:        options.BrutalDebug,
		serverAddress:      options.ServerAddress,
		serverPorts:        options.ServerPorts,
		hopInterval:        options.HopInterval,
		sendBPS:            options.SendBPS,
		receiveBPS:         options.ReceiveBPS,
		salamanderPassword: options.SalamanderPassword,
		password:           options.Password,
		tlsConfig:          options.TLSConfig,
		quicConfig:         quicConfig,
		udpDisabled:        options.UDPDisabled,
		cwnd:               options.CWND,
		udpMTU:             options.UdpMTU,
	}
	return client, nil
}

func (c *Client) hopLoop(conn *clientQUICConnection, remoteAddr *net.UDPAddr) {
	ticker := time.NewTicker(c.hopInterval)
	defer ticker.Stop()
	c.logger.Debug("Entering hop loop ...")
	for {
		select {
		case <-ticker.C:
			targetAddr := *remoteAddr                                             // make a copy
			targetAddr.Port = int(c.serverPorts[randv2.IntN(len(c.serverPorts))]) // only change port
			conn.quicConn.SetRemoteAddr(&targetAddr)
			c.logger.Debug("Hopped to ", &targetAddr)
			continue
		case <-c.ctx.Done():
		case <-conn.quicConn.Context().Done():
		case <-conn.connDone:
		}
		c.logger.Debug("Exiting hop loop ...")
		return
	}
}

func (c *Client) offer(ctx context.Context) (*clientQUICConnection, error) {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.connErr != nil {
		return nil, c.connErr
	}
	conn := c.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	conn, err := c.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) offerNew(ctx context.Context) (*clientQUICConnection, error) {
	serverAddr, err := c.serverAddress(ctx)
	if err != nil {
		return nil, err
	}
	if len(c.serverPorts) > 0 { // randomize select a port from serverPorts
		serverAddr.Port = int(c.serverPorts[randv2.IntN(len(c.serverPorts))])
	}
	packetConn, err := c.dialer.ListenPacket(ctx, M.SocksaddrFromNet(serverAddr).Unwrap())
	if err != nil {
		return nil, err
	}
	if c.salamanderPassword != "" {
		packetConn = NewSalamanderConn(packetConn, []byte(c.salamanderPassword))
	}
	var quicConn *quic.Conn
	http3Transport, err := qtls.CreateTransport(packetConn, &quicConn, serverAddr, c.tlsConfig, c.quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, err
	}
	request := &http.Request{
		Method: http.MethodPost,
		URL: &url.URL{
			Scheme: "https",
			Host:   protocol.URLHost,
			Path:   protocol.URLPath,
		},
		Header: make(http.Header),
	}
	protocol.AuthRequestToHeader(request.Header, protocol.AuthRequest{Auth: c.password, Rx: c.receiveBPS})
	response, err := http3Transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, err
	}
	response.Body.Close()
	if response.StatusCode != protocol.StatusAuthOK {
		if quicConn != nil {
			quicConn.CloseWithError(0, "")
		}
		packetConn.Close()
		return nil, E.New("authentication failed, status code: ", response.StatusCode)
	}
	authResponse := protocol.AuthResponseFromHeader(response.Header)
	actualTx := authResponse.Rx
	if actualTx == 0 || actualTx > c.sendBPS {
		actualTx = c.sendBPS
	}
	if !authResponse.RxAuto && actualTx > 0 {
		quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, c.brutalDebug, c.logger))
	} else {
		SetCongestionController(quicConn, "bbr", c.cwnd)
	}
	conn := &clientQUICConnection{
		quicConn:    quicConn,
		rawConn:     packetConn,
		connDone:    make(chan struct{}),
		udpDisabled: !authResponse.UDPEnabled,
		udpConnMap:  make(map[uint32]*udpPacketConn),
	}
	if !c.udpDisabled {
		go c.loopMessages(conn)
	}
	c.conn = conn
	if c.hopInterval > 0 {
		go c.hopLoop(conn, serverAddr)
	}
	return conn, nil
}

func (c *Client) DialConn(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := conn.quicConn.OpenStream()
	if err != nil {
		return nil, err
	}
	return &clientConn{
		Stream:      stream,
		destination: destination,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if c.udpDisabled {
		return nil, os.ErrInvalid
	}
	conn, err := c.offer(ctx)
	if err != nil {
		return nil, err
	}
	if conn.udpDisabled {
		return nil, E.New("UDP disabled by server")
	}
	var sessionID uint32
	clientPacketConn := newUDPPacketConn(c.ctx, conn.quicConn, func() {
		conn.udpAccess.Lock()
		delete(conn.udpConnMap, sessionID)
		conn.udpAccess.Unlock()
	}, c.udpMTU)
	conn.udpAccess.Lock()
	sessionID = conn.udpSessionID
	conn.udpSessionID++
	conn.udpConnMap[sessionID] = clientPacketConn
	conn.udpAccess.Unlock()
	clientPacketConn.sessionID = sessionID
	return clientPacketConn, nil
}

func (c *Client) CloseWithError(err error) error {
	c.connAccess.Lock()
	defer c.connAccess.Unlock()
	if c.connErr != nil {
		return nil
	}
	conn := c.conn
	if conn != nil {
		conn.closeWithError(err)
	}
	c.connErr = err
	return nil
}

type clientQUICConnection struct {
	quicConn     *quic.Conn
	rawConn      io.Closer
	closeOnce    sync.Once
	connDone     chan struct{}
	connErr      error
	udpDisabled  bool
	udpAccess    sync.RWMutex
	udpConnMap   map[uint32]*udpPacketConn
	udpSessionID uint32
}

func (c *clientQUICConnection) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientQUICConnection) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		c.quicConn.CloseWithError(0, "")
		c.rawConn.Close()
	})
}

type clientConn struct {
	*quic.Stream
	destination    M.Socksaddr
	requestWritten bool
	responseRead   bool
}

func (c *clientConn) NeedHandshake() bool {
	return !c.requestWritten
}

func (c *clientConn) Read(p []byte) (n int, err error) {
	if c.responseRead {
		n, err = c.Stream.Read(p)
		return n, baderror.WrapQUIC(err)
	}
	status, errorMessage, err := protocol.ReadTCPResponse(c.Stream)
	if err != nil {
		return 0, baderror.WrapQUIC(err)
	}
	if !status {
		err = E.New("remote error: ", errorMessage)
		return
	}
	c.responseRead = true
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) Write(p []byte) (n int, err error) {
	if !c.requestWritten {
		buffer := protocol.WriteTCPRequest(c.destination.String(), p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return
		}
		c.requestWritten = true
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *clientConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *clientConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
