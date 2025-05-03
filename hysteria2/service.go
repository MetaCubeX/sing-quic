package hysteria2

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	tls "github.com/metacubex/utls"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/sing-quic"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/sing-quic/hysteria2/internal/protocol"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/baderror"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

type ServiceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	TLSConfig             *tls.Config
	QUICConfig            *quic.Config
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               ServerHandler
	MasqueradeHandler     http.Handler
	CWND                  int
	UdpMTU                int
}

type ServerHandler interface {
	N.TCPConnectionHandler
	N.UDPConnectionHandler
}

type Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	tlsConfig             *tls.Config
	quicConfig            *quic.Config
	userMap               map[string]U
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	cwnd                  int
	udpMTU                int
}

func NewService[U comparable](options ServiceOptions) (*Service[U], error) {
	quicConfig := &quic.Config{}
	if options.QUICConfig != nil {
		quicConfig = options.QUICConfig
	}
	quicConfig.DisablePathMTUDiscovery = !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin")
	quicConfig.EnableDatagrams = !options.UDPDisabled
	if quicConfig.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = 1 << 60
	}
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
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos) == 0 {
		options.TLSConfig.NextProtos = []string{http3.NextProtoH3}
	}
	return &Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		userMap:               make(map[string]U),
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		cwnd:                  options.CWND,
		udpMTU:                options.UdpMTU,
	}, nil
}

func (s *Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U)
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	s.userMap = userMap
}

func (s *Service[U]) Start(conn net.PacketConn) error {
	if s.salamanderPassword != "" {
		conn = NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	err := qtls.ConfigureHTTP3(s.tlsConfig)
	if err != nil {
		return err
	}
	listener, err := qtls.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *Service[U]) Close() error {
	return common.Close(
		s.quicListener,
	)
}

func (s *Service[U]) loopConnections(listener qtls.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *Service[U]) handleConnection(connection quic.Connection) {
	session := &serverSession[U]{
		Service:    s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*udpPacketConn),
	}
	httpServer := http3.Server{
		Handler:        session,
		StreamHijacker: session.handleStream0,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type serverSession[U comparable] struct {
	*Service[U]
	ctx           context.Context
	quicConn      quic.Connection
	connAccess    sync.Mutex
	connDone      chan struct{}
	connErr       error
	authenticated bool
	authUser      U
	udpAccess     sync.RWMutex
	udpConnMap    map[uint32]*udpPacketConn
}

func (s *serverSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		if s.authenticated {
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !s.udpDisabled,
				Rx:         s.receiveBPS,
				RxAuto:     s.ignoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		request := protocol.AuthRequestFromHeader(r.Header)
		user, loaded := s.userMap[request.Auth]
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		s.authUser = user
		s.authenticated = true
		if !s.ignoreClientBandwidth && request.Rx > 0 {
			rx := request.Rx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.brutalDebug, s.logger))
		} else {
			SetCongestionController(s.quicConn, "bbr", s.cwnd)
		}
		protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
			UDPEnabled: !s.udpDisabled,
			Rx:         s.receiveBPS,
			RxAuto:     s.ignoreClientBandwidth,
		})
		w.WriteHeader(protocol.StatusAuthOK)
		if s.ctx.Done() != nil {
			go func() {
				select {
				case <-s.ctx.Done():
					s.closeWithError(s.ctx.Err())
				case <-s.connDone:
				}
			}()
		}
		if !s.udpDisabled {
			go s.loopMessages()
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *serverSession[U]) handleStream0(frameType http3.FrameType, _ quic.ConnectionTracingID, stream quic.Stream, err error) (bool, error) {
	if !s.authenticated || err != nil {
		return false, nil
	}
	if frameType != protocol.FrameTypeTCPRequest {
		return false, nil
	}
	go func() {
		hErr := s.handleStream(stream)
		stream.CancelRead(0)
		stream.Close()
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *serverSession[U]) handleStream(stream quic.Stream) error {
	destinationString, err := protocol.ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	ctx := auth.ContextWithUser(s.ctx, s.authUser)
	_ = s.handler.NewConnection(ctx, &serverConn{Stream: stream}, M.Metadata{
		Source:      M.SocksaddrFromNet(s.quicConn.RemoteAddr()),
		Destination: M.ParseSocksaddr(destinationString),
	})
	return nil
}

func (s *serverSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	_ = s.quicConn.CloseWithError(0, "")
}

type serverConn struct {
	quic.Stream
	responseWritten bool
}

func (c *serverConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrClosed
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := protocol.WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *serverConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := protocol.WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, baderror.WrapQUIC(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *serverConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *serverConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
