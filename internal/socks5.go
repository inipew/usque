package internal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/Diniboy1123/usque/internal/netstack"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"
)

// SOCKS5Config holds listen address, auth, tunnel dialers, and timeouts for SOCKS5Server.
type SOCKS5Config struct {
	Addr       string
	Username   string
	Password   string
	Resolver   *TunnelDNSResolver
	TunNet     *netstack.Net
	TCPTimeout time.Duration // 0 = no deadline on TCP CONNECT relay
	UDPTimeout time.Duration // 0 = no deadline on remote UDP reads
	Logger     *log.Logger
}

// SOCKS5Server wraps SagerNet SOCKS5 protocol handler.
type SOCKS5Server struct {
	cfg SOCKS5Config
}

// NewSOCKS5Server creates a new SOCKS5Server with the given configuration.
func NewSOCKS5Server(cfg SOCKS5Config) (*SOCKS5Server, error) {
	if cfg.TunNet == nil {
		return nil, fmt.Errorf("socks5: TunNet is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	return &SOCKS5Server{cfg: cfg}, nil
}

type socksPacketListener struct{}

func (s *socksPacketListener) ListenPacket(listenConfig net.ListenConfig, ctx context.Context, network string, address string) (net.PacketConn, error) {
	return net.ListenPacket(network, address)
}

type socksHandler struct {
	tunNet *netstack.Net
	logger *log.Logger
}

func (s *socksHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	targetConn, err := s.tunNet.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		_ = conn.Close()
		if onClose != nil {
			onClose(err)
		}
		return
	}

	// Relay TCP data between SOCKS5 client and MASQUE tunnel
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(targetConn, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, targetConn)
		errChan <- err
	}()

	err = <-errChan
	_ = targetConn.Close()
	_ = conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (s *socksHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()

	remotes := make(map[string]net.Conn)
	defer func() {
		for _, remote := range remotes {
			_ = remote.Close()
		}
	}()

	errChan := make(chan error, 1)

	// Reader loop: client -> tunnel
	go func() {
		for {
			buffer := buf.NewPacket()
			dest, err := conn.ReadPacket(buffer)
			if err != nil {
				buffer.Release()
				errChan <- err
				return
			}

			destStr := dest.String()
			remoteConn, ok := remotes[destStr]
			if !ok {
				remoteConn, err = s.tunNet.DialContext(ctx, "udp", destStr)
				if err != nil {
					buffer.Release()
					s.logger.Printf("Failed to dial UDP to %s: %v", destStr, err)
					continue
				}
				remotes[destStr] = remoteConn

				// Start copy loop for this remote: tunnel -> client
				go func(rc net.Conn, target M.Socksaddr) {
					packetBuf := make([]byte, 65535)
					for {
						n, err := rc.Read(packetBuf)
						if err != nil {
							return
						}

						writeBuf := buf.NewPacket()
						_, _ = writeBuf.Write(packetBuf[:n])
						err = conn.WritePacket(writeBuf, target)
						if err != nil {
							writeBuf.Release()
							return
						}
					}
				}(remoteConn, dest)
			}

			_, err = remoteConn.Write(buffer.Bytes())
			buffer.Release()
			if err != nil {
				s.logger.Printf("Failed to write UDP packet to %s: %v", destStr, err)
			}
		}
	}()

	err := <-errChan
	if onClose != nil {
		onClose(err)
	}
}

// Start launches the SOCKS5 server listening loop.
func (s *SOCKS5Server) Start() error {
	listener, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()

	var authenticator *auth.Authenticator
	if s.cfg.Username != "" && s.cfg.Password != "" {
		authenticator = auth.NewAuthenticator([]auth.User{
			{Username: s.cfg.Username, Password: s.cfg.Password},
		})
	}

	handler := &socksHandler{
		tunNet: s.cfg.TunNet,
		logger: s.cfg.Logger,
	}
	packetListener := &socksPacketListener{}

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		go func(c net.Conn) {
			r := bufio.NewReader(c)
			source := M.SocksaddrFromNet(c.RemoteAddr())
			
			err := socks.HandleConnectionEx(
				context.Background(),
				c,
				r,
				authenticator,
				handler,
				packetListener,
				s.cfg.UDPTimeout,
				source,
				nil,
			)
			if err != nil && !E.IsClosedOrCanceled(err) {
				s.cfg.Logger.Printf("SOCKS connection error: %v", err)
			}
		}(conn)
	}
}
