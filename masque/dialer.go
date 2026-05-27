package masque

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/quic-go/quic-go"
)

// DialContextFunc matches SagerNet / sing-box outbound TCP dialers
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ListenPacketFunc matches SagerNet / sing-box outbound UDP dialers
type ListenPacketFunc func(ctx context.Context, network, address string) (net.PacketConn, error)

// Logger defines a simple logger interface compatible with standard and sing-box loggers
type Logger interface {
	Printf(format string, v ...any)
}

// Config holds options for establishing a MASQUE connection
type Config struct {
	TLSConfig      *tls.Config
	QuicConfig     *quic.Config
	ConnectURI     string
	Endpoint       net.Addr
	UseHTTP2       bool
	DialContext    DialContextFunc
	ListenPacket   ListenPacketFunc
	Logger         Logger
}
