package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	connectip "github.com/inipew/connect-ip-go"
	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/net/http2"
)

// PrepareTlsConfig creates a TLS configuration using the provided certificate and SNI (Server Name Indication).
// It also verifies the peer's public key against the provided public key.
func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string, insecure bool) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
	}

	if !insecure {
		// we pin to the endpoint public key
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				//10 is NoValidChains
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		}
	}

	return tlsConfig, nil
}

// ConnectTunnel establishes a Connect-IP tunnel with the provided configuration.
// When UseHTTP2 is false it dials over QUIC/HTTP3; when true it dials over TCP/HTTP2.
func ConnectTunnel(ctx context.Context, cfg Config) (net.PacketConn, *http3.Transport, *connectip.Conn, *http.Response, error) {
	template := uritemplate.MustNew(cfg.ConnectURI)
	additionalHeaders := http.Header{
		"User-Agent": []string{""},
	}

	if cfg.UseHTTP2 {
		h2Endpoint, ok := cfg.Endpoint.(*net.TCPAddr)
		if !ok || h2Endpoint == nil {
			return nil, nil, nil, nil, errors.New("missing HTTP/2 TCP endpoint")
		}

		h2Headers := additionalHeaders.Clone()
		h2Headers.Set("cf-connect-proto", "cf-connect-ip")
		h2Headers.Set("pq-enabled", "false")

		h2Client, err := newHTTP2Client(cfg, cfg.TLSConfig, h2Endpoint, cfg.ConnectURI)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("failed to create HTTP/2 client: %w", err)
		}

		ipConn, rsp, err := connectip.DialH2(ctx, h2Client, template, h2Headers)
		if err != nil {
			if strings.Contains(err.Error(), "tls: access denied") {
				return nil, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
			}
			return nil, nil, nil, nil, fmt.Errorf("failed to dial connect-ip over HTTP/2: %w", err)
		}
		return nil, nil, ipConn, rsp, nil
	}

	quicEndpoint, ok := cfg.Endpoint.(*net.UDPAddr)
	if !ok || quicEndpoint == nil {
		return nil, nil, nil, nil, errors.New("missing HTTP/3 UDP endpoint")
	}

	var packetConn net.PacketConn
	var err error
	if cfg.ListenPacket != nil {
		packetConn, err = cfg.ListenPacket(ctx, "udp", quicEndpoint.String())
	} else {
		if quicEndpoint.IP.To4() == nil {
			packetConn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv6zero,
				Port: 0,
			})
		} else {
			packetConn, err = net.ListenUDP("udp", &net.UDPAddr{
				IP:   net.IPv4zero,
				Port: 0,
			})
		}
	}
	if err != nil {
		return packetConn, nil, nil, nil, err
	}

	conn, err := quic.Dial(
		ctx,
		packetConn,
		quicEndpoint,
		cfg.TLSConfig,
		cfg.QuicConfig,
	)
	if err != nil {
		return packetConn, nil, nil, nil, err
	}

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			// SETTINGS_H3_DATAGRAM_00 = 0x0000000000000276
			0x276: 1,
		},
		DisableCompression: true,
	}

	hconn := tr.NewClientConn(conn)
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	if err != nil {
		_ = tr.Close()
		_ = conn.CloseWithError(0, "connect-ip dial failed")
		if strings.Contains(err.Error(), "tls: access denied") {
			return packetConn, nil, nil, nil, errors.New("login failed! Please double-check if your tls key and cert is enrolled in the Cloudflare Access service")
		}
		return packetConn, nil, nil, nil, fmt.Errorf("failed to dial connect-ip: %w", err)
	}

	return packetConn, tr, ipConn, rsp, nil
}

// newHTTP2Client builds an HTTP client for CONNECT-IP over HTTP/2.
// It honors proxy environment variables and pins dialing to the selected endpoint.
func newHTTP2Client(cfg Config, baseTLSConfig *tls.Config, endpoint *net.TCPAddr, connectURI string) (*http.Client, error) {
	if endpoint == nil {
		return nil, errors.New("missing HTTP/2 endpoint")
	}

	parsedURI, err := url.Parse(connectURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connect URI: %w", err)
	}

	proxyURL, _ := http.ProxyFromEnvironment(&http.Request{URL: parsedURI})

	tlsConfig := baseTLSConfig.Clone()
	tlsConfig.NextProtos = []string{"h2"}

	if proxyURL == nil {
		transport := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
				var conn net.Conn
				var err error
				if cfg.DialContext != nil {
					conn, err = cfg.DialContext(ctx, network, endpoint.String())
				} else {
					dialer := &net.Dialer{}
					conn, err = dialer.DialContext(ctx, network, endpoint.String())
				}
				if err != nil {
					return nil, err
				}

				tlsConn := tls.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		}

		return &http.Client{Transport: transport}, nil
	}

	originAuthority := authorityWithDefaultPort(parsedURI, "443")
	proxyAuthority := authorityWithDefaultPort(proxyURL, proxyDefaultPort(proxyURL))
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:              http.ProxyFromEnvironment,
		ForceAttemptHTTP2:  true,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == originAuthority {
				addr = endpoint.String()
			}
			if cfg.DialContext != nil {
				return cfg.DialContext(ctx, network, addr)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialAddr := addr
			dialTLSConfig := tlsConfig
			if addr == proxyAuthority && proxyURL != nil {
				dialTLSConfig = &tls.Config{ServerName: proxyURL.Hostname()}
			} else if addr == originAuthority {
				dialAddr = endpoint.String()
			}

			var conn net.Conn
			var err error
			if cfg.DialContext != nil {
				conn, err = cfg.DialContext(ctx, network, dialAddr)
			} else {
				conn, err = dialer.DialContext(ctx, network, dialAddr)
			}
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, dialTLSConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	return &http.Client{Transport: transport}, nil
}

// authorityWithDefaultPort normalizes URL authority by adding a default port when missing.
func authorityWithDefaultPort(u *url.URL, defaultPort string) string {
	if u == nil {
		return ""
	}

	host := u.Hostname()
	if host == "" {
		return u.Host
	}

	port := u.Port()
	if port == "" {
		port = defaultPort
	}

	return net.JoinHostPort(host, port)
}

// proxyDefaultPort returns the default port for proxy scheme.
func proxyDefaultPort(u *url.URL) string {
	if u != nil && u.Scheme == "https" {
		return "443"
	}
	return "80"
}
