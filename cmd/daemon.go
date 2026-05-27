package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/netstack"

	"github.com/sagernet/sing-tun"
)

func runDaemon() {
	ctx := context.Background()

	// 1. Check if SOCKS or HTTP is enabled (User-space Netstack services)
	netstackEnabled := config.AppConfig.Socks.Enable || config.AppConfig.HTTPProxy.Enable

	// 2. Bootstrap Tunnel Connection for Netstack if needed
	var tunNet *netstack.Net
	if netstackEnabled {
		tlsConfig, endpoint, err := bootstrapTunnel(false, false, false, 443, internal.ConnectSNI)
		if err != nil {
			log.Fatalf("Failed to bootstrap tunnel for netstack services: %v", err)
		}

		var localAddresses []netip.Addr
		v4, err := netip.ParseAddr(config.AppConfig.IPv4)
		if err == nil {
			localAddresses = append(localAddresses, v4)
		}
		v6, err := netip.ParseAddr(config.AppConfig.IPv6)
		if err == nil {
			localAddresses = append(localAddresses, v6)
		}

		dnsAddrs := []netip.Addr{
			netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("149.112.112.112"),
		}

		tunDev, tNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, 1280)
		if err != nil {
			log.Fatalf("Failed to create virtual TUN device for netstack services: %v", err)
		}
		tunNet = tNet

		hookEnv := map[string]string{
			"USQUE_MODE": "daemon",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		go api.MaintainTunnel(ctx, api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   30 * time.Second,
			InitialPacketSize: 0,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(tunDev),
			MTU:               1280,
			ReconnectDelay:    1 * time.Second,
			AlwaysReconnect:   true,
			UseHTTP2:          false,
			HookEnv:           hookEnv,
		})

		log.Println("Background MASQUE tunnel for user-space proxies established successfully.")
	}

	// 3. Start SOCKS5 Server if enabled
	if config.AppConfig.Socks.Enable {
		sCfg := config.AppConfig.Socks
		if sCfg.Bind == "" {
			sCfg.Bind = "0.0.0.0"
		}
		if sCfg.Port == "" {
			sCfg.Port = "1080"
		}
		go func() {
			if err := startDaemonSocks(ctx, sCfg, tunNet); err != nil {
				log.Printf("Error starting SOCKS5 service: %v", err)
			}
		}()
	}

	// 4. Start HTTP Proxy Server if enabled
	if config.AppConfig.HTTPProxy.Enable {
		hCfg := config.AppConfig.HTTPProxy
		if hCfg.Bind == "" {
			hCfg.Bind = "0.0.0.0"
		}
		if hCfg.Port == "" {
			hCfg.Port = "8000"
		}
		go func() {
			if err := startDaemonHTTPProxy(ctx, hCfg, tunNet); err != nil {
				log.Printf("Error starting HTTP-Proxy service: %v", err)
			}
		}()
	}

	// 5. Start Transparent TUN if enabled
	if config.AppConfig.TransparentTun.Enable {
		tCfg := config.AppConfig.TransparentTun
		tlsConfig, endpoint, err := bootstrapTunnel(false, false, false, 443, internal.ConnectSNI)
		if err != nil {
			log.Fatalf("Failed to bootstrap tunnel for Transparent TUN service: %v", err)
		}

		go func() {
			if err := startDaemonTransparentTun(ctx, tCfg, tlsConfig, endpoint); err != nil {
				log.Printf("Error starting Transparent TUN service: %v", err)
			}
		}()
	}

	// Block indefinitely to keep the services running
	select {}
}

func bootstrapTunnel(useHTTP2, useIPv6, insecure bool, connectPort int, sni string) (*tls.Config, net.Addr, error) {
	privKey, err := config.AppConfig.GetEcPrivateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get private key: %w", err)
	}
	peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get public key: %w", err)
	}
	cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate cert: %w", err)
	}
	tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to prepare TLS config: %w", err)
	}
	endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to select endpoint: %w", err)
	}
	return tlsConfig, endpoint, nil
}

func startDaemonSocks(ctx context.Context, sCfg config.SocksConfig, tunNet *netstack.Net) error {
	var dnsAddrs []netip.Addr
	for _, dns := range sCfg.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return fmt.Errorf("failed to parse DNS %q: %w", dns, err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = []netip.Addr{
			netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("149.112.112.112"),
		}
	}
	resolver := &internal.TunnelDNSResolver{
		DNSAddrs:      dnsAddrs,
		Timeout:       2 * time.Second,
		UseOSResolver: false,
	}
	if !sCfg.LocalDNS {
		resolver.TunNet = tunNet
	}

	server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
		Addr:       net.JoinHostPort(sCfg.Bind, sCfg.Port),
		Username:   sCfg.Username,
		Password:   sCfg.Password,
		Resolver:   resolver,
		TunNet:     tunNet,
		UDPTimeout: 60 * time.Second,
		Logger:     log.New(internal.NewTZStampWriter(internal.GetLogWriter()), "socks5: ", 0),
	})
	if err != nil {
		return err
	}
	log.Printf("SOCKS5 proxy listening on %s:%s", sCfg.Bind, sCfg.Port)
	return server.Start()
}

func startDaemonHTTPProxy(ctx context.Context, hCfg config.HTTPProxyConfig, tunNet *netstack.Net) error {
	var dnsAddrs []netip.Addr
	for _, dns := range hCfg.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return fmt.Errorf("failed to parse DNS %q: %w", dns, err)
		}
		dnsAddrs = append(dnsAddrs, addr)
	}
	if len(dnsAddrs) == 0 {
		dnsAddrs = []netip.Addr{
			netip.MustParseAddr("9.9.9.9"),
			netip.MustParseAddr("149.112.112.112"),
		}
	}

	resolver := internal.GetProxyResolver(hCfg.LocalDNS, false, tunNet, dnsAddrs, 2*time.Second)

	var authHeader string
	if hCfg.Username != "" && hCfg.Password != "" {
		authHeader = "Basic " + internal.LoginToBase64(hCfg.Username, hCfg.Password)
	}

	server := &http.Server{
		Addr: net.JoinHostPort(hCfg.Bind, hCfg.Port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !authenticate(r, authHeader) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
				http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				return
			}

			if r.Method == http.MethodConnect {
				handleHTTPSConnect(w, r, tunNet, resolver)
			} else {
				handleHTTPProxy(w, r, tunNet, resolver)
			}
		}),
	}
	log.Printf("HTTP proxy listening on %s:%s\n", hCfg.Bind, hCfg.Port)
	return server.ListenAndServe()
}

type singTunDaemonDevice struct {
	tunDev tun.Tun
}

func (s *singTunDaemonDevice) ReadPacket(buf []byte) (int, error) {
	return s.tunDev.Read(buf)
}

func (s *singTunDaemonDevice) WritePacket(pkt []byte) error {
	_, err := s.tunDev.Write(pkt)
	return err
}

func startDaemonTransparentTun(ctx context.Context, tCfg config.TransparentTunConfig, tlsConfig *tls.Config, endpoint net.Addr) error {
	opts := tun.Options{
		Name:        tCfg.InterfaceName,
		MTU:         1280,
		AutoRoute:   tCfg.AutoRoute,
		StrictRoute: tCfg.StrictRoute,
	}
	if opts.Name == "" {
		opts.Name = "usque-tun"
	}

	ip4, err := netip.ParseAddr(config.AppConfig.IPv4)
	if err != nil {
		return fmt.Errorf("failed to parse IPv4 address: %w", err)
	}
	opts.Inet4Address = []netip.Prefix{netip.PrefixFrom(ip4, 32)}

	ip6, err := netip.ParseAddr(config.AppConfig.IPv6)
	if err != nil {
		return fmt.Errorf("failed to parse IPv6 address: %w", err)
	}
	opts.Inet6Address = []netip.Prefix{netip.PrefixFrom(ip6, 128)}

	tunInterface, err := tun.New(opts)
	if err != nil {
		return fmt.Errorf("failed to create transparent TUN interface: %w", err)
	}

	log.Printf("Successfully created transparent TUN interface: %s (MTU: 1280)", opts.Name)
	if tCfg.AutoRoute {
		log.Println("Auto-routing is enabled. System default gateway will be directed through this tunnel interface.")
	}

	hookEnv := map[string]string{
		"USQUE_MODE":  "transparenttun_daemon",
		"USQUE_IFACE": opts.Name,
		"USQUE_IPV4":  config.AppConfig.IPv4,
		"USQUE_IPV6":  config.AppConfig.IPv6,
	}

	tunAdapter := &singTunDaemonDevice{tunDev: tunInterface}

	go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
		TLSConfig:         tlsConfig,
		KeepalivePeriod:   30 * time.Second,
		InitialPacketSize: 0,
		Endpoint:          endpoint,
		Device:            tunAdapter,
		MTU:               1280,
		ReconnectDelay:    1 * time.Second,
		AlwaysReconnect:   true,
		UseHTTP2:          false,
		HookEnv:           hookEnv,
	})

	return nil
}
