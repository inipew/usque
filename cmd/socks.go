package cmd

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/auth"
	"github.com/things-go/go-socks5/bufferpool"
	socks5resolver "github.com/things-go/go-socks5/resolver"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Expose Warp as a SOCKS5 proxy",
	Long:  "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		bindAddress, err := cmd.Flags().GetString("bind")
		if err != nil {
			cmd.Printf("Failed to get bind address: %v\n", err)
			return
		}
		if config.ConfigLoaded && !cmd.Flags().Changed("bind") && config.AppConfig.Socks.BindAddress != "" {
			bindAddress = config.AppConfig.Socks.BindAddress
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			cmd.Printf("Failed to get port: %v\n", err)
			return
		}
		if config.ConfigLoaded && !cmd.Flags().Changed("port") && config.AppConfig.Socks.Port != "" {
			port = config.AppConfig.Socks.Port
		}

		if config.ConfigLoaded && !cmd.Flags().Changed("username") && config.AppConfig.Socks.Username != "" {
			cmd.Flags().Set("username", config.AppConfig.Socks.Username)
		}
		if config.ConfigLoaded && !cmd.Flags().Changed("password") && config.AppConfig.Socks.Password != "" {
			cmd.Flags().Set("password", config.AppConfig.Socks.Password)
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		var endpoint *net.UDPAddr
		if ipv6, err := cmd.Flags().GetBool("ipv6"); err == nil && !ipv6 {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV4),
				Port: connectPort,
			}
		} else {
			endpoint = &net.UDPAddr{
				IP:   net.ParseIP(config.AppConfig.EndpointV6),
				Port: connectPort,
			}
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		var dnsTimeout time.Duration
		if dnsTimeout, err = cmd.Flags().GetDuration("dns-timeout"); err != nil {
			cmd.Printf("Failed to get DNS timeout: %v\n", err)
			return
		}

		localDNS, err := cmd.Flags().GetBool("local-dns")
		if err != nil {
			cmd.Printf("Failed to get local-dns flag: %v\n", err)
			return
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		var username string
		var password string
		if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
			username = u
		}
		if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
			password = p
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		tcpBuf, err := cmd.Flags().GetInt("tcp-buf")
		if err != nil {
			cmd.Printf("Failed to get tcp-buf: %v\n", err)
			return
		}
		udpBuf, err := cmd.Flags().GetInt("udp-buf")
		if err != nil {
			cmd.Printf("Failed to get udp-buf: %v\n", err)
			return
		}
		timeout, err := cmd.Flags().GetDuration("timeout")
		if err != nil {
			cmd.Printf("Failed to get timeout: %v\n", err)
			return
		}
		if config.ConfigLoaded {
			if !cmd.Flags().Changed("tcp-buf") && config.AppConfig.Socks.TCPBuf != 0 {
				tcpBuf = config.AppConfig.Socks.TCPBuf
			}
			if !cmd.Flags().Changed("udp-buf") && config.AppConfig.Socks.UDPBuf != 0 {
				udpBuf = config.AppConfig.Socks.UDPBuf
			}
			if !cmd.Flags().Changed("timeout") && config.AppConfig.Socks.Timeout.Duration != 0 {
				timeout = config.AppConfig.Socks.Timeout.Duration
			}
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer tunDev.Close()

		go api.MaintainTunnel(context.Background(), tlsConfig, keepalivePeriod, initialPacketSize, endpoint, api.NewNetstackAdapter(tunDev), mtu, reconnectDelay)

		var resolver socks5resolver.NameResolver
		if localDNS {
			resolver = internal.TunnelDNSResolver{TunNet: nil, DNSAddrs: dnsAddrs, Timeout: dnsTimeout}
		} else {
			resolver = internal.TunnelDNSResolver{TunNet: tunNet, DNSAddrs: dnsAddrs, Timeout: dnsTimeout}
		}

		logger := zerolog.New(os.Stdout)
		dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tunNet.DialContext(ctx, network, addr)
		}

		opts := []socks5.Option{
			socks5.WithLogger(socks5.NewLogger(logger)),
			socks5.WithDial(dial),
			socks5.WithResolver(resolver),
		}
		if tcpBuf > 0 && udpBuf > 0 && tcpBuf == udpBuf {
			opts = append(opts, socks5.WithBufferPool(bufferpool.NewPool(tcpBuf)))
		} else {
			if tcpBuf > 0 {
				opts = append(opts, socks5.WithBufferPoolTCP(bufferpool.NewPool(tcpBuf)))
			}
			if udpBuf > 0 {
				opts = append(opts, socks5.WithBufferPoolUDP(bufferpool.NewPool(udpBuf)))
			}
		}
		if timeout > 0 {
			opts = append(opts, socks5.WithTimeout(timeout))
		}
		if username != "" && password != "" {
			opts = append(opts, socks5.WithAuthMethods([]auth.Authenticator{
				auth.UserPassAuthenticator{
					Credentials: auth.StaticCredentials{
						username: password,
					},
				},
			}))
		}
		server := socks5.NewServer(opts...)

		log.Printf("SOCKS proxy listening on %s:%s", bindAddress, port)
		if err := server.ListenAndServe("tcp", net.JoinHostPort(bindAddress, port)); err != nil {
			cmd.Printf("Failed to start SOCKS proxy: %v\n", err)
			return
		}
	},
}

func init() {
	socksCmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers to use")
	socksCmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", 1242, "Initial packet size for MASQUE connection")
	socksCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	socksCmd.Flags().BoolP("local-dns", "l", false, "Don't use the tunnel for DNS queries")
	socksCmd.Flags().Int("tcp-buf", 0, "TCP read/write buffer size")
	socksCmd.Flags().Int("udp-buf", 0, "UDP read/write buffer size")
	socksCmd.Flags().Duration("timeout", 0, "Connection timeout for proxy dials")
	rootCmd.AddCommand(socksCmd)
}
