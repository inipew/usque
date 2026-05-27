package cmd

import (
	"context"
	"log"
	"net/netip"
	"time"

	"github.com/inipew/usque/api"
	"github.com/inipew/usque/config"
	"github.com/inipew/usque/internal"
	"github.com/inipew/usque/masque"
	"github.com/spf13/cobra"

	"github.com/sagernet/sing-tun"
)


var transparentTunCmd = &cobra.Command{
	Use:   "transparenttun",
	Short: "Expose Warp as a fully automated transparent TUN device",
	Long:  "Expose Warp as a cross-platform transparent TUN device with automated routing using SagerNet sing-tun. Requires elevated privileges (administrator/root).",
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

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			cmd.Printf("Failed to get insecure flag: %v\n", err)
			return
		}

		tlsConfig, err := masque.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
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

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			cmd.Printf("Failed to get HTTP/2 flag: %v\n", err)
			return
		}

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			cmd.Printf("Failed to get ipv6 flag: %v\n", err)
			return
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			cmd.Printf("Failed to select endpoint: %v\n", err)
			return
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
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

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. Packet loss and other issues may occur.")
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		alwaysReconnect, err := cmd.Flags().GetBool("always-reconnect")
		if err != nil {
			cmd.Printf("Failed to get always-reconnect flag: %v\n", err)
			return
		}

		interfaceName, err := cmd.Flags().GetString("interface-name")
		if err != nil {
			cmd.Printf("Failed to get interface name: %v\n", err)
			return
		}

		autoRoute, err := cmd.Flags().GetBool("auto-route")
		if err != nil {
			cmd.Printf("Failed to get auto-route flag: %v\n", err)
			return
		}

		strictRoute, err := cmd.Flags().GetBool("strict-route")
		if err != nil {
			cmd.Printf("Failed to get strict-route flag: %v\n", err)
			return
		}

		// Merge TransparentTun config defaults from config.json if defined
		if config.AppConfig.TransparentTun.InterfaceName != "" && !cmd.Flags().Changed("interface-name") {
			interfaceName = config.AppConfig.TransparentTun.InterfaceName
		}
		if config.AppConfig.TransparentTun.AutoRoute && !cmd.Flags().Changed("auto-route") {
			autoRoute = true
		}
		if config.AppConfig.TransparentTun.StrictRoute && !cmd.Flags().Changed("strict-route") {
			strictRoute = true
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			cmd.Printf("Failed to get on-connect flag: %v\n", err)
			return
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			cmd.Printf("Failed to get on-disconnect flag: %v\n", err)
			return
		}

		// Configure sing-tun options
		opts := tun.Options{
			Name:        interfaceName,
			MTU:         uint32(mtu),
			AutoRoute:   autoRoute,
			StrictRoute: strictRoute,
		}

		if !tunnelIPv4 {
			ip4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			opts.Inet4Address = []netip.Prefix{netip.PrefixFrom(ip4, 32)}
		}

		if !tunnelIPv6 {
			ip6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			opts.Inet6Address = []netip.Prefix{netip.PrefixFrom(ip6, 128)}
		}

		// Initialize cross-platform TUN device using SagerNet sing-tun
		tunInterface, err := tun.New(opts)
		if err != nil {
			log.Println("Are you root/administrator? Creating TUN devices requires elevated privileges.")
			log.Fatalf("Failed to create transparent TUN interface: %v", err)
		}
		defer func() { _ = tunInterface.Close() }()

		log.Printf("Successfully created transparent TUN interface: %s (MTU: %d)", interfaceName, mtu)
		if autoRoute {
			log.Println("Auto-routing is enabled. System default gateway will be directed through this tunnel interface.")
		}

		hookEnv := map[string]string{
			"USQUE_MODE":  "transparenttun",
			"USQUE_IFACE": interfaceName,
			"USQUE_IPV4":  config.AppConfig.IPv4,
			"USQUE_IPV6":  config.AppConfig.IPv6,
		}

		// Wrap and run MaintainTunnel
		tunAdapter := &singTunDevice{tunDev: tunInterface}

		go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
			Endpoint:          endpoint,
			Device:            tunAdapter,
			MTU:               mtu,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   alwaysReconnect,
			UseHTTP2:          useHTTP2,
			OnConnect:         onConnect,
			OnDisconnect:      onDisconnect,
			HookEnv:           hookEnv,
		})

		log.Println("Transparent tunnel successfully established. Running in the background...")

		// Wait indefinitely
		select {}
	},
}

func init() {
	transparentTunCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	transparentTunCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	transparentTunCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	transparentTunCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	transparentTunCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	transparentTunCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	transparentTunCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	transparentTunCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	transparentTunCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	transparentTunCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	transparentTunCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	transparentTunCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	transparentTunCmd.Flags().StringP("interface-name", "n", "usque-tun", "Custom interface name for the transparent TUN interface")
	transparentTunCmd.Flags().Bool("auto-route", true, "Automatically configure host system routing table to direct traffic to this interface")
	transparentTunCmd.Flags().Bool("strict-route", false, "Prevent packet loops by strictly filtering out loop routes")
	transparentTunCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	transparentTunCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(transparentTunCmd)
}
