package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"
)

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type ProxyServerConfig struct {
	BindAddress string `json:"bind_address"` // Address to bind the proxy
	Port        string `json:"port"`         // Port for the proxy
	Username    string `json:"username"`     // Username for authentication
	Password    string `json:"password"`     // Password for authentication
}

type TunnelConfig struct {
	ConnectPort       int           `json:"connect_port"`        // MASQUE connection port
	DNS               []string      `json:"dns"`                 // DNS servers for the tunnel
	DNSTimeout        time.Duration `json:"dns_timeout"`         // Timeout for DNS queries
	UseIPv6           bool          `json:"use_ipv6"`            // Use IPv6 for MASQUE connection
	NoTunnelIPv4      bool          `json:"no_tunnel_ipv4"`      // Disable IPv4 inside the tunnel
	NoTunnelIPv6      bool          `json:"no_tunnel_ipv6"`      // Disable IPv6 inside the tunnel
	SNIAddress        string        `json:"sni_address"`         // SNI address for MASQUE connection
	KeepalivePeriod   time.Duration `json:"keepalive_period"`    // Keepalive period for MASQUE connection
	MTU               int           `json:"mtu"`                 // MTU for MASQUE connection
	InitialPacketSize uint16        `json:"initial_packet_size"` // Initial packet size for MASQUE connection
	ReconnectDelay    time.Duration `json:"reconnect_delay"`     // Delay between reconnect attempts
	ConnectionTimeout time.Duration `json:"connection_timeout"`  // Timeout for establishing the connection
	IdleTimeout       time.Duration `json:"idle_timeout"`        // Idle timeout for MASQUE connection
}

type Config struct {
	PrivateKey     string            `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string            `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string            `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointPubKey string            `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string            `json:"license"`          // Application license key
	ID             string            `json:"id"`               // Device unique identifier
	AccessToken    string            `json:"access_token"`     // Authentication token for API access
	IPv4           string            `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string            `json:"ipv6"`             // Assigned IPv6 address
	Socks          ProxyServerConfig `json:"socks"`            // SOCKS proxy configuration
	HTTP           ProxyServerConfig `json:"http"`             // HTTP proxy configuration
	Tunnel         TunnelConfig      `json:"tunnel"`           // MASQUE tunnel configuration
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
func LoadConfig(configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&AppConfig); err != nil {
		return fmt.Errorf("failed to decode config file: %v", err)
	}

	ConfigLoaded = true

	return nil
}

// SaveConfig writes the current application configuration to a prettified JSON file.
//
// Parameters:
//   - configPath: string - The path to save the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be written.
func (*Config) SaveConfig(configPath string) error {
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(AppConfig); err != nil {
		return fmt.Errorf("failed to encode config file: %v", err)
	}

	return nil
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (*Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(AppConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (*Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(AppConfig.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}
