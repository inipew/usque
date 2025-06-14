package config

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSaveAndLoadConfig(t *testing.T) {
	expected := Config{
		PrivateKey:     "cHJpdmF0ZWtleQ==",
		EndpointV4:     "127.0.0.1",
		EndpointV6:     "::1",
		EndpointPubKey: "-----BEGIN PUBLIC KEY-----\nMFkwE...\n-----END PUBLIC KEY-----\n",
		License:        "license",
		ID:             "device-id",
		AccessToken:    "token",
		IPv4:           "172.16.0.2",
		IPv6:           "2606::1",
		Socks: ProxyServerConfig{
			BindAddress: "0.0.0.0",
			Port:        "1080",
			Username:    "user",
			Password:    "pass",
		},
		HTTP: ProxyServerConfig{
			BindAddress: "0.0.0.0",
			Port:        "8000",
			Username:    "huser",
			Password:    "hpass",
		},
		Tunnel: TunnelConfig{
			ConnectPort:       443,
			DNS:               []string{"1.1.1.1"},
			DNSTimeout:        2 * time.Second,
			UseIPv6:           true,
			NoTunnelIPv4:      false,
			NoTunnelIPv6:      true,
			SNIAddress:        "example.com",
			KeepalivePeriod:   30 * time.Second,
			MTU:               1280,
			InitialPacketSize: 1242,
			ReconnectDelay:    time.Second,
			ConnectionTimeout: 20 * time.Second,
			IdleTimeout:       5 * time.Minute,
		},
	}

	AppConfig = expected
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := AppConfig.SaveConfig(path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	// Clear and reload
	AppConfig = Config{}
	ConfigLoaded = false
	if err := LoadConfig(path); err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if !ConfigLoaded {
		t.Fatalf("ConfigLoaded not set")
	}

	if !reflect.DeepEqual(AppConfig, expected) {
		t.Fatalf("Loaded config does not match expected")
	}
}
