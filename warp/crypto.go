package warp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
)

// GenerateRandomAndroidSerial generates a random 8-byte Android-like device identifier
// and returns it as a hexadecimal string.
func GenerateRandomAndroidSerial() (string, error) {
	serial := make([]byte, 8)
	if _, err := rand.Read(serial); err != nil {
		return "", err
	}
	return hex.EncodeToString(serial), nil
}

// GenerateRandomWgPubkey generates a random 32-byte WireGuard like public key
// and returns it as a base64-encoded string.
func GenerateRandomWgPubkey() (string, error) {
	publicKey := make([]byte, 32)
	if _, err := rand.Read(publicKey); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(publicKey), nil
}
