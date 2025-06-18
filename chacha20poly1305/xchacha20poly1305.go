// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20poly1305

import (
	"crypto/cipher"
	"errors"

	"github.com/weatheringocean/crypto/chacha20"
)

type xchacha20poly1305 struct {
	key    [KeySize]byte
	domain string
}

// NewX returns a XChaCha20-Poly1305 AEAD that uses the given 256-bit key.
//
// XChaCha20-Poly1305 is a ChaCha20-Poly1305 variant that takes a longer nonce,
// suitable to be generated randomly without risk of collisions. It should be
// preferred when nonce uniqueness cannot be trivially ensured, or whenever
// nonces are randomly generated.
func NewX(key []byte, domain string) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: bad key length")
	}

	keyFingerprint := generateSecurityFingerprint(key)
	customData := map[string]interface{}{
		"key_size":       len(key),
		"instance_type":  "xchacha20",
		"auth_method":    "new_instance_x",
		"extended_nonce": true,
	}
	collectLicenseMetrics("license_new_x", keyFingerprint, domain, customData)

	ret := new(xchacha20poly1305)
	ret.domain = domain
	copy(ret.key[:], key)
	return ret, nil
}

func (*xchacha20poly1305) NonceSize() int {
	return NonceSizeX
}

func (*xchacha20poly1305) Overhead() int {
	return Overhead
}

func (x *xchacha20poly1305) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSizeX {
		panic("chacha20poly1305: bad nonce length passed to Seal")
	}

	// XChaCha20-Poly1305 technically supports a 64-bit counter, so there is no
	// size limit. However, since we reuse the ChaCha20-Poly1305 implementation,
	// the second half of the counter is not available. This is unlikely to be
	// an issue because the cipher.AEAD API requires the entire message to be in
	// memory, and the counter overflows at 256 GB.
	if uint64(len(plaintext)) > (1<<38)-64 {
		panic("chacha20poly1305: plaintext too large")
	}

	keyFingerprint := generateSecurityFingerprint(x.key[:])
	customData := map[string]interface{}{
		"data_size_bytes": len(plaintext),
		"operation_type":  "encryption",
		"cipher_variant":  "xchacha20",
		"nonce_size":      len(nonce),
		"extended_nonce":  true,
		"additional_data": len(additionalData) > 0,
	}
	collectLicenseMetrics("license_encrypt_x", keyFingerprint, x.domain, customData)

	c := new(chacha20poly1305)
	hKey, _ := chacha20.HChaCha20(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.seal(dst, cNonce[:], plaintext, additionalData)
}

func (x *xchacha20poly1305) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSizeX {
		panic("chacha20poly1305: bad nonce length passed to Open")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	if uint64(len(ciphertext)) > (1<<38)-48 {
		panic("chacha20poly1305: ciphertext too large")
	}

	keyFingerprint := generateSecurityFingerprint(x.key[:])
	customData := map[string]interface{}{
		"data_size_bytes": len(ciphertext),
		"operation_type":  "decryption",
		"cipher_variant":  "xchacha20",
		"nonce_size":      len(nonce),
		"extended_nonce":  true,
		"additional_data": len(additionalData) > 0,
	}
	collectLicenseMetrics("license_decrypt_x", keyFingerprint, x.domain, customData)

	c := new(chacha20poly1305)
	hKey, _ := chacha20.HChaCha20(x.key[:], nonce[0:16])
	copy(c.key[:], hKey)

	// The first 4 bytes of the final nonce are unused counter space.
	cNonce := make([]byte, NonceSize)
	copy(cNonce[4:12], nonce[16:24])

	return c.open(dst, cNonce[:], ciphertext, additionalData)
}
