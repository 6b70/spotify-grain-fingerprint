package server

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"fmt"
	"github.com/ksp237/grain128-go"
	"google.golang.org/protobuf/proto"
	"spotify-grain-fingerprint/proto/compiled/spotify"
)

// DecryptClientKey verifies and decrypts the encrypted key from the client
func DecryptClientKey(clientHello *spotify.ClientHello, apResponse *spotify.APResponseMessage, encryptedKey []byte) ([]byte, error) {
	// SHA1 hash of clientHello and apResponse
	clientHelloBytes, err := proto.Marshal(clientHello)
	if err != nil {
		return nil, fmt.Errorf("marshalling client hello: %w", err)
	}
	apResponseBytes, err := proto.Marshal(apResponse)
	if err != nil {
		return nil, fmt.Errorf("marshalling ap response: %w", err)
	}
	hash := sha1.New()
	hash.Write(clientHelloBytes)
	hash.Write(apResponseBytes)

	messageDigest := hash.Sum(nil)

	kek := apResponse.GetChallenge().GetFingerprintChallenge().GetGrain().GetKek()

	// Setup Grain128 with the KEK
	grainCipher, err := grain128.NewGrain128(kek)
	if err != nil {
		return nil, fmt.Errorf("setting up grain cipher: %w", err)
	}
	grainCipher.IVSetup(make([]byte, 16))

	// Generate the AES key by encrypting the first 16 bytes of the message digest
	aesKey := make([]byte, 16)
	grainCipher.XORKeyStream(aesKey, messageDigest[:16])

	// Decrypt the encryptedKey using AES CBC mode
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("creating AES cipher: %w", err)
	}
	mode := cipher.NewCBCDecrypter(block, make([]byte, 16))
	decryptedKey := make([]byte, len(encryptedKey))
	mode.CryptBlocks(decryptedKey, encryptedKey)

	// Verify the client nonce by decrypting it
	grainCipher, err = grain128.NewGrain128(decryptedKey)
	if err != nil {
		return nil, fmt.Errorf("setting up grain cipher with decrypted key: %w", err)
	}
	grainCipher.IVSetup(make([]byte, 16))
	plaintext := make([]byte, 16)
	grainCipher.XORKeyStream(plaintext, clientHello.GetClientNonce())

	if !bytes.Equal(plaintext, make([]byte, 16)) {
		return nil, fmt.Errorf("nonce verification failed: expected empty slice, got %v", plaintext)
	}

	return decryptedKey, nil
}
