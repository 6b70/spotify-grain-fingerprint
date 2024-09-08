package client

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha1"
	"fmt"
	"github.com/ksp237/grain128-go"
	"google.golang.org/protobuf/proto"
	"spotify-grain-fingerprint/proto/compiled/spotify"
)

type Fingerprint struct {
	ClientNonce    []byte
	secretKeyBytes []byte
}

func NewFingerprintGrain() (*Fingerprint, error) {
	// Client generates secret key
	secretKeyBytes := make([]byte, 16)
	if _, err := crand.Read(secretKeyBytes); err != nil {
		return nil, fmt.Errorf("generating random private key: %w", err)
	}

	nonceGrain, err := grain128.NewGrain128(secretKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("new grain: %w", err)
	}
	nonceGrain.IVSetup(make([]byte, 16))

	clientNonce := make([]byte, 16)
	// Encrypt an empty slice to get the client nonce
	nonceGrain.XORKeyStream(clientNonce, make([]byte, 16))

	// Client nonce sent to server in the PB ClientHello message
	return &Fingerprint{
		secretKeyBytes: secretKeyBytes,
		ClientNonce:    clientNonce,
	}, nil
}

// CreateEncryptedKey creates enc key which is sent in the ClientResponseEncrypted message
func (c *Fingerprint) CreateEncryptedKey(clientHello *spotify.ClientHello, apResponse *spotify.APResponseMessage) ([]byte, error) {
	hash := sha1.New()
	clientHelloBytes, err := proto.Marshal(clientHello)
	if err != nil {
		return nil, fmt.Errorf("marshalling client hello: %w", err)
	}
	apResponseBytes, err := proto.Marshal(apResponse)
	if err != nil {
		return nil, fmt.Errorf("marshalling ap response: %w", err)
	}
	hash.Write(clientHelloBytes)
	hash.Write(apResponseBytes)

	// Message digest is 20 bytes long
	messageDigest := hash.Sum(nil)

	// Key encryption key used to get AES key
	kek := apResponse.GetChallenge().GetFingerprintChallenge().GetGrain().GetKek()

	aesKey := make([]byte, 16)
	aesGrain, err := grain128.NewGrain128(kek)
	if err != nil {
		return nil, fmt.Errorf("new grain: %w", err)
	}
	aesGrain.IVSetup(make([]byte, 16))
	// encrypt with first 16 bytes of message digest
	aesGrain.XORKeyStream(aesKey, messageDigest[:16])

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("new aes cipher: %w", err)
	}

	// AES CBC-128-NoPadding to encrypt client secret key
	// will panic if block length and iv length are not the same
	mode := cipher.NewCBCEncrypter(block, make([]byte, 16))
	clientSecretKey := c.secretKeyBytes
	mode.CryptBlocks(clientSecretKey, clientSecretKey)
	// Fingerprint response in ClientResponseEncrypted
	return clientSecretKey, nil
}
