package token

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// EncryptToken Encrypts a JWT token value with specific encryption key
func EncryptToken(value, key string) (string, error) {
	keyDecoded, _ := base64.StdEncoding.DecodeString(key)
	plaintext := []byte(value)

	block, err := aes.NewCipher(keyDecoded)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptToken Decrypts a JWT token value with specific encryption key
func DecryptToken(value, key string) (string, error) {
	keyDecoded, _ := base64.StdEncoding.DecodeString(key)
	enc, _ := base64.StdEncoding.DecodeString(value)

	block, err := aes.NewCipher(keyDecoded)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()

	if len(enc) < nonceSize {
		return "", errors.New("encrypted value is not valid")
	}

	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
