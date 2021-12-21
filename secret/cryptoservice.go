package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
)

type CryptoService struct {
	password   string
	iterations int
	keyBytes   int
	saltBytes  int
}

func NewCryptoService(password string, iterations int, keyBytes int, saltBytes int) *CryptoService {
	return &CryptoService{
		password:   password,
		iterations: iterations,
		keyBytes:   keyBytes,
		saltBytes:  saltBytes,
	}
}

func (s *CryptoService) Decrypt(cipherText CipherText) ([]byte, error) {
	key := s.deriveKey(cipherText.salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(block, cipherText.iv)
	plaintextBytes := make([]byte, len(cipherText.data))
	decrypter.CryptBlocks(plaintextBytes, cipherText.data)
	plaintext := pkcs5Trim(plaintextBytes)
	return plaintext, nil
}

func (s *CryptoService) Encrypt(plaintext []byte) (CipherText, error) {
	salt := make([]byte, s.saltBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return CipherText{}, err
	}
	iv := make([]byte, aes.BlockSize)
	_, err = rand.Read(iv)
	if err != nil {
		return CipherText{}, err
	}
	paddedPlaintext := pkcs5Pad(plaintext, aes.BlockSize)

	key := s.deriveKey(salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return CipherText{}, err
	}
	encrypter := cipher.NewCBCEncrypter(block, iv)
	data := make([]byte, len(paddedPlaintext))
	encrypter.CryptBlocks(data, paddedPlaintext)
	return CipherText{salt: salt, iv: iv, data: data}, nil
}

func (s *CryptoService) deriveKey(salt []byte) []byte {
	// Java implementation uses PBEWithHmacSHA256AndAES_128 which means we can use PBKDF2
	// with SHA-256 hashing function and default 16-byte key to select AES-128 in aes.NewCipher
	return pbkdf2.Key([]byte(s.password), salt, s.iterations, s.keyBytes, sha256.New)
}

func pkcs5Pad(plaintextBytes []byte, blockSize int) []byte {
	padding := blockSize - len(plaintextBytes)%blockSize
	paddingBytes := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintextBytes, paddingBytes...)
}

func pkcs5Trim(plaintextBytes []byte) []byte {
	padding := plaintextBytes[len(plaintextBytes)-1]
	return plaintextBytes[:len(plaintextBytes)-int(padding)]
}
