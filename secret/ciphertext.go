package secret

import (
	"bytes"
	"encoding/base64"
	"fmt"
)

type CipherText struct {
	salt []byte
	iv   []byte
	data []byte
}

func NewCipherText(cipherText []byte) (CipherText, error) {
	parts := bytes.Split(cipherText, []byte(":"))
	if len(parts) != 3 {
		return CipherText{}, fmt.Errorf("expected cipher text to consist of 3 parts, but found %d", len(parts))
	}
	salt, err := base64.StdEncoding.DecodeString(string(parts[0]))
	if err != nil {
		return CipherText{}, fmt.Errorf("unable to decode salt: %v", err.Error())
	}
	iv, err := base64.StdEncoding.DecodeString(string(parts[1]))
	if err != nil {
		return CipherText{}, fmt.Errorf("unable to decode iv: %v", err.Error())
	}
	data, err := base64.StdEncoding.DecodeString(string(parts[2]))
	if err != nil {
		return CipherText{}, fmt.Errorf("unable to decode data: %v", err.Error())
	}
	return CipherText{salt: salt, iv: iv, data: data}, nil
}

func (t CipherText) String() string {
	salt := base64.StdEncoding.EncodeToString(t.salt)
	iv := base64.StdEncoding.EncodeToString(t.iv)
	data := base64.StdEncoding.EncodeToString(t.data)
	return fmt.Sprintf("%s:%s:%s", salt, iv, data)
}

func (t CipherText) Bytes() []byte {
	return []byte(t.String())
}
