package secret

import "io"

type PipeService struct {
	cryptoService *CryptoService
	r             io.Reader
	w             io.Writer
}

func NewPipeService(cryptoService *CryptoService, r io.Reader, w io.Writer) *PipeService {
	return &PipeService{cryptoService: cryptoService, r: r, w: w}
}

func (s *PipeService) Encrypt() error {
	bytes, err := io.ReadAll(s.r)
	if err != nil {
		return err
	}
	cipherText, err := s.cryptoService.Encrypt(bytes)
	if err != nil {
		return err
	}
	_, err = s.w.Write(cipherText.Bytes())
	return err
}

func (s *PipeService) Decrypt() error {
	bytes, err := io.ReadAll(s.r)
	if err != nil {
		return err
	}
	cipherText, err := NewCipherText(bytes)
	if err != nil {
		return err
	}
	plaintext, err := s.cryptoService.Decrypt(cipherText)
	if err != nil {
		return err
	}
	_, err = s.w.Write(plaintext)
	return err
}
