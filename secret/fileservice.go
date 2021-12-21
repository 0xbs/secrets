package secret

import "os"

type FileService struct {
	cryptoService *CryptoService
	extension     string
	removeFiles   bool
}

func NewFileService(cryptoService *CryptoService, extension string, removeFiles bool) *FileService {
	return &FileService{cryptoService: cryptoService, extension: extension, removeFiles: removeFiles}
}

func (s *FileService) DecryptFile(filename string) error {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	cipherText, err := NewCipherText(fileBytes)
	if err != nil {
		return err
	}
	plaintext, err := s.cryptoService.Decrypt(cipherText)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename[:len(filename)-len(s.extension)], plaintext, 0600)
	if err != nil {
		return err
	}
	if s.removeFiles {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *FileService) EncryptFile(filename string) error {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	cipherText, err := s.cryptoService.Encrypt(fileBytes)
	if err != nil {
		return err
	}
	err = os.WriteFile(filename+s.extension, cipherText.Bytes(), 0600)
	if err != nil {
		return err
	}
	if s.removeFiles {
		err = os.Remove(filename)
		if err != nil {
			return err
		}
	}
	return nil
}
