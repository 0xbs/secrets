package secret

import (
	"math/rand"
	"testing"
)

const (
	passwordShort       = "zAzrqbw"
	passwordLong        = "sz-m9jKJEsM8Ue4LJpdt8Jw*Akax6y_u!hTfvXd@MweVFmqvPtKEbUm7PUn@FxCKwAnNUaA!.FXb7puzWU9dUQoM9tiP2"
	iterations          = 10000
	saltBytes           = 8
	plaintextHelloWorld = "Hello, World!"
	plaintextLorem      = "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod\ntempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,\nquis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo\nconsequat. Duis aute irure dolor in reprehenderit in voluptate velit esse\ncillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non\nproident, sunt in culpa qui officia deserunt mollit anim id est laborum."
	plaintextEmoji      = "👩🏿‍🤝‍👨🏻"
)

func TestEncryptDecrypt(t *testing.T) {
	type args struct {
		plaintext  string
		password   string
		iterations int
		saltBytes  int
	}
	tests := []struct {
		name string
		args args
	}{
		{"Hello World short 10000/8", args{plaintextHelloWorld, passwordShort, iterations, saltBytes}},
		{"Hello World short 100/8", args{plaintextHelloWorld, passwordShort, 100, saltBytes}},
		{"Hello World short 10000/32", args{plaintextHelloWorld, passwordShort, iterations, 32}},
		{"Hello World long 10000/8", args{plaintextHelloWorld, passwordLong, iterations, saltBytes}},
		{"Hello World long 100000/8", args{plaintextHelloWorld, passwordLong, 100000, saltBytes}},
		{"Lorem short", args{plaintextLorem, passwordShort, iterations, saltBytes}},
		{"Lorem long", args{plaintextLorem, passwordLong, iterations, saltBytes}},
		{"Emoji short", args{plaintextEmoji, passwordShort, iterations, saltBytes}},
		{"Emoji long", args{plaintextEmoji, passwordLong, iterations, saltBytes}},
		{"Empty short", args{"", passwordShort, iterations, saltBytes}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rand.Seed(1)
			s := NewCryptoService(tt.args.password, tt.args.iterations, 16, tt.args.saltBytes)

			aesCipherText, err := s.Encrypt([]byte(tt.args.plaintext))
			if err != nil {
				t.Error(err)
			}
			output := aesCipherText.String()

			parsedCipherText, err := NewCipherText([]byte(output))
			if err != nil {
				t.Error(err)
			}

			plaintextBytes, err := s.Decrypt(parsedCipherText)
			plaintext := string(plaintextBytes)
			if err != nil {
				t.Error(err)
			}
			if tt.args.plaintext != plaintext {
				t.Errorf("expected decrypted text '%s' to equal original text '%s'", plaintext, tt.args.plaintext)
			}
		})
	}
}
