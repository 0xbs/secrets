package main

import secret "github.com/0xbs/secrets/secret"

import (
	"flag"
	"fmt"
	"golang.org/x/term"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	rand.Seed(time.Now().UTC().UnixNano())

	forceDecrypt := flag.Bool("d", false, "force decryption regardless of file extension")
	passwordDirect := flag.String("p", "", "password for encryption and decryption")
	passwordFromEnv := flag.String("q", "", "read password from given environment variable")
	extension := flag.String("x", ".encrypted", "extension for encrypted files")
	continueOnError := flag.Bool("c", false, "continue operation even if a file cannot be processed")
	removeFiles := flag.Bool("r", false, "remove source files after encryption or decryption")
	iterations := flag.Int("i", 10000, "number of iterations for PBKDF2 key derivation")
	saltBytes := flag.Int("s", 8, "number bytes used for salt")
	keyBytes := flag.Int("k", 16, "number bytes used for encryption key, either 16, 24, or 32 bytes to select AES-128, AES-192, or AES-256")
	flag.Usage = printUsage
	flag.Parse()

	password := ""
	if *passwordDirect != "" {
		password = *passwordDirect
	} else if *passwordFromEnv != "" {
		password = os.Getenv(*passwordFromEnv)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		ErrPrintf("Password:")
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			ErrPrintf("Error reading password from terminal: %s\n", err.Error())
			os.Exit(1)
		}
		password = string(bytePassword)
	}

	if password == "" {
		ErrPrintf("No password given, aborting.\n")
		os.Exit(1)
	}

	cryptoService := secret.NewCryptoService(password, *iterations, *keyBytes, *saltBytes)
	fileService := secret.NewFileService(cryptoService, *extension, *removeFiles)
	pipeService := secret.NewPipeService(cryptoService, os.Stdin, os.Stdout)

	if flag.NArg() == 0 {
		if *forceDecrypt {
			err := pipeService.Decrypt()
			if err != nil {
				ErrPrintf("Error decrypting stdin: %s\n", err.Error())
				os.Exit(1)
			}
		} else {
			err := pipeService.Encrypt()
			if err != nil {
				ErrPrintf("Error encrypting stdin: %s\n", err.Error())
				os.Exit(1)
			}
		}
	} else {
		for _, filename := range flag.Args() {
			if *forceDecrypt || strings.HasSuffix(filename, *extension) {
				err := fileService.DecryptFile(filename)
				if err != nil {
					ErrPrintf("Error decrypting file '%s': %s\n", filename, err.Error())
					if !*continueOnError {
						os.Exit(1)
					}
				}
			} else {
				err := fileService.EncryptFile(filename)
				if err != nil {
					ErrPrintf("Error encrypting file '%s': %s\n", filename, err.Error())
					if !*continueOnError {
						os.Exit(1)
					}
				}
			}
		}
	}
}

func printUsage() {
	FlagPrintf("Secrets is a tool for symmetric encryption and decryption of files.\n\n")
	FlagPrintf("Usage:\n  %s [file...]\n", filepath.Base(os.Args[0]))
	FlagPrintf("\n")
	FlagPrintf("Multiple files to be encrypted or decrypted can be given as arguments.\n")
	FlagPrintf("If no files are given, input is read from STDIN and will be encrypted\n")
	FlagPrintf("except `-d` is set.\n")
	FlagPrintf("\n")
	FlagPrintf("Files are encrypted by default except `-d` is set or the filename ends\n")
	FlagPrintf("with '.encrypted' or the extension configured via `-x <.extension>`.\n")
	FlagPrintf("\n")
	FlagPrintf("Password can be given via `-p <password>` or `-q <environment_variable>`.\n")
	FlagPrintf("If running in a terminal and neither `-p` nor `-q` is specified, password\n")
	FlagPrintf("is prompted from the user.\n")
	FlagPrintf("\n")
	FlagPrintf("Flags:\n")
	flag.PrintDefaults()
}

func FlagPrintf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(flag.CommandLine.Output(), format, a...)
}

func ErrPrintf(format string, a ...interface{}) {
	_, _ = fmt.Fprintf(os.Stderr, format, a...)
}
