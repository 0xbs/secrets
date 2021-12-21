# Secrets

Secrets is a tool for symmetric encryption and decryption of files.

The encryption key is derived using HMAC-SHA-256 based PBKDF2, the used AES encryption algorithm depends on the number 
of key bytes.

```
Usage:
  secrets [file...]

Multiple files to be encrypted or decrypted can be given as arguments.
If no files are given, input is read from STDIN and will be encrypted
except `-d` is set.

Files are encrypted by default except `-d` is set or the filename ends
with '.encrypted' (can be configured via `-x <.extension>`).

Password can be given via `-p <password>` or `-q <environment_variable>`.
If running in a terminal and neither `-p` nor `-q` is specified, password
is prompted from the user.

Flags:
  -c	continue operation even if a file cannot be processed
  -d	force decryption regardless of file extension
  -i int
    	number of iterations for PBKDF2 key derivation (default 10000)
  -k int
    	number bytes used for encryption key, either 16, 24, or 32 bytes
    	to select AES-128, AES-192, or AES-256 (default 16)
  -p string
    	password for encryption and decryption
  -q string
    	read password from given environment variable
  -r	remove input files after encryption or decryption
  -s int
    	number bytes used for salt (default 8)
  -x string
    	extension for encrypted files (default ".encrypted")
```

## Build

To build, use standard Golang commands like `go build`.

The Makefile provides some convenience functions like `make all` to build the program for all operating systems. 
