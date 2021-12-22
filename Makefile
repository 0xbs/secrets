.PHONY: build all install clean

build:
	go build -v ./...

test:
	go test -v ./...

all:
	GOOS=darwin  GOARCH=amd64 go build -o build/secrets-macos
	GOOS=darwin  GOARCH=arm64 go build -o build/secrets-macos-arm
	GOOS=linux   GOARCH=amd64 go build -o build/secrets-linux
	GOOS=linux   GOARCH=arm64 go build -o build/secrets-linux-arm
	GOOS=windows GOARCH=amd64 go build -o build/secrets-win.exe

install: build
	cp -f build/secrets /usr/local/bin/

clean:
	rm -rf build
