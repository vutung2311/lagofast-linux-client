.PHONY: all build clean test install

all: build

build:
	mkdir -p bin
	go build -o bin/lagofast ./cmd/lagofast
	go build -o bin/nm-lagofast-service ./cmd/nm-lagofast-service

test:
	go test -v ./...

install: build
	./scripts/install-nm-plugin.sh

clean:
	rm -rf bin
	rm -f plasma-plugin/*.moc plasma-plugin/*.so
