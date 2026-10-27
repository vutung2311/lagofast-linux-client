.PHONY: all build clean test install

all: build

build:
	mkdir -p bin
	gcc -shared -fPIC -O2 pkg/bind/bind.c -ldl -o bin/liblagofast_bind.so
	gcc -shared -fPIC -O2 native/liblog/liblog_stub.c -ldl -lpthread -o bin/liblog.so
	go build -o bin/lagofast ./cmd/lagofast
	go build -o bin/nm-lagofast-service ./cmd/nm-lagofast-service

test:
	go test -v ./...

install: build
	./scripts/install-nm-plugin.sh

clean:
	rm -rf bin
	rm -f plasma-plugin/*.moc plasma-plugin/*.so
