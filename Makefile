.PHONY: build generate clean

build:
    go build -o netxfw ./cmd/netxfw

generate:
    cd internal/xdp && go generate

clean:
    rm -f netxfw
    rm -f internal/xdp/*_bpf*.go

run: build
    sudo ./netxfw