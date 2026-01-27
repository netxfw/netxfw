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

install: build
	sudo mkdir -p /etc/netxfw
	sudo cp rules/default.yaml /etc/netxfw/config.yaml
	sudo cp netxfw /usr/local/bin/
	@echo "✅ Installed netxfw to /usr/local/bin/"
	@echo "✅ Configuration file created at /etc/netxfw/config.yaml"
