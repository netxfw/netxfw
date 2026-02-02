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
	if [ ! -f /etc/netxfw/config.yaml ]; then sudo cp rules/default.yaml /etc/netxfw/config.yaml; fi
	sudo cp netxfw /usr/local/bin/
	sudo cp netxfw.service /etc/systemd/system/
	sudo systemctl daemon-reload
	@echo "✅ Installed netxfw to /usr/local/bin/"
	@echo "✅ Configuration file: /etc/netxfw/config.yaml"
	@echo "✅ Systemd service: netxfw.service installed"
	@echo "   Usage: sudo systemctl start netxfw"
