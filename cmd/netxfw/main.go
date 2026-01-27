package main

import (
	"github.com/livp123/netxfw/internal/xdp"
	"log"
)

func main() {
	run()
}

func run() {
	// ...
	interfaces, err := xdp.GetPhysicalInterfaces()
	if err != nil {
		log.Fatalf("Get interfaces: %v", err)
	}

	manager, err := xdp.NewManager()
	if err != nil {
		log.Fatalf("Create XDP manager: %v", err)
	}
	defer manager.Close()

	if err := manager.Attach(interfaces); err != nil {
		log.Fatalf("Attach XDP: %v", err)
	}

	// 阻塞运行，等待信号
	select {}
}
