package proxy

import (
	"net"
	"testing"

	"lan-gateway/internal/discovery"
)

func TestManagerExposesPrivateServicesOnly(t *testing.T) {
	manager, err := NewManager(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()

	services := []discovery.Service{
		{Address: "192.168.1.15", Port: 5432, Type: "_postgresql._tcp", Source: "mdns"},
		{Address: "203.0.113.8", Port: 8080, Type: "_http._tcp", Source: "mdns"},
		{Address: "127.0.0.1", Port: 22, Type: "_ssh._tcp", Source: "mdns"},
	}
	got, err := manager.Sync(services)
	if err != nil {
		t.Fatalf("Sync() error = %v", err)
	}
	if got[0].GatewayPort == 0 {
		t.Fatal("expected private LAN service to receive a proxy port")
	}
	if got[0].GatewayAddr == "" {
		t.Fatal("expected private LAN service to receive a tunnel address")
	}
	if got[1].GatewayPort != 0 || got[2].GatewayPort != 0 {
		t.Fatal("expected public and loopback targets not to be exposed")
	}
}

func TestManagerReusesProxyPort(t *testing.T) {
	manager, err := NewManager(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	service := discovery.Service{Address: "192.168.1.15", Port: 5432, Type: "_postgresql._tcp", Source: "mdns"}

	first, err := manager.Sync([]discovery.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.Sync([]discovery.Service{service})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].GatewayPort != second[0].GatewayPort {
		t.Fatalf("proxy port changed from %d to %d", first[0].GatewayPort, second[0].GatewayPort)
	}
}
