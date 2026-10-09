package tunnel

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestCreatePairPersistsDistinctPeers(t *testing.T) {
	stateDir := t.TempDir()
	address, qr, err := CreatePair(stateDir, DefaultNetwork, "vpn.example.net:51820", "phone")
	if err != nil {
		t.Fatalf("CreatePair() error = %v", err)
	}
	if address != "10.203.0.2" || qr == "" {
		t.Fatalf("CreatePair() = (%q, QR length %d), want .2 and non-empty QR", address, len(qr))
	}
	secondAddress, _, err := CreatePair(stateDir, DefaultNetwork, "[2001:db8::1]:51820", "tablet")
	if err != nil {
		t.Fatalf("CreatePair() second peer error = %v", err)
	}
	if secondAddress != "10.203.0.3" {
		t.Fatalf("second peer address = %q, want 10.203.0.3", secondAddress)
	}

	data, err := os.ReadFile(filepath.Join(stateDir, "peers.json"))
	if err != nil {
		t.Fatalf("read peers state: %v", err)
	}
	var peers []Peer
	if err := json.Unmarshal(data, &peers); err != nil {
		t.Fatalf("decode peers state: %v", err)
	}
	if len(peers) != 2 || peers[0].PublicKey == "" || peers[1].PublicKey == "" {
		t.Fatalf("unexpected persisted peers: %#v", peers)
	}
}

func TestCreatePairRejectsDuplicateName(t *testing.T) {
	stateDir := t.TempDir()
	if _, _, err := CreatePair(stateDir, DefaultNetwork, "vpn.example.net:51820", "phone"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CreatePair(stateDir, DefaultNetwork, "vpn.example.net:51820", "phone"); err == nil {
		t.Fatal("expected duplicate peer name to be rejected")
	}
}

func TestRemovePeerUpdatesStateHash(t *testing.T) {
	stateDir := t.TempDir()
	if _, _, err := CreatePair(stateDir, DefaultNetwork, "vpn.example.net:51820", "phone"); err != nil {
		t.Fatal(err)
	}
	before, err := PeerStateHash(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := RemovePeer(stateDir, "phone"); err != nil {
		t.Fatalf("RemovePeer() error = %v", err)
	}
	after, err := PeerStateHash(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("peer state hash did not change after revocation")
	}
	if err := RemovePeer(stateDir, "phone"); err == nil {
		t.Fatal("expected removing an unknown peer to fail")
	}
}

func TestNextPeerAddressExhaustion(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/30")
	peers := []Peer{{ID: "device", Address: "10.0.0.2"}}
	if _, err := nextPeerAddress(prefix, peers); err == nil {
		t.Fatal("expected /30 network to be exhausted")
	}
}

func TestValidateEndpoint(t *testing.T) {
	for _, endpoint := range []string{"gateway.example:51820", "[2001:db8::1]:51820", "vpn-gateway.home:51820"} {
		if err := validateEndpoint(endpoint); err != nil {
			t.Errorf("validateEndpoint(%q) error = %v", endpoint, err)
		}
	}
	for _, endpoint := range []string{"gateway.example", "gateway.example:0", "gateway.example:65536", "https://gateway.example:51820", "evil\nAllowedIPs=0.0.0.0/0:51820", "bad_host:51820"} {
		if err := validateEndpoint(endpoint); err == nil {
			t.Errorf("validateEndpoint(%q) unexpectedly succeeded", endpoint)
		}
	}
}
