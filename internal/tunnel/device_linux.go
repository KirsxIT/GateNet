//go:build linux

package tunnel

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Start(interfaceName, stateDir, network string, listenPort int) (net.IP, func() error, error) {
	if !validInterfaceName(interfaceName) {
		return nil, nil, errors.New("interface name must be 1-15 letters, digits, hyphens, or underscores")
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, nil, errors.New("listen port must be between 1 and 65535")
	}
	prefix, err := parseNetwork(network)
	if err != nil {
		return nil, nil, err
	}
	privateKey, err := loadOrCreateIdentity(stateDir)
	if err != nil {
		return nil, nil, err
	}
	peers, err := loadPeers(stateDir)
	if err != nil {
		return nil, nil, err
	}
	configuredPeers, err := peerConfigurations(prefix, peers)
	if err != nil {
		return nil, nil, err
	}

	link, err := netlink.LinkByName(interfaceName)
	created := false
	if err != nil {
		if !isLinkNotFound(err) {
			return nil, nil, fmt.Errorf("find WireGuard interface: %w", err)
		}
		link = &netlink.GenericLink{
			LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
			LinkType:  "wireguard",
		}
		if err := netlink.LinkAdd(link); err != nil {
			return nil, nil, fmt.Errorf("create WireGuard interface %q: %w", interfaceName, err)
		}
		created = true
		link, err = netlink.LinkByName(interfaceName)
		if err != nil {
			if cleanupErr := netlink.LinkDel(&netlink.GenericLink{
				LinkAttrs: netlink.LinkAttrs{Name: interfaceName},
				LinkType:  "wireguard",
			}); cleanupErr != nil {
				log.Printf("remove incomplete WireGuard interface: %v", cleanupErr)
			}
			return nil, nil, fmt.Errorf("find created WireGuard interface: %w", err)
		}
	}
	if link.Type() != "wireguard" {
		return nil, nil, fmt.Errorf("interface %q exists but is type %q, not wireguard", interfaceName, link.Type())
	}
	if !created {
		client, err := wgctrl.New()
		if err != nil {
			return nil, nil, fmt.Errorf("connect to WireGuard control API: %w", err)
		}
		device, deviceErr := client.Device(interfaceName)
		closeErr := client.Close()
		if deviceErr != nil {
			return nil, nil, fmt.Errorf("inspect WireGuard interface %q: %w", interfaceName, deviceErr)
		}
		if closeErr != nil {
			return nil, nil, fmt.Errorf("close WireGuard control API: %w", closeErr)
		}
		if device.PublicKey != privateKey.PublicKey() {
			return nil, nil, fmt.Errorf("refusing to take over WireGuard interface %q with a different identity", interfaceName)
		}
	}
	cleanupOnError := func() {
		if created {
			if cleanupErr := netlink.LinkDel(link); cleanupErr != nil {
				log.Printf("remove incomplete WireGuard interface: %v", cleanupErr)
			}
		}
	}

	address, err := netlink.ParseAddr(netip.PrefixFrom(prefix.Addr().Next(), prefix.Bits()).String())
	if err != nil {
		cleanupOnError()
		return nil, nil, fmt.Errorf("parse interface address: %w", err)
	}
	if err := netlink.AddrReplace(link, address); err != nil {
		cleanupOnError()
		return nil, nil, fmt.Errorf("assign WireGuard interface address: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		cleanupOnError()
		return nil, nil, fmt.Errorf("bring WireGuard interface up: %w", err)
	}

	client, err := wgctrl.New()
	if err != nil {
		cleanupOnError()
		return nil, nil, fmt.Errorf("connect to WireGuard control API: %w", err)
	}
	port := listenPort
	if err := client.ConfigureDevice(interfaceName, wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &port,
		ReplacePeers: true,
		Peers:        configuredPeers,
	}); err != nil {
		client.Close()
		cleanupOnError()
		return nil, nil, fmt.Errorf("configure WireGuard interface: %w", err)
	}
	if err := client.Close(); err != nil {
		cleanupOnError()
		return nil, nil, fmt.Errorf("close WireGuard control API: %w", err)
	}

	gatewayIP := net.ParseIP(prefix.Addr().Next().String())
	cleanup := func() error {
		return netlink.LinkDel(link)
	}
	return gatewayIP, cleanup, nil
}

func isLinkNotFound(err error) bool {
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

func Reload(interfaceName, stateDir, network string) error {
	prefix, err := parseNetwork(network)
	if err != nil {
		return err
	}
	peers, err := loadPeers(stateDir)
	if err != nil {
		return err
	}
	configured, err := peerConfigurations(prefix, peers)
	if err != nil {
		return err
	}
	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("connect to WireGuard control API: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Printf("close WireGuard control API: %v", err)
		}
	}()
	device, err := client.Device(interfaceName)
	if err != nil {
		return fmt.Errorf("read WireGuard interface %q: %w", interfaceName, err)
	}

	current := make(map[wgtypes.Key]wgtypes.Peer, len(device.Peers))
	for _, peer := range device.Peers {
		current[peer.PublicKey] = peer
	}
	desiredKeys := make(map[wgtypes.Key]struct{}, len(configured))
	updates := make([]wgtypes.PeerConfig, 0, len(configured)+len(current))
	for _, peer := range configured {
		desiredKeys[peer.PublicKey] = struct{}{}
		currentPeer, exists := current[peer.PublicKey]
		if exists && sameAllowedIPs(currentPeer.AllowedIPs, peer.AllowedIPs) {
			continue
		}
		updates = append(updates, peer)
	}
	for publicKey := range current {
		if _, exists := desiredKeys[publicKey]; !exists {
			updates = append(updates, wgtypes.PeerConfig{PublicKey: publicKey, Remove: true})
		}
	}
	if len(updates) == 0 {
		return nil
	}
	if err := client.ConfigureDevice(interfaceName, wgtypes.Config{Peers: updates}); err != nil {
		return fmt.Errorf("apply peer changes to WireGuard interface: %w", err)
	}
	return nil
}

func peerConfigurations(prefix netip.Prefix, peers []Peer) ([]wgtypes.PeerConfig, error) {
	configured := make([]wgtypes.PeerConfig, 0, len(peers))
	seenIDs := make(map[string]struct{}, len(peers))
	seenKeys := make(map[wgtypes.Key]struct{}, len(peers))
	seenAddresses := make(map[netip.Addr]struct{}, len(peers))
	for _, peer := range peers {
		if !validID(peer.ID) {
			return nil, fmt.Errorf("invalid peer id %q in state", peer.ID)
		}
		if _, exists := seenIDs[peer.ID]; exists {
			return nil, fmt.Errorf("duplicate peer id %q in state", peer.ID)
		}
		seenIDs[peer.ID] = struct{}{}
		address, err := netip.ParseAddr(peer.Address)
		if err != nil || !usablePeerAddress(prefix, address) {
			return nil, fmt.Errorf("invalid tunnel address for peer %q", peer.ID)
		}
		if _, exists := seenAddresses[address]; exists {
			return nil, fmt.Errorf("duplicate tunnel address %q in state", address)
		}
		seenAddresses[address] = struct{}{}
		publicKey, err := wgtypes.ParseKey(peer.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("parse public key for peer %q: %w", peer.ID, err)
		}
		if _, exists := seenKeys[publicKey]; exists {
			return nil, fmt.Errorf("duplicate public key for peer %q", peer.ID)
		}
		seenKeys[publicKey] = struct{}{}
		_, allowedIP, err := net.ParseCIDR(address.String() + "/32")
		if err != nil {
			return nil, fmt.Errorf("build allowed IP for peer %q: %w", peer.ID, err)
		}
		configured = append(configured, wgtypes.PeerConfig{
			PublicKey:         publicKey,
			ReplaceAllowedIPs: true,
			AllowedIPs:        []net.IPNet{*allowedIP},
		})
	}
	return configured, nil
}

func sameAllowedIPs(current, desired []net.IPNet) bool {
	if len(current) != len(desired) {
		return false
	}
	for index := range current {
		if current[index].String() != desired[index].String() {
			return false
		}
	}
	return true
}

func validInterfaceName(name string) bool {
	if len(name) == 0 || len(name) > 15 {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
