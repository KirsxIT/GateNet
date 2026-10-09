package tunnel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const DefaultNetwork = "10.203.0.0/24"

type Peer struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
}

func CreatePair(stateDir, network, endpoint, id string) (string, string, error) {
	prefix, err := parseNetwork(network)
	if err != nil {
		return "", "", err
	}
	if err := validateEndpoint(endpoint); err != nil {
		return "", "", err
	}
	if !validID(id) {
		return "", "", errors.New("peer name must contain only letters, digits, hyphens, or underscores")
	}
	identity, err := loadOrCreateIdentity(stateDir)
	if err != nil {
		return "", "", err
	}
	peers, err := loadPeers(stateDir)
	if err != nil {
		return "", "", err
	}
	for _, peer := range peers {
		if peer.ID == id {
			return "", "", fmt.Errorf("peer %q already exists", id)
		}
	}
	address, err := nextPeerAddress(prefix, peers)
	if err != nil {
		return "", "", err
	}
	clientKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate peer key: %w", err)
	}
	peer := Peer{ID: id, Address: address.String(), PublicKey: clientKey.PublicKey().String()}
	peers = append(peers, peer)
	if err := savePeers(stateDir, peers); err != nil {
		return "", "", err
	}

	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s/32\nPersistentKeepalive = 25\n",
		clientKey.String(), address, identity.PublicKey().String(), endpoint, prefix.Addr().Next())
	qr, err := qrcode.New(config, qrcode.Medium)
	if err != nil {
		return "", "", fmt.Errorf("generate peer QR code: %w", err)
	}
	return address.String(), qr.ToSmallString(false), nil
}

func RemovePeer(stateDir, id string) error {
	if !validID(id) {
		return errors.New("peer name must contain only letters, digits, hyphens, or underscores")
	}
	peers, err := loadPeers(stateDir)
	if err != nil {
		return err
	}
	for index, peer := range peers {
		if peer.ID == id {
			peers = append(peers[:index], peers[index+1:]...)
			return savePeers(stateDir, peers)
		}
	}
	return fmt.Errorf("peer %q does not exist", id)
}

func PeerStateHash(stateDir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(stateDir, "peers.json"))
	if errors.Is(err, os.ErrNotExist) {
		data = nil
	} else if err != nil {
		return "", fmt.Errorf("read peer state: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func loadOrCreateIdentity(stateDir string) (wgtypes.Key, error) {
	if err := ensureStateDir(stateDir); err != nil {
		return wgtypes.Key{}, err
	}
	path := filepath.Join(stateDir, "gateway.key")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return wgtypes.Key{}, errors.New("gateway private key must be a regular file")
		}
		if chmodErr := os.Chmod(path, 0600); chmodErr != nil {
			return wgtypes.Key{}, fmt.Errorf("secure gateway private key: %w", chmodErr)
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return wgtypes.Key{}, fmt.Errorf("read gateway private key: %w", readErr)
		}
		key, parseErr := wgtypes.ParseKey(strings.TrimSpace(string(data)))
		if parseErr != nil {
			return wgtypes.Key{}, fmt.Errorf("parse gateway private key: %w", parseErr)
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, fmt.Errorf("read gateway private key: %w", err)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("generate gateway private key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("create gateway private key: %w", err)
	}
	_, writeErr := file.WriteString(key.String() + "\n")
	closeErr := file.Close()
	if writeErr != nil {
		return wgtypes.Key{}, fmt.Errorf("write gateway private key: %w", writeErr)
	}
	if closeErr != nil {
		return wgtypes.Key{}, fmt.Errorf("close gateway private key: %w", closeErr)
	}
	return key, nil
}

func loadPeers(stateDir string) ([]Peer, error) {
	path := filepath.Join(stateDir, "peers.json")
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read peer state: %w", err)
	}
	var peers []Peer
	if err := json.Unmarshal(data, &peers); err != nil {
		return nil, fmt.Errorf("parse peer state: %w", err)
	}
	return peers, nil
}

func savePeers(stateDir string, peers []Peer) error {
	if err := ensureStateDir(stateDir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(peers, "", "  ")
	if err != nil {
		return fmt.Errorf("encode peer state: %w", err)
	}
	path := filepath.Join(stateDir, "peers.json")
	temp, err := os.CreateTemp(stateDir, "peers-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary peer state: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0600); err != nil {
		temp.Close()
		return fmt.Errorf("secure temporary peer state: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return fmt.Errorf("write peer state: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close peer state: %w", err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("replace peer state: %w", err)
	}
	return nil
}

func ensureStateDir(stateDir string) error {
	if stateDir == "" {
		return errors.New("state directory cannot be empty")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(stateDir, 0700); err != nil {
		return fmt.Errorf("secure state directory: %w", err)
	}
	return nil
}

func parseNetwork(network string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(network)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < 16 || prefix.Bits() > 30 {
		return netip.Prefix{}, errors.New("network must be an IPv4 CIDR between /16 and /30")
	}
	return prefix.Masked(), nil
}

func nextPeerAddress(prefix netip.Prefix, peers []Peer) (netip.Addr, error) {
	used := make(map[netip.Addr]struct{}, len(peers)+1)
	gateway := prefix.Addr().Next()
	used[gateway] = struct{}{}
	for _, peer := range peers {
		address, err := netip.ParseAddr(peer.Address)
		if err != nil || !usablePeerAddress(prefix, address) {
			return netip.Addr{}, fmt.Errorf("peer %q has invalid address state", peer.ID)
		}
		used[address] = struct{}{}
	}
	base := prefix.Addr().As4()
	baseValue := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	count := uint32(1) << (32 - prefix.Bits())
	for offset := uint32(2); offset < count-1; offset++ {
		value := baseValue + offset
		candidate := netip.AddrFrom4([4]byte{
			byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value),
		})
		if _, found := used[candidate]; !found {
			return candidate, nil
		}
	}
	return netip.Addr{}, errors.New("no peer addresses remain in the WireGuard network")
}

func usablePeerAddress(prefix netip.Prefix, address netip.Addr) bool {
	if !prefix.Contains(address) || address == prefix.Addr().Next() {
		return false
	}
	base := prefix.Addr().As4()
	baseValue := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	addressBytes := address.As4()
	addressValue := uint32(addressBytes[0])<<24 | uint32(addressBytes[1])<<16 | uint32(addressBytes[2])<<8 | uint32(addressBytes[3])
	offset := addressValue - baseValue
	count := uint32(1) << (32 - prefix.Bits())
	return offset >= 2 && offset < count-1
}

func validateEndpoint(endpoint string) error {
	host, portText, err := net.SplitHostPort(endpoint)
	if err != nil || strings.TrimSpace(host) != host || host == "" {
		return errors.New("endpoint must be a host:port or [IPv6]:port")
	}
	if net.ParseIP(host) == nil && !validHostname(host) {
		return errors.New("endpoint host must be an IP address or DNS hostname")
	}
	for _, digit := range portText {
		if digit < '0' || digit > '9' {
			return errors.New("endpoint port must be numeric")
		}
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("endpoint port must be between 1 and 65535")
	}
	return nil
}

func validHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return true
}

func validID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
