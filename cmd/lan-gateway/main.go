package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"lan-gateway/internal/discovery"
	"lan-gateway/internal/proxy"
	"lan-gateway/internal/tunnel"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "discover":
		err = runDiscover(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "pair":
		err = runPair(os.Args[2:])
	case "revoke":
		err = runRevoke(os.Args[2:])
	case "gateway":
		err = runGateway(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		log.Printf("error: %v", err)
		os.Exit(1)
	}
}

func runPair(args []string) error {
	flags := flag.NewFlagSet("pair", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/lan-gateway", "directory for gateway identity and peer state")
	network := flags.String("network", tunnel.DefaultNetwork, "WireGuard IPv4 network")
	endpoint := flags.String("endpoint", "", "directly reachable gateway host:port")
	peerName := flags.String("name", "", "unique peer name")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *endpoint == "" || *peerName == "" {
		return errors.New("pair requires --endpoint and --name")
	}
	address, qr, err := tunnel.CreatePair(*stateDir, *network, *endpoint, *peerName)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Peer %q assigned tunnel address %s\n", *peerName, address)
	fmt.Fprintln(os.Stdout, qr)
	return nil
}

func runRevoke(args []string) error {
	flags := flag.NewFlagSet("revoke", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/lan-gateway", "directory for gateway identity and peer state")
	peerName := flags.String("name", "", "peer name to revoke")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *peerName == "" {
		return errors.New("revoke requires --name")
	}
	if err := tunnel.RemovePeer(*stateDir, *peerName); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Revoked peer %q\n", *peerName)
	return nil
}

func runGateway(args []string) error {
	flags := flag.NewFlagSet("gateway", flag.ContinueOnError)
	stateDir := flags.String("state-dir", "/var/lib/lan-gateway", "directory for gateway identity and peer state")
	network := flags.String("network", tunnel.DefaultNetwork, "WireGuard IPv4 network")
	interfaceName := flags.String("interface", "wg-lan", "WireGuard interface name")
	listenPort := flags.Int("listen-port", 51820, "WireGuard UDP listen port")
	catalogPort := flags.Int("catalog-port", 8787, "service catalog TCP port on the tunnel")
	refresh := flags.Duration("refresh", 30*time.Second, "service discovery refresh interval")
	timeout := flags.Duration("timeout", 3*time.Second, "maximum time per discovery scan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *catalogPort < 1 || *catalogPort > 65535 || *refresh <= 0 || *timeout <= 0 {
		return errors.New("catalog port must be valid and refresh/timeout must be positive")
	}
	peerStateHash, err := tunnel.PeerStateHash(*stateDir)
	if err != nil {
		return err
	}
	gatewayIP, cleanupTunnel, err := tunnel.Start(*interfaceName, *stateDir, *network, *listenPort)
	if err != nil {
		return err
	}
	defer func() {
		if err := cleanupTunnel(); err != nil {
			log.Printf("remove WireGuard interface: %v", err)
		}
	}()

	proxies, err := proxy.NewManager(gatewayIP)
	if err != nil {
		return err
	}
	defer func() {
		if err := proxies.Close(); err != nil {
			log.Printf("close service proxies: %v", err)
		}
	}()

	catalog := discovery.NewCatalog()
	refreshCatalog := func() error {
		services, err := discovery.Scan(*timeout)
		if err != nil {
			return err
		}
		exposed, err := proxies.Sync(services)
		if err != nil {
			return err
		}
		catalog.SetServices(exposed)
		return nil
	}
	if err := refreshCatalog(); err != nil {
		return fmt.Errorf("initial service discovery: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		ticker := time.NewTicker(*refresh)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := refreshCatalog(); err != nil {
					log.Printf("refresh service catalog: %v", err)
				}
			}
		}
	}()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currentHash, err := tunnel.PeerStateHash(*stateDir)
				if err != nil {
					log.Printf("read peer state: %v", err)
					continue
				}
				if currentHash == peerStateHash {
					continue
				}
				if err := tunnel.Reload(*interfaceName, *stateDir, *network); err != nil {
					log.Printf("reload WireGuard peers: %v", err)
					continue
				}
				peerStateHash = currentHash
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /services", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(catalog.Services()); err != nil {
			log.Printf("encode service catalog: %v", err)
		}
	})
	server := &http.Server{
		Addr:              net.JoinHostPort(gatewayIP.String(), fmt.Sprint(*catalogPort)),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("gateway HTTP shutdown: %v", err)
		}
	}()

	log.Printf("WireGuard interface %s active at %s:%d", *interfaceName, gatewayIP, *listenPort)
	log.Printf("service catalog available to tunnel peers at http://%s/services", server.Addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func runDiscover(args []string) error {
	flags := flag.NewFlagSet("discover", flag.ContinueOnError)
	timeout := flags.Duration("timeout", 3*time.Second, "maximum discovery time")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}

	services, err := discovery.Scan(*timeout)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(services)
}

func runServe(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", "127.0.0.1:8787", "HTTP listen address")
	refresh := flags.Duration("refresh", 30*time.Second, "catalog refresh interval")
	timeout := flags.Duration("timeout", 3*time.Second, "maximum time per discovery scan")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *refresh <= 0 || *timeout <= 0 {
		return errors.New("refresh and timeout must be positive")
	}

	catalog := discovery.NewCatalog()
	if err := catalog.Refresh(*timeout); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go catalog.RefreshPeriodically(ctx, *refresh, *timeout)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /services", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(catalog.Services()); err != nil {
			log.Printf("encode service catalog: %v", err)
		}
	})
	server := &http.Server{
		Addr:              *listenAddress,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown: %v", err)
		}
	}()

	log.Printf("service catalog listening at http://%s/services", *listenAddress)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: lan-gateway <discover|serve|gateway|pair|revoke> [options]")
}
