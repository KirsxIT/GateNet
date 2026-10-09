package proxy

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"lan-gateway/internal/discovery"
)

type Manager struct {
	bindIP  net.IP
	mu      sync.Mutex
	forward map[string]*forwarder
}

type forwarder struct {
	listener net.Listener
	target   string
	port     int
	slots    chan struct{}
}

func NewManager(bindIP net.IP) (*Manager, error) {
	if bindIP == nil || bindIP.To4() == nil {
		return nil, errors.New("proxy bind address must be an IPv4 address")
	}
	return &Manager{bindIP: bindIP.To4(), forward: make(map[string]*forwarder)}, nil
}

func (m *Manager) Sync(services []discovery.Service) ([]discovery.Service, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	result := append([]discovery.Service(nil), services...)
	wanted := make(map[string]struct{}, len(services))
	var created []string
	for index := range result {
		service := &result[index]
		service.GatewayPort = 0
		service.GatewayAddr = ""
		if !isLANAddress(service.Address) || service.Port < 1 || service.Port > 65535 {
			continue
		}
		key := serviceKey(*service)
		wanted[key] = struct{}{}
		forward := m.forward[key]
		if forward == nil {
			var err error
			forward, err = m.start(service.Address, service.Port)
			if err != nil {
				for _, key := range created {
					_ = m.forward[key].listener.Close()
					delete(m.forward, key)
				}
				return nil, fmt.Errorf("expose discovered service %s:%d: %w", service.Address, service.Port, err)
			}
			m.forward[key] = forward
			created = append(created, key)
		}
		service.GatewayPort = forward.port
		service.GatewayAddr = net.JoinHostPort(m.bindIP.String(), strconv.Itoa(forward.port))
	}
	for key, forward := range m.forward {
		if _, found := wanted[key]; !found {
			if err := forward.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Printf("close stale service proxy: %v", err)
			}
			delete(m.forward, key)
		}
	}
	return result, nil
}

func (m *Manager) start(address string, port int) (*forwarder, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(m.bindIP.String(), "0"))
	if err != nil {
		return nil, err
	}
	forward := &forwarder{
		listener: listener,
		target:   net.JoinHostPort(address, strconv.Itoa(port)),
		port:     listener.Addr().(*net.TCPAddr).Port,
		slots:    make(chan struct{}, 64),
	}
	go forward.serve()
	return forward, nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var closeErrors []error
	for key, forward := range m.forward {
		if err := forward.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErrors = append(closeErrors, err)
		}
		delete(m.forward, key)
	}
	return errors.Join(closeErrors...)
}

func (f *forwarder) serve() {
	for {
		client, err := f.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("accept service proxy connection: %v", err)
			}
			return
		}
		select {
		case f.slots <- struct{}{}:
			go func() {
				defer func() { <-f.slots }()
				f.proxy(client)
			}()
		default:
			_ = client.Close()
		}
	}
}

func (f *forwarder) proxy(client net.Conn) {
	defer client.Close()
	upstream, err := net.DialTimeout("tcp", f.target, 5*time.Second)
	if err != nil {
		log.Printf("connect service proxy target %s: %v", f.target, err)
		return
	}
	defer upstream.Close()

	done := make(chan struct{})
	go func() {
		_, err := io.Copy(upstream, client)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("copy client data to %s: %v", f.target, err)
		}
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, err = io.Copy(client, upstream)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Printf("copy service response from %s: %v", f.target, err)
	}
	if tcp, ok := client.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
	<-done
}

func isLANAddress(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.IsPrivate()
}

func serviceKey(service discovery.Service) string {
	return strings.Join([]string{service.Source, service.Type, service.Address, strconv.Itoa(service.Port)}, "\x00")
}
