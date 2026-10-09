package discovery

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Service struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	URL         string `json:"url,omitempty"`
	Source      string `json:"source"`
	GatewayPort int    `json:"gateway_port,omitempty"`
	GatewayAddr string `json:"gateway_address,omitempty"`
}

var mdnsServiceTypes = []string{
	"_http._tcp",
	"_https._tcp",
	"_ssh._tcp",
	"_postgresql._tcp",
	"_smb._tcp",
	"_home-assistant._tcp",
	"_hap._tcp",
	"_ipp._tcp",
	"_printer._tcp",
	"_mqtt._tcp",
}

func Scan(timeout time.Duration) ([]Service, error) {
	if timeout <= 0 {
		return nil, fmt.Errorf("timeout must be positive")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	type result struct {
		services []Service
		err      error
	}
	results := make(chan result, 2)
	go func() {
		services, err := scanMDNS(ctx)
		results <- result{services: services, err: err}
	}()
	go func() {
		services, err := scanSSDP(ctx)
		results <- result{services: services, err: err}
	}()

	var services []Service
	var scanErrors []error
	for range 2 {
		result := <-results
		services = append(services, result.services...)
		if result.err != nil {
			scanErrors = append(scanErrors, result.err)
		}
	}
	services = uniqueServices(services)
	if len(services) == 0 && len(scanErrors) > 0 {
		return nil, fmt.Errorf("service discovery failed: %w", errors.Join(scanErrors...))
	}
	return services, nil
}

func scanMDNS(ctx context.Context) ([]Service, error) {
	group := &net.UDPAddr{IP: net.ParseIP("224.0.0.251"), Port: 5353}
	conn, err := net.ListenMulticastUDP("udp4", nil, group)
	if err != nil {
		return nil, fmt.Errorf("open mDNS multicast socket: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set mDNS deadline: %w", err)
		}
	}

	query := new(dns.Msg)
	query.MsgHdr.Id = 0
	for _, serviceType := range mdnsServiceTypes {
		query.Question = append(query.Question, dns.Question{
			Name:   dns.Fqdn(serviceType + ".local"),
			Qtype:  dns.TypePTR,
			Qclass: dns.ClassINET,
		})
	}
	packet, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("encode mDNS query: %w", err)
	}
	if _, err := conn.WriteToUDP(packet, group); err != nil {
		return nil, fmt.Errorf("send mDNS query: %w", err)
	}

	collector := newMDNSCollector()
	buffer := make([]byte, 9000)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() && ctx.Err() != nil {
				return collector.services(), nil
			}
			return nil, fmt.Errorf("receive mDNS response: %w", err)
		}
		response := new(dns.Msg)
		if err := response.Unpack(buffer[:n]); err != nil {
			continue
		}
		if response.Response {
			collector.add(response)
		}
	}
}

type mdnsCollector struct {
	ptrs map[string]map[string]string
	srvs map[string]dns.SRV
	ips  map[string][]net.IP
}

func newMDNSCollector() *mdnsCollector {
	return &mdnsCollector{
		ptrs: make(map[string]map[string]string),
		srvs: make(map[string]dns.SRV),
		ips:  make(map[string][]net.IP),
	}
}

func (c *mdnsCollector) add(message *dns.Msg) {
	records := append(append(append([]dns.RR(nil), message.Answer...), message.Ns...), message.Extra...)
	for _, record := range records {
		switch rr := record.(type) {
		case *dns.PTR:
			serviceType := strings.ToLower(strings.TrimSuffix(rr.Hdr.Name, ".local."))
			if !isKnownMDNSService(serviceType) {
				continue
			}
			instance := canonicalDNSName(rr.Ptr)
			if c.ptrs[serviceType] == nil {
				c.ptrs[serviceType] = make(map[string]string)
			}
			c.ptrs[serviceType][instance] = strings.TrimSuffix(rr.Ptr, ".")
		case *dns.SRV:
			c.srvs[canonicalDNSName(rr.Hdr.Name)] = *rr
		case *dns.A:
			key := canonicalDNSName(rr.Hdr.Name)
			c.ips[key] = append(c.ips[key], append(net.IP(nil), rr.A...))
		case *dns.AAAA:
			key := canonicalDNSName(rr.Hdr.Name)
			c.ips[key] = append(c.ips[key], append(net.IP(nil), rr.AAAA...))
		}
	}
}

func (c *mdnsCollector) services() []Service {
	var services []Service
	for serviceType, instances := range c.ptrs {
		for instance, name := range instances {
			srv, ok := c.srvs[instance]
			if !ok || srv.Port < 1 || srv.Port > 65535 {
				continue
			}
			for _, ip := range c.ips[canonicalDNSName(srv.Target)] {
				address := ip.String()
				services = append(services, Service{
					Name:    name,
					Type:    serviceType,
					Address: address,
					Port:    int(srv.Port),
					URL:     serviceURL(serviceType, address, int(srv.Port)),
					Source:  "mdns",
				})
			}
		}
	}
	return services
}

func isKnownMDNSService(serviceType string) bool {
	for _, known := range mdnsServiceTypes {
		if serviceType == known {
			return true
		}
	}
	return false
}

func canonicalDNSName(name string) string {
	return strings.ToLower(dns.Fqdn(name))
}

func scanSSDP(ctx context.Context) ([]Service, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, fmt.Errorf("open SSDP socket: %w", err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set SSDP deadline: %w", err)
		}
	}
	search := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: 239.255.255.250:1900",
		"MAN: \"ssdp:discover\"",
		"MX: 2",
		"ST: ssdp:all",
		"",
		"",
	}, "\r\n")
	destination := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}
	if _, err := conn.WriteToUDP([]byte(search), destination); err != nil {
		return nil, fmt.Errorf("send SSDP search: %w", err)
	}

	var services []Service
	buffer := make([]byte, 8192)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if timeoutErr, ok := err.(net.Error); ok && timeoutErr.Timeout() {
				if ctx.Err() != nil {
					return services, nil
				}
				return services, nil
			}
			return services, fmt.Errorf("receive SSDP response: %w", err)
		}
		service, ok := parseSSDPResponse(string(buffer[:n]), remote.IP.String())
		if ok {
			services = append(services, service)
		}
	}
}

func parseSSDPResponse(response, address string) (Service, bool) {
	if !strings.HasPrefix(response, "HTTP/1.1 200 ") && !strings.HasPrefix(response, "HTTP/1.0 200 ") {
		return Service{}, false
	}
	headers := make(map[string]string)
	lines := strings.Split(response, "\r\n")
	for _, line := range lines[1:] {
		name, value, found := strings.Cut(line, ":")
		if found {
			headers[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
	}

	location := headers["location"]
	port := 0
	if parsed, err := url.Parse(location); err == nil && parsed.Port() != "" {
		port, _ = strconv.Atoi(parsed.Port())
	}
	if port == 0 {
		port = 80
	}
	name := headers["server"]
	if name == "" {
		name = headers["st"]
	}
	if name == "" {
		name = headers["usn"]
	}
	if name == "" {
		name = "SSDP device"
	}
	serviceType := headers["st"]
	if serviceType == "" {
		serviceType = headers["nt"]
	}
	service := Service{
		Name:    name,
		Type:    serviceType,
		Address: address,
		Port:    port,
		Source:  "ssdp",
	}
	if location != "" {
		service.URL = location
	} else if serviceType == "upnp:rootdevice" || strings.Contains(serviceType, "http") {
		service.URL = fmt.Sprintf("http://%s:%d", address, port)
	}
	return service, true
}

func serviceURL(serviceType, address string, port int) string {
	scheme := "tcp"
	if strings.HasPrefix(serviceType, "_https") {
		scheme = "https"
	} else if strings.HasPrefix(serviceType, "_http") {
		scheme = "http"
	} else {
		return ""
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(address, strconv.Itoa(port)))
}

func uniqueServices(services []Service) []Service {
	seen := make(map[string]struct{}, len(services))
	unique := make([]Service, 0, len(services))
	for _, service := range services {
		serviceType := strings.ToLower(service.Type)
		if service.Source == "ssdp" {
			serviceType = ""
		}
		key := strings.ToLower(net.JoinHostPort(service.Address, strconv.Itoa(service.Port)) + "\x00" + serviceType)
		if _, found := seen[key]; found {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, service)
	}
	return unique
}

type Catalog struct {
	mu       sync.RWMutex
	services []Service
}

func NewCatalog() *Catalog {
	return &Catalog{}
}

func (c *Catalog) Refresh(timeout time.Duration) error {
	services, err := Scan(timeout)
	if err != nil {
		return err
	}
	c.SetServices(services)
	return nil
}

func (c *Catalog) SetServices(services []Service) {
	c.mu.Lock()
	c.services = append([]Service(nil), services...)
	c.mu.Unlock()
}

func (c *Catalog) RefreshPeriodically(ctx context.Context, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Refresh(timeout); err != nil {
				log.Printf("refresh service catalog: %v", err)
			}
		}
	}
}

func (c *Catalog) Services() []Service {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]Service(nil), c.services...)
}
