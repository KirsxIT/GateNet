package discovery

import (
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func TestMDNSCollectorResolvesAdvertisedService(t *testing.T) {
	message := new(dns.Msg)
	message.Answer = []dns.RR{
		&dns.PTR{
			Hdr: dns.RR_Header{Name: "_http._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET},
			Ptr: "Home Assistant._http._tcp.local.",
		},
		&dns.SRV{
			Hdr:      dns.RR_Header{Name: "Home Assistant._http._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET},
			Port:     8123,
			Target:   "home.local.",
			Priority: 0,
			Weight:   0,
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "home.local.", Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.ParseIP("192.168.1.20").To4(),
		},
	}

	collector := newMDNSCollector()
	collector.add(message)
	services := collector.services()
	if len(services) != 1 {
		t.Fatalf("collector returned %d services, want 1", len(services))
	}
	want := Service{
		Name:    "Home Assistant._http._tcp.local",
		Type:    "_http._tcp",
		Address: "192.168.1.20",
		Port:    8123,
		URL:     "http://192.168.1.20:8123",
		Source:  "mdns",
	}
	if !reflect.DeepEqual(services[0], want) {
		t.Fatalf("collector returned %#v, want %#v", services[0], want)
	}
}

func TestParseSSDPResponse(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\n" +
		"LOCATION: http://192.168.1.12:8080/device.xml\r\n" +
		"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n" +
		"SERVER: Example/1.0\r\n\r\n"

	got, ok := parseSSDPResponse(response, "192.168.1.12")
	if !ok {
		t.Fatal("expected valid SSDP response to be parsed")
	}
	want := Service{
		Name:    "Example/1.0",
		Type:    "urn:schemas-upnp-org:device:MediaServer:1",
		Address: "192.168.1.12",
		Port:    8080,
		URL:     "http://192.168.1.12:8080/device.xml",
		Source:  "ssdp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseSSDPResponse() = %#v, want %#v", got, want)
	}
}

func TestParseSSDPResponseRejectsInvalidStatus(t *testing.T) {
	if _, ok := parseSSDPResponse("garbage\r\nSERVER: Example\r\n\r\n", "192.168.1.12"); ok {
		t.Fatal("expected malformed response to be rejected")
	}
}

func TestUniqueServices(t *testing.T) {
	services := []Service{
		{Address: "192.168.1.2", Port: 80, Type: "_http._tcp"},
		{Address: "192.168.1.2", Port: 80, Type: "_http._tcp"},
		{Address: "192.168.1.2", Port: 80, Type: "_https._tcp"},
	}
	got := uniqueServices(services)
	if len(got) != 2 {
		t.Fatalf("uniqueServices() returned %d entries, want 2", len(got))
	}
}

func TestServiceURL(t *testing.T) {
	tests := []struct {
		name        string
		serviceType string
		want        string
	}{
		{name: "http", serviceType: "_http._tcp", want: "http://192.168.1.2:8123"},
		{name: "https", serviceType: "_https._tcp", want: "https://192.168.1.2:443"},
		{name: "non-web", serviceType: "_ssh._tcp", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := serviceURL(test.serviceType, "192.168.1.2", map[string]int{"http": 8123, "https": 443}[test.name]); got != test.want {
				t.Fatalf("serviceURL() = %q, want %q", got, test.want)
			}
		})
	}
}
