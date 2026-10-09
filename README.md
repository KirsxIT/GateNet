# LAN Gateway

Linux-first prototype for reaching discovered TCP services over WireGuard.
The gateway uses the Linux kernel WireGuard interface; phones use the official
WireGuard app and import a generated QR profile. No traffic passes through a
relay.

## Quick start

Build on Linux with Go 1.25 or newer:

```sh
go build -o lan-gateway ./cmd/lan-gateway
sudo ./lan-gateway pair --name phone --endpoint vpn.example.net:51820
sudo ./lan-gateway gateway
```

Use the same `--network` value on `pair` and `gateway` if the default
`10.203.0.0/24` overlaps an existing route.

Scan the QR shown by `pair` in the WireGuard app. `pair` stores the peer's
public key and prints its private profile only in the QR. Keep that QR private.
The gateway watches peer state; `revoke --name phone` removes the peer from the
running interface within about one second.

Use `--state-dir` on `pair`, `gateway`, and `revoke` to select a different
directory. The default is `/var/lib/lan-gateway`. The gateway private key and
peer registry are runtime state files, not configuration files; the directory
and private key are restricted to owner-only permissions.

The `--endpoint` in the generated profile must already be directly reachable
from the client. Stock WireGuard apps do not poll a rendezvous service or
perform NAT hole punching. This prototype therefore supports networks with a
directly reachable endpoint (for example, reachable IPv6); it does not promise
connectivity through arbitrary NAT/CGNAT and does not set up port forwarding.

For local diagnostics, `discover` prints a one-shot catalog and `serve
--listen 127.0.0.1:8787` refreshes it over loopback without creating a tunnel.

## Service access

The gateway queries mDNS and SSDP on the attached LAN, then exposes discovered
private-address TCP services through per-service TCP proxies bound to the
WireGuard interface. With the default network and catalog port, fetch
`http://10.203.0.1:8787/services` through the tunnel to see each service's
`gateway_address` and `gateway_port`. Connect to that address and port with the
service's normal client (browser, SSH, database client, etc.).

The generated peer route includes only the gateway tunnel address; it does not
route the whole home LAN. Proxies are created only for discovered services
advertising a private IPv4 or IPv6 address. UDP services, undiscovered services,
and services on other VLANs are not exposed. mDNS/SSDP discovery is best-effort
and generally does not cross VLAN boundaries.

## Host requirements and limits

- Linux with kernel WireGuard support; run `gateway` with privileges to create
  and configure a network interface.
- Allow inbound WireGuard UDP on the chosen listen port from reachable clients.
  Permit TCP on `wg-lan` for tunnel peers so they can reach the catalog and
  discovered service proxies. Apply firewall policy yourself; the daemon does
  not alter host firewall rules.
- All paired peers currently share access to every discovered TCP service; the
  prototype does not provide per-peer service ACLs.
- Gateway mode and the tunnel interface are Linux-only. Other platforms can
  run discovery only.
