# n8n-nodes-troubleshoot

A community node for [n8n](https://n8n.io) that provides network troubleshooting tools directly inside your workflows.

## Features

- **ICMP Ping** — Send real ICMP echo requests with configurable count and timeout. Returns packet loss, min/avg/max RTT, and reachability status.
- **DNS Resolve** — Query DNS records (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, ALL) with optional custom DNS server.
- **Verify TLS Cert** — Connect via TLS, retrieve the full certificate chain, cipher suite, protocol version, and authorization status.

## Installation

Install via the n8n Community Node panel:

```
n8n-nodes-troubleshoot
```

Or install manually into your n8n instance by placing the package in your custom extensions directory.

## Usage

Add the **Troubleshoot** node to your workflow. Choose an action:

### Ping
- **Host** — IP address or hostname
- **Ping Count** — Number of ICMP packets to send (`-c` flag)
- **Timeout (seconds)** — Maximum time to wait before ping exits (`-w` flag)

### DNS Resolve
- **Host** — Domain name to resolve
- **Record Type** — A, AAAA, MX, CNAME, TXT, NS, SOA, SRV, PTR, or ALL
- **DNS Server** — Optional custom resolver (e.g. `8.8.8.8`)

### Verify TLS Cert
- **Host** — Target server
- **Port** — Port to connect on (default: 443)
- **Servername (SNI)** — Override SNI hostname
- **Reject Unauthorized** — Reject self-signed / invalid certificates

## Output

All actions return a structured JSON object including:
- `success` — boolean
- `host` — target host
- `timestamp` — ISO 8601 timestamp
- Action-specific fields (RTT, records, certificate details, etc.)

## Security

- Input validation rejects shell metacharacters and invalid hosts
- ICMP ping uses `execFile` (no shell interpretation)
- No runtime dependencies — only Node.js built-in modules

## Compatibility

- Requires n8n >= 1.0
- Requires Node.js >= 18.10

## License

[MIT](LICENSE)
