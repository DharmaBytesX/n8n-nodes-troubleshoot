# n8n-nodes-troubleshoot

Real network troubleshooting in n8n workflows. ICMP ping, DNS resolve, TLS cert verification.

**Self-hosted only.** Uses Node.js built-in modules (`child_process`, `dns`, `tls`) — blocked by n8n Cloud.

## Features

- **ICMP Ping** — Real Layer 3 reachability via system `ping`. Returns packet loss, RTT min/avg/max, reachability.
- **DNS Resolve** — Query A, AAAA, MX, CNAME, TXT, NS, SOA, SRV, PTR, ALL. Optional custom DNS server. Outputs `resolvedIp` + `resolvedIps` for chaining.
- **Verify TLS Cert** — Full cert chain, cipher suite, protocol, authorization status.

## Quick Start (Docker)

Add to your n8n Docker Compose:

```yaml
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n
    environment:
      - N8N_CUSTOM_EXTENSIONS=/home/node/.n8n/custom
    volumes:
      - ./nodes/Troubleshoot:/home/node/.n8n/custom/troubleshoot
    restart: unless-stopped
```

Restart n8n. Node appears in workflow editor.

## Usage

| Action | Parameters | Output |
|--------|-----------|--------|
| **Ping** | Host, Count, Timeout | `reachable`, `packetLossPercent`, `rttAvg`, `elapsed` |
| **DNS Resolve** | Host, Record Type, DNS Server (opt) | `records`, `resolvedIp`, `resolvedIps`, `recordCount` |
| **Verify TLS Cert** | Host, Port, Servername, Reject Unauthorized | `certificate`, `certificateChain`, `cipher`, `protocol` |

### Chaining DNS → Ping

DNS Resolve outputs `resolvedIp` (first resolved address). Use it as input for Ping:

```
DNS Resolve (google.com) → Ping host: {{ $json.resolvedIp }}
```

## Compatibility

| Requirement | Detail |
|------------|--------|
| n8n hosting | Self-hosted only (not n8n Cloud) |
| Node.js | >= 18.10 |
| Container | `ping` binary required (included in Alpine, Debian, Ubuntu) |

## License

MIT
