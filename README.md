# n8n-nodes-troubleshoot

A custom node for [n8n](https://n8n.io) that provides **real** network troubleshooting tools inside your workflows.

**Important:** This node uses Node.js built-in modules (`dns`, `tls`, `child_process`) that are **blocked by n8n Cloud** for verified community nodes. This node is intended for **self-hosted n8n** instances only. It will not pass n8n's community node verification scan.

## Features

- **ICMP Ping** — Sends real ICMP echo requests via the system `ping` command. Returns packet loss, min/avg/max RTT, and reachability status.
- **DNS Resolve** — Queries DNS records using Node.js `dns` module (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, PTR, ALL) with optional custom DNS server.
- **Verify TLS Cert** — Connects via `tls.connect()`, retrieves the full certificate chain, cipher suite, protocol version, and authorization status.

## Why not HTTP/DoH?

ICMP ping tests **Layer 3** network reachability. HTTP HEAD tests **Layer 7** application availability. They are not the same:

| | ICMP Ping | HTTP HEAD |
|---|---|---|
| Layer | 3 (Network) | 7 (Application) |
| Tests | IP reachability | HTTP service availability |
| Works if port 80 closed? | Yes | No |
| Firewalls | Often block ICMP | Often allow HTTP |

For real network troubleshooting, you need ICMP. This node gives you that.

## Installation (Self-Hosted n8n)

### Option 1: Custom Extensions Directory

1. Download or clone this repo
2. Copy the `nodes/` folder into your n8n custom extensions directory (default: `~/.n8n/custom/`)
3. Restart n8n

### Option 2: npm install

```bash
cd ~/.n8n/custom/
npm install n8n-nodes-troubleshoot
```

### Option 3: Docker Compose

Mount this repo into your n8n container:

```yaml
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n
    volumes:
      - ./n8n-nodes-troubleshoot:/home/node/.n8n/custom/n8n-nodes-troubleshoot
```

## Usage

Add the **Troubleshoot** node to your workflow. Choose an action:

### Ping
- **Host** — IP address or hostname
- **Ping Count** — Number of ICMP packets (`-c` flag)
- **Timeout (seconds)** — Max wait before exit (`-w` flag)

### DNS Resolve
- **Host** — Domain name
- **Record Type** — A, AAAA, MX, CNAME, TXT, NS, SOA, SRV, PTR, ALL
- **DNS Server** — Optional custom resolver (e.g. `8.8.8.8`)

### Verify TLS Cert
- **Host** — Target server
- **Port** — Port (default: 443)
- **Servername (SNI)** — Override SNI hostname
- **Reject Unauthorized** — Reject invalid/self-signed certs

## Compatibility

- Requires **self-hosted n8n** (Docker, bare metal, etc.)
- Does **not** work on n8n Cloud
- Requires Node.js >= 18.10
- Container must have `ping` binary available (included in most Linux images)

## License

[MIT](LICENSE)
