class Troubleshoot {
	description = {
		displayName: 'Troubleshoot',
		name: 'troubleshoot',
		icon: 'fa:bug',
		group: ['transform'],
		version: 1,
		description:
			'Run network troubleshooting checks: HTTP connectivity, DNS-over-HTTPS, HTTPS handshake',
		defaults: {
			name: 'Troubleshoot',
		},
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Action',
				name: 'action',
				type: 'options',
				options: [
					{
						name: 'Ping',
						value: 'ping',
						description: 'HTTP connectivity check (HEAD request, port 80)',
					},
					{
						name: 'DNS Resolve',
						value: 'dnsResolve',
						description: 'Resolve DNS via Cloudflare DNS-over-HTTPS',
					},
					{
						name: 'Verify TLS Cert',
						value: 'verifyTlsCert',
						description: 'HTTPS handshake and connectivity check',
					},
				],
				default: 'ping',
				description: 'Troubleshooting action to perform',
			},

			{
				displayName: 'Host',
				name: 'host',
				type: 'string',
				default: '',
				placeholder: 'e.g. google.com',
				required: true,
				description: 'Hostname or IP address to target',
			},

			{
				displayName: 'Ping Count',
				name: 'pingCount',
				type: 'number',
				default: 4,
				displayOptions: { show: { action: ['ping'] } },
				description: 'Number of HTTP HEAD requests to send',
			},

			{
				displayName: 'Record Type',
				name: 'dnsRecordType',
				type: 'options',
				displayOptions: { show: { action: ['dnsResolve'] } },
				options: [
					{ name: 'A - IPv4 Address', value: 'A' },
					{ name: 'AAAA - IPv6 Address', value: 'AAAA' },
					{ name: 'MX - Mail Exchange', value: 'MX' },
					{ name: 'CNAME - Canonical Name', value: 'CNAME' },
					{ name: 'TXT - Text Record', value: 'TXT' },
					{ name: 'NS - Nameserver', value: 'NS' },
					{ name: 'SOA - Start of Authority', value: 'SOA' },
					{ name: 'SRV - Service Record', value: 'SRV' },
					{ name: 'PTR - Reverse Lookup', value: 'PTR' },
					{ name: 'ALL - All Records', value: 'ALL' },
				],
				default: 'A',
			},

			{
				displayName: 'Port',
				name: 'tlsPort',
				type: 'number',
				default: 443,
				displayOptions: { show: { action: ['verifyTlsCert'] } },
				description: 'HTTPS port to connect to',
			},
			{
				displayName: 'Servername (SNI)',
				name: 'tlsServername',
				type: 'string',
				default: '',
				placeholder: 'e.g. google.com',
				displayOptions: { show: { action: ['verifyTlsCert'] } },
				description: 'Server name for TLS SNI. Defaults to host if empty.',
			},
		],
	};

	async execute() {
		const items = this.getInputData();
		const returnData = [];

		for (let i = 0; i < items.length; i++) {
			const action = this.getNodeParameter('action', i);
			const host = this.getNodeParameter('host', i);
			let result;

			try {
				switch (action) {
					case 'ping':
						result = await httpPing(host, this.getNodeParameter('pingCount', i));
						break;
					case 'dnsResolve':
						result = await dnsResolve(host, this.getNodeParameter('dnsRecordType', i));
						break;
					case 'verifyTlsCert':
						result = await verifyTls(
							host,
							this.getNodeParameter('tlsPort', i),
							this.getNodeParameter('tlsServername', i) || host,
						);
						break;
					default:
						throw new Error(`Unknown action: ${action}`);
				}
			} catch (error) {
				result = {
					success: false,
					error: error.message,
				};
			}

			returnData.push({
				json: {
					action,
					host,
					timestamp: new Date().toISOString(),
					...result,
				},
			});
		}

		return [returnData];
	}
}

// ---------------------------------------------------------------------------
// Helpers — zero require(), zero setTimeout, only fetch() + basic JS
// ---------------------------------------------------------------------------

async function httpPing(host, count) {
	if (!host || typeof host !== 'string' || host.length === 0) {
		throw new Error('Invalid host');
	}
	if (!Number.isInteger(count) || count < 1 || count > 100) {
		throw new Error('Count must be an integer between 1 and 100');
	}

	const results = [];
	let successCount = 0;

	for (let i = 0; i < count; i++) {
		const start = Date.now();
		try {
			const response = await fetch(`http://${host}:80/`, {
				method: 'HEAD',
				redirect: 'manual',
			});
			const rtt = Date.now() - start;
			successCount++;
			results.push({ seq: i + 1, rtt, success: true, status: response.status });
		} catch (err) {
			results.push({ seq: i + 1, rtt: Date.now() - start, success: false, error: err.message });
		}
	}

	return {
		success: successCount > 0,
		reachable: successCount > 0,
		type: 'http',
		host,
		count,
		port: 80,
		packetsTransmitted: count,
		packetsReceived: successCount,
		packetLossPercent: Math.round(((count - successCount) / count) * 100),
		results,
	};
}

async function dnsResolve(hostname, recordType) {
	if (!hostname || typeof hostname !== 'string' || hostname.length === 0) {
		throw new Error('Invalid hostname');
	}

	const typeMap = {
		A: 1,
		NS: 2,
		CNAME: 5,
		SOA: 6,
		PTR: 12,
		MX: 15,
		TXT: 16,
		AAAA: 28,
		SRV: 33,
		ALL: 255,
	};

	const typeCode = typeMap[recordType];
	if (!typeCode) {
		throw new Error(`Unsupported DNS record type: ${recordType}`);
	}

	const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=${typeCode}`;

	try {
		const response = await fetch(url, {
			headers: { Accept: 'application/dns-json' },
		});

		if (!response.ok) {
			throw new Error(`DoH API returned ${response.status}`);
		}

		const data = await response.json();

		if (data.Status !== 0) {
			return {
				success: false,
				error: `DNS lookup failed with status ${data.Status}`,
				code: data.Status,
				query: { hostname, recordType },
			};
		}

		const answers = data.Answer || [];
		const records = answers.map((a) => ({
			name: a.name,
			type: a.type,
			TTL: a.TTL,
			data: a.data,
		}));

		return {
			success: true,
			query: { hostname, recordType },
			records,
			recordCount: records.length,
		};
	} catch (err) {
		return {
			success: false,
			error: `DNS lookup failed: ${err.message}`,
			query: { hostname, recordType },
		};
	}
}

async function verifyTls(host, port, servername) {
	if (!host || typeof host !== 'string' || host.length === 0) {
		throw new Error('Invalid host');
	}
	if (!Number.isInteger(port) || port < 1 || port > 65535) {
		throw new Error('Port must be between 1 and 65535');
	}

	const url = `https://${servername || host}:${port}/`;
	const start = Date.now();

	try {
		const response = await fetch(url, {
			method: 'HEAD',
			redirect: 'manual',
		});
		const rtt = Date.now() - start;

		return {
			success: true,
			rtt,
			rttMs: `${rtt}ms`,
			connected: true,
			statusCode: response.status,
			statusText: response.statusText,
			url: response.url,
		};
	} catch (err) {
		const rtt = Date.now() - start;
		let errorMsg = err.message;

		if (errorMsg.includes('certificate') || errorMsg.includes('UNABLE_TO_VERIFY')) {
			errorMsg = `TLS certificate validation failed: ${errorMsg}`;
		} else if (errorMsg.includes('ECONNREFUSED')) {
			errorMsg = `Connection refused on port ${port}`;
		} else if (errorMsg.includes('ENOTFOUND') || errorMsg.includes('getaddrinfo')) {
			errorMsg = `Host not found: ${host}`;
		}

		return {
			success: false,
			connected: false,
			error: errorMsg,
			rtt,
			rttMs: `${rtt}ms`,
		};
	}
}

module.exports = { Troubleshoot };
