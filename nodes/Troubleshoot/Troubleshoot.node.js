const net = require('net');

// ----------------------------------------------------------------------------
// Validation helpers
// ----------------------------------------------------------------------------

function isValidHost(host) {
	if (!host || typeof host !== 'string') return false;
	return !/[;&|`$(){}[\]<>\n\r\x00]/.test(host);
}

function isPositiveInt(n) {
	return Number.isInteger(n) && n > 0;
}

function isNonNegativeInt(n) {
	return Number.isInteger(n) && n >= 0;
}

// ----------------------------------------------------------------------------
// Standalone helper functions
// ----------------------------------------------------------------------------

/**
 * TCP connectivity check — n8n Cloud blocks child_process, so no ICMP ping.
 * Uses net.createConnection to host:port and measures RTT.
 */
async function tcpPing(host, count, timeoutMs) {
	if (!isValidHost(host)) {
		throw new Error('Invalid host value');
	}
	if (!isPositiveInt(count) || count > 100) {
		throw new Error('Ping count must be a positive integer (max 100)');
	}
	if (!isNonNegativeInt(timeoutMs) || timeoutMs > 300000) {
		throw new Error('Timeout must be between 0 and 300000 ms');
	}

	const results = [];
	let successCount = 0;
	let failCount = 0;
	let totalRtt = 0;
	let minRtt = Infinity;
	let maxRtt = 0;

	for (let i = 0; i < count; i++) {
		const startTime = Date.now();
		try {
			await new Promise((resolve, reject) => {
				const socket = new net.Socket();
				let settled = false;
				const settle = (fn) => {
					if (settled) return;
					settled = true;
					socket.destroy();
					fn();
				};
				socket.setTimeout(timeoutMs);
				socket.on('connect', () => {
					const rtt = Date.now() - startTime;
					settle(() => resolve({ rtt, ip: socket.remoteAddress }));
				});
				socket.on('error', (err) => {
					settle(() => reject(err));
				});
				socket.on('timeout', () => {
					settle(() => reject(new Error('Connection timed out')));
				});
				socket.connect(80, host);
			});
			const rtt = Date.now() - startTime;
			successCount++;
			totalRtt += rtt;
			if (rtt < minRtt) minRtt = rtt;
			if (rtt > maxRtt) maxRtt = rtt;
			results.push({ seq: i + 1, rtt, success: true });
		} catch (err) {
			failCount++;
			results.push({ seq: i + 1, rtt: null, success: false, error: err.message });
		}
	}

	const rttAvg = successCount > 0 ? Math.round(totalRtt / successCount) : null;
	const lossPercent = Math.round((failCount / count) * 100);

	return {
		success: successCount > 0,
		reachable: successCount > 0,
		type: 'tcp',
		host,
		count,
		port: 80,
		timeout: timeoutMs,
		packetsTransmitted: count,
		packetsReceived: successCount,
		packetLossPercent: lossPercent,
		rttMin: successCount > 0 ? minRtt : null,
		rttAvg,
		rttMax: successCount > 0 ? maxRtt : null,
		rttMs: rttAvg !== null ? `${rttAvg}ms` : null,
		results,
	};
}

/**
 * DNS resolution via Cloudflare DNS-over-HTTPS (fetch).
 * n8n Cloud blocks the dns module, so we use a public DoH API.
 */
async function dnsResolve(hostname, recordType) {
	if (!isValidHost(hostname)) {
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

	let data;
	try {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), 15000);
		const response = await fetch(url, {
			headers: { Accept: 'application/dns-json' },
			signal: controller.signal,
		});
		clearTimeout(timer);

		if (!response.ok) {
			throw new Error(`DoH API returned ${response.status}`);
		}
		data = await response.json();
	} catch (err) {
		return {
			success: false,
			error: `DNS lookup failed: ${err.message}`,
			query: { hostname, recordType, server: 'cloudflare-dns.com' },
		};
	}

	if (data.Status !== 0) {
		return {
			success: false,
			error: `DNS lookup failed with status code ${data.Status}`,
			code: data.Status,
			query: { hostname, recordType, server: 'cloudflare-dns.com' },
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
		query: { hostname, recordType, server: 'cloudflare-dns.com' },
		records,
		recordCount: records.length,
	};
}

/**
 * TLS / HTTPS connectivity check via fetch().
 * n8n Cloud blocks the tls module, so we cannot extract certificate details.
 * Instead we verify the HTTPS handshake succeeds and measure timing.
 */
async function verifyTlsCert(host, port, servername) {
	if (!isValidHost(host)) {
		throw new Error('Invalid host value');
	}
	if (!isPositiveInt(port) || port > 65535) {
		throw new Error('Port must be between 1 and 65535');
	}

	const url = `https://${servername || host}:${port}/`;
	const startTime = Date.now();

	try {
		const controller = new AbortController();
		const timer = setTimeout(() => controller.abort(), 15000);
		const response = await fetch(url, {
			method: 'HEAD',
			redirect: 'manual',
			signal: controller.signal,
		});
		clearTimeout(timer);

		const rtt = Date.now() - startTime;

		return {
			success: true,
			rtt,
			rttMs: `${rtt}ms`,
			connected: true,
			statusCode: response.status,
			statusText: response.statusText,
			url: response.url,
			headers: Object.fromEntries(response.headers.entries()),
			note: 'n8n Cloud restricts tls module access; certificate details unavailable. Connectivity and handshake verified.',
		};
	} catch (err) {
		const rtt = Date.now() - startTime;
		let errorMsg = err.message;

		if (errorMsg.includes('UNABLE_TO_VERIFY_LEAF_SIGNATURE') ||
			errorMsg.includes('UNABLE_TO_VERIFY') ||
			errorMsg.includes('certificate')) {
			errorMsg = `TLS certificate validation failed: ${errorMsg}`;
		} else if (errorMsg.includes('ECONNREFUSED')) {
			errorMsg = `Connection refused on port ${port}`;
		} else if (errorMsg.includes('ETIMEDOUT') || errorMsg.includes('timed out')) {
			errorMsg = `Connection timed out after ${rtt}ms`;
		} else if (errorMsg.includes('ENOTFOUND') || errorMsg.includes('getaddrinfo')) {
			errorMsg = `Host not found: ${host}`;
		}

		return {
			success: false,
			connected: false,
			error: errorMsg,
			rtt,
			rttMs: `${rtt}ms`,
			note: 'n8n Cloud restricts tls module access; certificate details unavailable.',
		};
	}
}

// ----------------------------------------------------------------------------
// Node class
// ----------------------------------------------------------------------------

class Troubleshoot {
	description = {
		displayName: 'Troubleshoot',
		name: 'troubleshoot',
		icon: 'fa:bug',
		group: ['transform'],
		version: 1,
		description:
			'Run network troubleshooting checks: TCP connectivity, DNS resolve, TLS/HTTPS verification',
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
						description: 'TCP connectivity check to a host (port 80)',
					},
					{
						name: 'DNS Resolve',
						value: 'dnsResolve',
						description: 'Resolve a domain name via DNS-over-HTTPS',
					},
					{
						name: 'Verify TLS Cert',
						value: 'verifyTlsCert',
						description:
							'Verify HTTPS/TLS connectivity (handshake & response)',
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
				description: 'Number of TCP connection attempts',
			},
			{
				displayName: 'Timeout (ms)',
				name: 'pingTimeout',
				type: 'number',
				default: 5000,
				displayOptions: { show: { action: ['ping'] } },
				description: 'Connection timeout per attempt in milliseconds',
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
				description: 'Port to connect to for TLS verification',
			},
			{
				displayName: 'Servername (SNI)',
				name: 'tlsServername',
				type: 'string',
				default: '',
				placeholder: 'e.g. google.com',
				displayOptions: { show: { action: ['verifyTlsCert'] } },
				description:
					'Server name for TLS SNI extension. Defaults to host if empty.',
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
						result = await tcpPing(
							host,
							this.getNodeParameter('pingCount', i),
							this.getNodeParameter('pingTimeout', i),
						);
						break;

					case 'dnsResolve':
						result = await dnsResolve(
							host,
							this.getNodeParameter('dnsRecordType', i),
						);
						break;

					case 'verifyTlsCert':
						result = await verifyTlsCert(
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
					errorStack: error.stack,
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

module.exports = { Troubleshoot };
