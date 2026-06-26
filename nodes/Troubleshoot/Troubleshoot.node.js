const dnsPromises = require('dns').promises;
const tls = require('tls');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

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

async function icmpPing(host, count, timeoutSec) {
	if (!isValidHost(host)) throw new Error('Invalid host value');
	if (!isPositiveInt(count) || count > 100) throw new Error('Ping count must be a positive integer (max 100)');
	if (!isNonNegativeInt(timeoutSec) || timeoutSec > 300) throw new Error('Timeout must be between 0 and 300 seconds');

	const startTime = Date.now();
	try {
		const { stdout } = await execFileAsync('ping', ['-c', String(count), '-w', String(timeoutSec), '-q', host]);
		const elapsed = Date.now() - startTime;

		const stats = { packetsTransmitted: null, packetsReceived: null, packetLossPercent: null, rttMin: null, rttAvg: null, rttMax: null, rttMs: null };

		const packetMatch = stdout.match(/(\d+)\s+packets?\s+transmitted[,\s]+(\d+)\s+packets?\s+received[,\s]+(\d+)%\s+packet loss/);
		if (packetMatch) {
			stats.packetsTransmitted = parseInt(packetMatch[1], 10);
			stats.packetsReceived = parseInt(packetMatch[2], 10);
			stats.packetLossPercent = parseInt(packetMatch[3], 10);
		}

		const rttMatch = stdout.match(new RegExp('(?:round-trip|rtt)\s+min/avg/max\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms'));
		if (rttMatch) {
			stats.rttMin = parseFloat(rttMatch[1]);
			stats.rttAvg = parseFloat(rttMatch[2]);
			stats.rttMax = parseFloat(rttMatch[3]);
			stats.rttMs = `${stats.rttAvg}ms`;
		}

		const success = stats.packetsReceived > 0;
		return { success, reachable: success, type: 'icmp', host, count, timeout: timeoutSec, elapsed: `${elapsed}ms`, ...stats };
	} catch (error) {
		const elapsed = Date.now() - startTime;
		const stdout = error.stdout || '';
		const packetMatch = stdout.match(/(\d+)\s+packets?\s+transmitted[,\s]+(\d+)\s+packets?\s+received[,\s]+(\d+)%\s+packet loss/);
		const stats = {
			packetsTransmitted: packetMatch ? parseInt(packetMatch[1], 10) : null,
			packetsReceived: packetMatch ? parseInt(packetMatch[2], 10) : null,
			packetLossPercent: packetMatch ? parseInt(packetMatch[3], 10) : null,
		};
		const rttMatch = stdout.match(new RegExp('(?:round-trip|rtt)\s+min/avg/max\s*=\s*([0-9.]+)/([0-9.]+)/([0-9.]+)\s*ms'));
		if (rttMatch) {
			stats.rttMin = parseFloat(rttMatch[1]);
			stats.rttAvg = parseFloat(rttMatch[2]);
			stats.rttMax = parseFloat(rttMatch[3]);
		}
		return { success: false, reachable: false, type: 'icmp', host, count, timeout: timeoutSec, elapsed: `${elapsed}ms`, error: `ping failed: ${error.stderr || stdout || error.message}`, ...stats };
	}
}

async function dnsResolve(hostname, recordType, dnsServer) {
	if (!isValidHost(hostname)) throw new Error('Invalid hostname');
	const resolver = new dnsPromises.Resolver();
	if (dnsServer) resolver.setServers([dnsServer]);

	const resolveMap = {
		A: resolver.resolve4.bind(resolver),
		AAAA: resolver.resolve6.bind(resolver),
		MX: resolver.resolveMx.bind(resolver),
		CNAME: resolver.resolveCname.bind(resolver),
		TXT: resolver.resolveTxt.bind(resolver),
		NS: resolver.resolveNs.bind(resolver),
		SOA: resolver.resolveSoa.bind(resolver),
		SRV: resolver.resolveSrv.bind(resolver),
		PTR: resolver.resolvePtr.bind(resolver),
		ALL: resolver.resolveAny.bind(resolver),
	};

	const resolveFn = resolveMap[recordType];
	if (!resolveFn) throw new Error(`Unsupported DNS record type: ${recordType}`);

	try {
		const records = await resolveFn(hostname);
		return { success: true, query: { hostname, recordType, server: dnsServer || 'system default' }, records, recordCount: Array.isArray(records) ? records.length : 1 };
	} catch (err) {
		return { success: false, error: `DNS ${recordType} lookup failed: ${err.message}`, code: err.code, query: { hostname, recordType, server: dnsServer || 'system default' } };
	}
}

function formatCert(cert) {
	if (!cert) return null;
	return {
		subject: cert.subject || {},
		issuer: cert.issuer || {},
		serialNumber: cert.serialNumber || '',
		validFrom: cert.valid_from || '',
		validTo: cert.valid_to || '',
		fingerprint: cert.fingerprint || '',
		fingerprint256: cert.fingerprint256 || '',
		fingerprint512: cert.fingerprint512 || '',
		subjectAltName: cert.subjectaltname || '',
		bits: cert.bits || null,
		pubkey: cert.pubkey ? `[${cert.pubkey.type} key, ${cert.bits || 'unknown'} bits]` : null,
	};
}

function getCertChain(cert) {
	const chain = [];
	let current = cert;
	while (current) {
		chain.push({ subject: current.subject || {}, issuer: current.issuer || {}, fingerprint: current.fingerprint || '', validFrom: current.valid_from || '', validTo: current.valid_to || '' });
		current = current.issuerCertificate;
		if (current && chain.some((c) => c.fingerprint === current.fingerprint)) break;
	}
	return chain;
}

async function verifyTlsCert(host, port, servername, rejectUnauthorized) {
	if (!isValidHost(host)) throw new Error('Invalid host value');
	if (!isPositiveInt(port) || port > 65535) throw new Error('Port must be between 1 and 65535');

	return new Promise((resolve) => {
		const startTime = Date.now();
		const socket = tls.connect({ host, port, servername, rejectUnauthorized }, () => {
			const rtt = Date.now() - startTime;
			const cert = socket.getPeerCertificate(true);
			if (!cert || Object.keys(cert).length === 0) {
				socket.end();
				resolve({ success: false, error: 'No certificate received from server' });
				return;
			}
			const result = {
				success: true,
				rtt,
				rttMs: `${rtt}ms`,
				authorized: socket.authorized,
				authorizationError: socket.authorizationError || null,
				cipher: socket.getCipher ? socket.getCipher() : null,
				protocol: socket.getProtocol ? socket.getProtocol() : null,
				certificate: formatCert(cert),
				certificateChain: getCertChain(cert),
			};
			socket.end();
			resolve(result);
		});
		socket.setTimeout(15000);
		socket.on('error', (err) => resolve({ success: false, error: `TLS connection failed: ${err.message}`, rtt: Date.now() - startTime }));
		socket.on('timeout', () => { socket.destroy(); resolve({ success: false, error: 'TLS connection timed out' }); });
	});
}

class Troubleshoot {
	description = {
		displayName: 'Troubleshoot',
		name: 'troubleshoot',
		icon: 'fa:bug',
		group: ['transform'],
		version: 1,
		description: 'Run network troubleshooting checks: ICMP ping, DNS resolve, TLS cert verification',
		defaults: { name: 'Troubleshoot' },
		inputs: ['main'],
		outputs: ['main'],
		properties: [
			{
				displayName: 'Action',
				name: 'action',
				type: 'options',
				options: [
					{ name: 'Ping', value: 'ping', description: 'ICMP ping a host' },
					{ name: 'DNS Resolve', value: 'dnsResolve', description: 'Resolve a domain name to IP addresses' },
					{ name: 'Verify TLS Cert', value: 'verifyTlsCert', description: 'Check TLS/SSL certificate details for a host' },
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
				description: 'Number of ICMP echo requests to send (-c flag)',
			},
			{
				displayName: 'Timeout (seconds)',
				name: 'pingTimeout',
				type: 'number',
				default: 10,
				displayOptions: { show: { action: ['ping'] } },
				description: 'Maximum time in seconds to wait before ping exits (-w flag)',
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
				displayName: 'DNS Server',
				name: 'dnsServer',
				type: 'string',
				default: '',
				placeholder: 'e.g. 8.8.8.8',
				displayOptions: { show: { action: ['dnsResolve'] } },
				description: 'Optional custom DNS server (leave empty for system default)',
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
				description: 'Server name for TLS SNI extension. Defaults to host if empty.',
			},
			{
				displayName: 'Reject Unauthorized',
				name: 'tlsRejectUnauthorized',
				type: 'boolean',
				default: false,
				displayOptions: { show: { action: ['verifyTlsCert'] } },
				description: 'Whether to reject unauthorized / self-signed certificates',
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
						result = await icmpPing(host, this.getNodeParameter('pingCount', i), this.getNodeParameter('pingTimeout', i));
						break;
					case 'dnsResolve':
						result = await dnsResolve(host, this.getNodeParameter('dnsRecordType', i), this.getNodeParameter('dnsServer', i));
						break;
					case 'verifyTlsCert':
						result = await verifyTlsCert(host, this.getNodeParameter('tlsPort', i), this.getNodeParameter('tlsServername', i) || host, this.getNodeParameter('tlsRejectUnauthorized', i));
						break;
					default:
						throw new Error(`Unknown action: ${action}`);
				}
			} catch (error) {
				result = { success: false, error: error.message, errorStack: error.stack };
			}
			returnData.push({
				json: { action, host, timestamp: new Date().toISOString(), ...result },
			});
		}
		return [returnData];
	}
}

module.exports = { Troubleshoot };
