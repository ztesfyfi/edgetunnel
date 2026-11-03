import upstream from './_worker-core.js';

const TLSFP_MEMORY = new Map();

function normalizeHost(value) {
	const raw = String(value || '').trim().toLowerCase().replace(/^https?:\/\//i, '').split(/[/?#]/)[0];
	if (!raw || raw.includes('@')) return '';
	if (raw.startsWith('*.')) return raw;
	return raw.replace(/:\d+$/, '').replace(/\.$/, '');
}

function hostMatches(host, pattern) {
	const h = normalizeHost(host);
	const p = normalizeHost(pattern);
	if (!h || !p) return false;
	if (h === p) return true;
	if (p.startsWith('*.')) return h.endsWith(p.slice(1)) && h.split('.').length === p.split('.').length;
	return false;
}

function readDER(bytes, offset) {
	if (offset + 2 > bytes.length) throw new Error('DER truncated');
	const start = offset;
	const tag = bytes[offset++];
	let length = bytes[offset++];
	if (length & 0x80) {
		const count = length & 0x7f;
		if (!count || count > 4 || offset + count > bytes.length) throw new Error('Invalid DER length');
		length = 0;
		for (let i = 0; i < count; i++) length = length * 256 + bytes[offset++];
	}
	const contentStart = offset;
	const end = contentStart + length;
	if (end > bytes.length) throw new Error('DER bounds error');
	return { tag, start, contentStart, end };
}

function extractSPKI(der) {
	const cert = readDER(der, 0);
	const tbs = readDER(der, cert.contentStart);
	let offset = tbs.contentStart;
	let node = readDER(der, offset);
	if (node.tag === 0xa0) offset = node.end;
	for (let i = 0; i < 5; i++) offset = readDER(der, offset).end;
	const spki = readDER(der, offset);
	if (spki.tag !== 0x30) throw new Error('Invalid SPKI sequence');
	return der.slice(spki.start, spki.end);
}

function bytesToHex(bytes, colon = false) {
	const parts = Array.from(bytes, b => b.toString(16).padStart(2, '0').toUpperCase());
	return colon ? parts.join(':') : parts.join('').toLowerCase();
}

function bytesToBase64(bytes) {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary);
}

function pemToDER(pem) {
	const base64 = String(pem || '').replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, '');
	if (!base64 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) throw new Error('Invalid PEM');
	const binary = atob(base64);
	return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function getTLSFingerprint(hostPattern, env, forceRefresh = false) {
	const pattern = normalizeHost(hostPattern);
	if (!pattern || pattern.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(pattern)) return null;
	const key = 'TLSFP:v1:' + pattern;
	const now = Date.now();

	if (!forceRefresh) {
		const memory = TLSFP_MEMORY.get(key);
		if (memory) return memory.value;
		try {
			const cached = env?.KV ? await env.KV.get(key, 'json') : null;
			if (cached?.certificateSha256Hex && cached?.spkiSha256Base64) {
				TLSFP_MEMORY.set(key, { value: cached });
				return cached;
			}
		} catch (error) {
			console.warn('[TLSFP] KV read failed:', error?.message || error);
		}
	}

	try {
		const probeHost = pattern.startsWith('*.') ? 'fp-check.' + pattern.slice(2) : pattern;
		const apiBase = String(env?.TLSFP_API || 'https://networkcalc.com/api/security/certificate').replace(/\/+$/, '');
		const response = await fetch(apiBase + '/' + encodeURIComponent(probeHost), {
			headers: { Accept: 'application/json' },
			signal: AbortSignal.timeout(10000)
		});
		if (!response.ok) throw new Error('TLS probe API HTTP ' + response.status);
		const payload = await response.json();
		const cert = payload?.certificate;
		if (payload?.status !== 'OK' || !cert?.raw) throw new Error('TLS probe API returned no certificate');

		const validFrom = Date.parse(cert.valid_from || 0);
		const validTo = Date.parse(cert.valid_to || 0);
		if (!Number.isFinite(validFrom) || !Number.isFinite(validTo) || validFrom > now || validTo <= now) {
			throw new Error('The served certificate is outside its validity period');
		}
		const names = [cert.issued_to, ...(Array.isArray(cert.alternate_names) ? cert.alternate_names : [])]
			.filter(Boolean).map(name => String(name).replace(/^DNS:/i, '').trim());
		if (!names.some(name => hostMatches(probeHost, name))) throw new Error('Certificate SAN does not match ' + probeHost);

		const der = pemToDER(cert.raw);
		const spkiDER = extractSPKI(der);
		const certDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', der));
		const spkiDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', spkiDER));
		const value = {
			domain: pattern,
			probeHost,
			certificateSha256Hex: bytesToHex(certDigest),
			certificateSha256Colon: bytesToHex(certDigest, true),
			certificateSha256Base64: bytesToBase64(certDigest),
			spkiSha256Hex: bytesToHex(spkiDigest),
			spkiSha256Base64: bytesToBase64(spkiDigest),
			validTo: cert.valid_to,
			issuer: cert.issued_by || ''
		};

		TLSFP_MEMORY.set(key, { value });
		try {
			if (env?.KV) await env.KV.put(key, JSON.stringify(value));
		} catch (error) {
			console.warn('[TLSFP] KV write failed:', error?.message || error);
		}
		return value;
	} catch (error) {
		console.warn('[TLSFP] Probe failed; leaving node unchanged:', pattern, error?.message || error);
		return null;
	}
}

function findFingerprint(host, mapping) {
	const domain = normalizeHost(host);
	if (!domain) return null;
	if (mapping[domain]) return mapping[domain];
	for (const [pattern, value] of Object.entries(mapping)) {
		if (pattern.startsWith('*.') && hostMatches(domain, pattern)) return value;
	}
	return null;
}

async function collectFingerprints(hosts, env, forceRefresh) {
	const patterns = [...new Set(hosts.map(normalizeHost).filter(Boolean))].slice(0, 12);
	const entries = await Promise.all(patterns.map(async pattern => [pattern, await getTLSFingerprint(pattern, env, forceRefresh)]));
	return Object.fromEntries(entries.filter(([, value]) => value));
}

function buildResponse(original, body) {
	const headers = new Headers(original.headers);
	headers.delete('content-length');
	headers.delete('content-encoding');
	headers.set('Cache-Control', 'no-store');
	return new Response(body, { status: original.status, statusText: original.statusText, headers });
}

function addXrayPins(text, mapping, forceRefresh) {
	let changed = false;
	const output = text.split(/\r?\n/).map(line => {
		if (!/^(?:vless|trojan):\/\//i.test(line.trim())) return line;
		try {
			const node = new URL(line.trim());
			const security = (node.searchParams.get('security') || (node.protocol === 'trojan:' ? 'tls' : '')).toLowerCase();
			if (security !== 'tls') return line;
			const sni = node.searchParams.get('sni') || node.hostname;
			const pin = findFingerprint(sni, mapping);
			if (!pin) return line;
			if (!node.searchParams.has('pcs') || forceRefresh) node.searchParams.set('pcs', pin.certificateSha256Colon);
			if (!node.searchParams.has('vcn')) node.searchParams.set('vcn', sni);
			changed = true;
			return node.toString();
		} catch {
			return line;
		}
	}).join('\n');
	return { text: output, changed };
}

function addSingBoxPins(config, mapping, certificateMode) {
	let changed = false;
	if (!Array.isArray(config?.outbounds)) return false;
	for (const outbound of config.outbounds) {
		if (!outbound || !['vless', 'trojan'].includes(String(outbound.type || '').toLowerCase())) continue;
		if (!outbound.tls || typeof outbound.tls !== 'object') continue;
		const sni = outbound.tls.server_name || outbound.server_name || outbound.server;
		const pin = findFingerprint(sni, mapping);
		if (!pin) continue;
		const merge = (oldValue, value) => [...new Set([...(Array.isArray(oldValue) ? oldValue : (oldValue ? [oldValue] : [])), value])];
		outbound.tls.certificate_public_key_sha256 = merge(outbound.tls.certificate_public_key_sha256, pin.spkiSha256Base64);
		if (certificateMode) outbound.tls.certificate_sha256 = merge(outbound.tls.certificate_sha256, pin.certificateSha256Base64);
		changed = true;
	}
	return changed;
}

export default {
	async fetch(request, env, ctx) {
		const response = await upstream.fetch(request, env, ctx);
		const url = new URL(request.url);
		if (url.pathname.replace(/\/+$/, '') !== '/sub' || !response.ok) return response;

		const originalText = await response.text();
		if (!originalText) return buildResponse(response, originalText);

		const ua = (request.headers.get('User-Agent') || '').toLowerCase();
		const target = (url.searchParams.get('target') || '').toLowerCase();
		const isSingBox = target === 'singbox' || url.searchParams.has('sb') || url.searchParams.has('singbox') || (!target && (ua.includes('singbox') || ua.includes('sing-box')));
		const forceRefresh = url.searchParams.get('refreshfp') === '1';
		const certificateMode = url.searchParams.get('sbcert') === '1' || Number.parseFloat(url.searchParams.get('sbver') || '0') >= 1.15;

		if (isSingBox) {
			try {
				const config = JSON.parse(originalText);
				const hosts = [];
				for (const outbound of config?.outbounds || []) {
					if (!outbound || !['vless', 'trojan'].includes(String(outbound.type || '').toLowerCase())) continue;
					const sni = outbound.tls?.server_name || outbound.server_name || outbound.server;
					if (sni) hosts.push(sni);
				}
				const mapping = await collectFingerprints(hosts, env, forceRefresh);
				if (!addSingBoxPins(config, mapping, certificateMode)) return buildResponse(response, originalText);
				return buildResponse(response, JSON.stringify(config, null, 2));
			} catch (error) {
				console.warn('[TLSFP] Sing-box subscription patch failed:', error?.message || error);
				return buildResponse(response, originalText);
			}
		}

		if (target && target !== 'mixed') return buildResponse(response, originalText);
		let mixedText = originalText;
		let wasBase64 = false;
		if (!/^(?:vless|trojan|ss):\/\//im.test(mixedText.trim())) {
			try {
				const decoded = atob(mixedText.trim().replace(/\s+/g, ''));
				if (/(?:^|\n)(?:vless|trojan|ss):\/\//im.test(decoded)) {
					mixedText = decoded;
					wasBase64 = true;
				}
			} catch { }
		}
		if (!/(?:^|\n)(?:vless|trojan):\/\//im.test(mixedText)) return buildResponse(response, originalText);

		const hosts = [];
		for (const line of mixedText.split(/\r?\n/)) {
			if (!/^(?:vless|trojan):\/\//i.test(line.trim())) continue;
			try {
				const node = new URL(line.trim());
				if ((node.searchParams.get('security') || (node.protocol === 'trojan:' ? 'tls' : '')).toLowerCase() === 'tls') {
					hosts.push(node.searchParams.get('sni') || node.hostname);
				}
			} catch { }
		}
		const mapping = await collectFingerprints(hosts, env, forceRefresh);
		const result = addXrayPins(mixedText, mapping, forceRefresh);
		if (!result.changed) return buildResponse(response, originalText);
		return buildResponse(response, wasBase64 ? btoa(result.text) : result.text);
	}
};
