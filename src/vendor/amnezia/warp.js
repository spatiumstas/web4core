/*! SPDX-License-Identifier: AGPL-3.0-only
 * Derived from https://github.com/HereIamGosu/amnezia-config-gen
 * Copyright HereIamGosu and contributors. See src/vendor/amnezia/NOTICE.md.
 */
// Adapted from HereIamGosu/amnezia-config-gen/api/warp.js; see NOTICE.md.
import nacl from 'tweetnacl';
import { Buffer } from 'buffer';
import { generateTlsPayload, randomInt } from './tls.js';
import { validateAmneziaRequest } from '../../core/amnezia.js';

const API = 'https://api.cloudflareclient.com/v0i1909051800/';
const DEFAULT_CPS_DOMAINS = ['www.google.com', 'cloudflare.com', 'discord.com', 'api.telegram.org', 'youtube.com'];
const FALLBACK_PEER = 'bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=';

export function buildAmneziaConfig({ version, domain, privateKey, peerKey, address }) {
    const jmin = version === '2.0' ? randomInt(64, 513) : 23;
    const lines = [
        '[Interface]', `PrivateKey = ${privateKey}`, `Address = ${address}/32`,
        'DNS = 1.1.1.1, 1.0.0.1', 'MTU = 1280',
        `Jc = ${version === '2.0' ? randomInt(1, 26) : 120}`,
        `Jmin = ${jmin}`, `Jmax = ${version === '2.0' ? randomInt(jmin + 1, 1025) : 911}`,
        'S1 = 0', 'S2 = 0',
    ];
    if (version === '2.0') lines.push('S3 = 0', 'S4 = 0');
    // Cloudflare is a stock WireGuard peer: retain packet types 1..4 and zero padding.
    lines.push('H1 = 1', 'H2 = 2', 'H3 = 3', 'H4 = 4');
    // Both AWG 1.5 and 2.0 support I1–I5. Each packet has its own TLS
    // randomness, while SNI consistently uses the requested/selected domain.
    for (let index = 1; index <= 5; index++) {
        lines.push(`I${index} = <b 0x${generateTlsPayload(domain).toString('hex')}>`);
    }
    lines.push('', '[Peer]',
        `PublicKey = ${peerKey}`, 'AllowedIPs = 0.0.0.0/0',
        'Endpoint = engage.cloudflareclient.com:4500', 'PersistentKeepalive = 25', '');
    return lines.join('\n');
}

export async function generateAmneziaConfig(body, fetchFn = fetch) {
    const { version, domain: requestedDomain } = validateAmneziaRequest(body);
    const domain = requestedDomain || DEFAULT_CPS_DOMAINS[randomInt(0, DEFAULT_CPS_DOMAINS.length)];
    const keys = nacl.box.keyPair.fromSecretKey(crypto.getRandomValues(new Uint8Array(32)));
    const privateKey = Buffer.from(keys.secretKey).toString('base64');
    const publicKey = Buffer.from(keys.publicKey).toString('base64');
    // One deadline covers registration, activation, and response body reads.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    async function request(method, path, payload, token) {
        const response = await fetchFn(API + path, {
            method, signal: controller.signal, redirect: 'error',
            headers: { 'Content-Type': 'application/json', 'User-Agent': 'okhttp/3.12.1',
                ...(token ? { Authorization: `Bearer ${token}` } : {}) },
            ...(payload ? { body: JSON.stringify(payload) } : {}),
        });
        if (!response.ok) {
            const error = new Error(response.status === 429
                ? 'Cloudflare rate limit reached. Please try again later.'
                : 'Could not retrieve the configuration from Cloudflare. Please try again later.');
            error.status = response.status === 429 ? 429 : 502;
            throw error;
        }
        return response.json();
    }
    try {
        const registration = await request('POST', 'reg', {
            install_id: '', tos: new Date().toISOString(), key: publicKey,
            fcm_token: '', type: 'ios', locale: 'en_US',
        });
        const { id, token, config: initialConfig } = registration.result || {};
        if (!id || typeof token !== 'string' || !token) throw new Error('Invalid registration response from Cloudflare.');
        const activated = await request('PATCH', `reg/${encodeURIComponent(id)}`, { warp_enabled: true }, token);
        const config = activated.result?.config || initialConfig;
        const address = config?.interface?.addresses?.v4;
        const peerKey = config?.peers?.[0]?.public_key || FALLBACK_PEER;
        if (typeof address !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(address) ||
            address.split('.').some(n => Number(n) > 255) ||
            !/^[A-Za-z0-9+/]{43}=$/.test(peerKey) || !config?.peers?.length) {
            throw new Error('Cloudflare returned an incomplete configuration.');
        }
        return {
            content: buildAmneziaConfig({ version, domain, privateKey, peerKey, address }),
            filename: `amnezia-awg-${version}.conf`, version, domain,
        };
    } catch (error) {
        if (controller.signal.aborted) throw new Error('Cloudflare request timed out. Please try again.');
        throw error;
    } finally { clearTimeout(timer); }
}
