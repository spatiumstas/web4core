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
    lines.push('H1 = 1', 'H2 = 2', 'H3 = 3', 'H4 = 4',
        `I1 = <b 0x${generateTlsPayload(domain).toString('hex')}>`, '', '[Peer]',
        `PublicKey = ${peerKey}`, 'AllowedIPs = 0.0.0.0/0',
        'Endpoint = engage.cloudflareclient.com:4500', 'PersistentKeepalive = 25', '');
    return lines.join('\n');
}

export async function generateAmneziaConfig(body, fetchFn = fetch) {
    const { version, domain } = validateAmneziaRequest(body);
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
                ? 'Cloudflare ограничил запросы. Попробуйте позже.'
                : 'Не удалось получить конфигурацию от Cloudflare. Попробуйте позже.');
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
        if (!id || typeof token !== 'string' || !token) throw new Error('Некорректный ответ регистрации Cloudflare.');
        const activated = await request('PATCH', `reg/${encodeURIComponent(id)}`, { warp_enabled: true }, token);
        const config = activated.result?.config || initialConfig;
        const address = config?.interface?.addresses?.v4;
        const peerKey = config?.peers?.[0]?.public_key || FALLBACK_PEER;
        if (typeof address !== 'string' || !/^\d{1,3}(\.\d{1,3}){3}$/.test(address) ||
            address.split('.').some(n => Number(n) > 255) ||
            !/^[A-Za-z0-9+/]{43}=$/.test(peerKey) || !config?.peers?.length) {
            throw new Error('Cloudflare вернул неполную конфигурацию.');
        }
        return {
            content: buildAmneziaConfig({ version, domain, privateKey, peerKey, address }),
            filename: `amnezia-awg-${version}.conf`, version, domain,
        };
    } catch (error) {
        if (controller.signal.aborted) throw new Error('Cloudflare не ответил вовремя. Попробуйте ещё раз.');
        throw error;
    } finally { clearTimeout(timer); }
}
