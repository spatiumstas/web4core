import { validateAmneziaRequest } from '../../../src/core/amnezia.js';
import { isIPv4, isIPv6 } from '../../../src/core/warp-options.js';
import { randomHex } from '../../../src/core/warp-cps.js';
import { applyAwgOptions, setConfigFields } from './awg-options.js';
import { cacheKey, openRegistration, sealRegistration, licenseFingerprint } from './warp-cache.js';

// Registration request and prefix list ported from Skiro1/warp-awg-gen (MIT).
export const API_PREFIXES = Object.freeze(['v0i1909051800', 'v0a1909051800', 'v0b1909051800', 'v0c1909051800', 'v0d1909051800', 'v0e1909051800', 'v0f1909051800', 'v0g1909051800', 'v0h1909051800', 'v0i1604021500', 'v0a1604021500']);
const API = 'https://api.cloudflareclient.com';
const MAX_RESPONSE_BYTES = 256 * 1024;
const HEADERS = { Accept: 'application/json', 'Content-Type': 'application/json', 'User-Agent': 'okhttp/3.12.1' };
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fail = (message, status = 502) => Object.assign(new Error(message), { status });
const urlFor = (prefix, id = '') => `${API}/${prefix}/reg${id ? `/${id}` : ''}`;

export async function readBoundedJson(response) {
    if (Number(response.headers.get('Content-Length')) > MAX_RESPONSE_BYTES) {
        await response.body?.cancel();
        throw fail('Cloudflare returned an oversized response.');
    }
    const reader = response.body?.getReader();
    if (!reader) throw fail('Cloudflare returned an empty response.');
    const chunks = [];
    let size = 0;
    try {
        while (true) {
            const { value, done } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > MAX_RESPONSE_BYTES) {
                await reader.cancel();
                throw fail('Cloudflare returned an oversized response.');
            }
            chunks.push(value);
        }
    } finally { reader.releaseLock(); }
    const data = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { data.set(chunk, offset); offset += chunk.length; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)); }
    catch { throw fail('Cloudflare returned invalid JSON.'); }
}
function unwrap(payload) {
    if (!payload || typeof payload !== 'object' || payload.success === false) throw fail('Cloudflare rejected the WARP request.');
    const value = Object.hasOwn(payload, 'result') ? payload.result : payload;
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw fail('Cloudflare returned an invalid WARP profile.');
    return value;
}
function credentials(payload) {
    if (!UUID.test(payload?.id || '') || typeof payload?.token !== 'string' || !/^[A-Za-z0-9._~+/=-]{8,2048}$/.test(payload.token)) {
        throw fail('Cloudflare returned invalid registration credentials.');
    }
    return { id: payload.id, token: payload.token };
}
function key32(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(value)) throw fail('Cloudflare returned an invalid WireGuard key.');
    const decoded = atob(value);
    if (decoded.length !== 32 || btoa(decoded) !== value || ![...decoded].some(c => c.charCodeAt(0))) throw fail('Cloudflare returned an invalid WireGuard key.');
    return value;
}
export async function generateWireGuardKeys() {
    try {
        const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
        const decode = value => Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
        const privateBytes = decode(jwk.d);
        // X25519 already clamps during scalar multiplication; export the WG form.
        privateBytes[0] &= 248; privateBytes[31] &= 127; privateBytes[31] |= 64;
        return { privateKey: key32(btoa(String.fromCharCode(...privateBytes))), publicKey: key32(btoa(String.fromCharCode(...decode(jwk.x)))) };
    } catch { throw fail('Could not generate WireGuard keys.'); }
}
function readRegistration(payload) {
    const config = payload?.config;
    const peer = Array.isArray(config?.peers) ? config.peers[0] : null;
    const address = (value, validate, prefix) => {
        if (typeof value !== 'string') throw fail('Cloudflare returned invalid WARP addresses.');
        const parts = value.split('/');
        if (parts.length > 2 || !validate(parts[0]) || (parts.length === 2 && parts[1] !== String(prefix))) throw fail('Cloudflare returned invalid WARP addresses.');
        return `${parts[0]}/${prefix}`;
    };
    return {
        ...credentials(payload),
        ipv4: address(config?.interface?.addresses?.v4, isIPv4, 32),
        ipv6: address(config?.interface?.addresses?.v6, isIPv6, 128),
        publicKey: key32(peer?.public_key),
        warpEnabled: payload.warp_enabled === true,
        accountType: typeof payload.account?.account_type === 'string' ? payload.account.account_type : 'unknown',
        warpPlus: payload.account?.warp_plus === true || ['unlimited', 'plus'].includes(payload.account?.account_type),
    };
}
async function requestApi(fetchFn, prefix, method, id, token, body, signal, allowMissing = false) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal.aborted) abort(); else signal.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(abort, 5000);
    try {
        const response = await fetchFn(urlFor(prefix, id), {
            method, signal: controller.signal, redirect: 'manual',
            headers: { ...HEADERS, ...(token ? { Authorization: `Bearer ${token}` } : {}) },
            ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        // Only unsupported routes justify trying a different registration prefix.
        if (allowMissing && [404, 405].includes(response.status)) { await response.body?.cancel(); return null; }
        if (!response.ok) {
            await response.body?.cancel();
            throw fail(response.status === 429 ? 'Cloudflare WARP rate limit reached. Please try again later.' : `Cloudflare WARP ${method} failed (HTTP ${response.status}).`, response.status === 429 ? 429 : 502);
        }
        if (response.status === 204) return {};
        return unwrap(await readBoundedJson(response));
    } catch (error) {
        if (error?.status) throw error;
        throw fail(controller.signal.aborted ? 'Cloudflare WARP request timed out. Please try again.' : 'Could not reach Cloudflare WARP. Please try again.');
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); }
}
async function cleanup(fetchFn, prefix, auth) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);
    try {
        const response = await fetchFn(urlFor(prefix, auth.id), { method: 'DELETE', redirect: 'manual', signal: controller.signal, headers: { ...HEADERS, Authorization: `Bearer ${auth.token}` } });
        await response.body?.cancel();
    } catch { /* Best effort: never log credentials or overwrite the original error. */ }
    finally { clearTimeout(timer); }
}
export function applyCpsPackets(config, cpsPackets) {
    if (!cpsPackets) return config;
    return setConfigFields(config, 'Interface', Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`I${i + 1}`, cpsPackets[i] || null])));
}

export async function generateWarpProfile(input, fetchFn = fetch, env = {}, domainPackets = null) {
    let body;
    try { body = validateAmneziaRequest(input); } catch (error) { throw fail(error.message, 400); }
    const { version, options } = body;
    const encryptionKey = await cacheKey(env.WARP_CACHE_KEY);
    const licenseHash = await licenseFingerprint(options.license_key);
    let record = !body.freshRegistration && body.registrationCache ? await openRegistration(body.registrationCache, encryptionKey) : null;
    const cached = Boolean(record);
    if (record && options.license_key && record.licenseHash !== licenseHash) throw fail('Use a fresh registration when changing the WARP+ license.', 400);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 25000);
    let created = null;
    try {
        if (!record) {
            const keys = await generateWireGuardKeys();
            const request = { key: keys.publicKey, install_id: '', fcm_token: '', tos: new Date().toISOString(), model: 'PC', serial_number: randomHex(8), locale: 'en_US' };
            let payload, prefix;
            for (const candidate of API_PREFIXES) {
                payload = await requestApi(fetchFn, candidate, 'POST', '', '', request, controller.signal, true);
                if (payload) { prefix = candidate; break; }
            }
            if (!payload) throw fail('No supported Cloudflare WARP registration route was found.');
            const auth = credentials(payload);
            created = { prefix, auth };
            if (payload.warp_enabled !== true) {
                let activated = await requestApi(fetchFn, prefix, 'PATCH', auth.id, auth.token, { warp_enabled: true }, controller.signal);
                if (activated.warp_enabled === undefined) activated = await requestApi(fetchFn, prefix, 'GET', auth.id, auth.token, undefined, controller.signal);
                if (activated.warp_enabled !== true) throw fail('Cloudflare did not confirm WARP activation.');
                payload = { ...payload, ...activated, ...auth };
            }
            if (options.license_key) {
                await requestApi(fetchFn, prefix, 'PATCH', auth.id, auth.token, { license_key: options.license_key }, controller.signal);
                const updated = await requestApi(fetchFn, prefix, 'GET', auth.id, auth.token, undefined, controller.signal);
                payload = { ...payload, ...updated, ...auth };
                if (payload.account?.warp_plus !== true && !['unlimited', 'plus'].includes(payload.account?.account_type)) throw fail('Cloudflare did not confirm WARP+ activation.');
            }
            const registration = readRegistration(payload);
            if (!registration.warpEnabled) throw fail('Cloudflare did not confirm WARP activation.');
            record = { savedAt: Date.now(), keys, registration, prefix, licenseHash };
        }
        const { keys, registration } = record;
        if (!API_PREFIXES.includes(record.prefix) || !registration.warpEnabled) throw fail('Invalid cached registration; request a fresh registration.', 400);
        const base = `[Interface]\nPrivateKey = ${keys.privateKey}\nAddress = ${registration.ipv4}, ${registration.ipv6}\n\n[Peer]\nPublicKey = ${registration.publicKey}\nAllowedIPs = 0.0.0.0/0, ::/0\n`;
        const content = applyAwgOptions(base, body, await domainPackets);
        const warnings = [];
        if (options.transport !== 'none' && version === '3.1') warnings.push('AWG 3.1 uses experimental upstream options; importing a profile does not confirm WARP connectivity.');
        if (Object.entries(options.awg).some(([key, value]) => key.startsWith('s') ? value !== 0 : key.startsWith('h') && value !== key.slice(1))) warnings.push('Custom S/H parameters may be incompatible with Cloudflare WARP.');
        return {
            content, version, domain: body.domain,
            filename: options.transport === 'none' ? 'warp-wireguard.conf' : `amnezia-awg-${version}.conf`,
            registrationCache: await sealRegistration(record, encryptionKey),
            cached, endpointSelection: options.endpoint ? 'manual' : 'random',
            accountType: registration.accountType, warpPlus: registration.warpPlus, warnings,
        };
    } catch (error) {
        if (created) await cleanup(fetchFn, created.prefix, created.auth);
        if (error?.status) throw error;
        throw fail('Could not generate the Cloudflare WARP profile.');
    } finally { clearTimeout(timer); }
}

// Preserve the existing module API for callers which only need the .conf text.
export async function fetchAmneziaConfig(version, fetchFn = fetch, options = {}) {
    return (await generateWarpProfile({ version, options }, fetchFn)).content;
}
