// Client-held, authenticated encryption replaces Go's shared plaintext cache file.
export const CACHE_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const AAD = new TextEncoder().encode('web4core:warp-registration:v1');
const fail = (message, status = 400) => Object.assign(new Error(message), { status });
function encode(bytes) {
    return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decode(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw fail('Invalid registration cache.');
    return Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)), c => c.charCodeAt(0));
}
export async function cacheKey(secret) {
    if (!secret) return null;
    try {
        if (typeof secret !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(secret)) throw new Error();
        const bytes = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
        if (bytes.length !== 32) throw new Error();
        return await crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
    } catch { throw fail('Registration caching is misconfigured.', 500); }
}
export async function sealRegistration(record, key) {
    if (!key) return null;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(record));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: AAD }, key, data));
    const bytes = new Uint8Array(iv.length + encrypted.length);
    bytes.set(iv); bytes.set(encrypted, iv.length);
    return `v1.${encode(bytes)}`;
}
export async function openRegistration(token, key, now = Date.now()) {
    if (!key) throw fail('Registration caching is unavailable; request a fresh registration.');
    try {
        if (typeof token !== 'string' || token.length > 16384 || !token.startsWith('v1.')) throw new Error();
        const bytes = decode(token.slice(3));
        if (bytes.length < 29) throw new Error();
        const data = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: AAD }, key, bytes.slice(12));
        const record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data));
        if (!Number.isFinite(record.savedAt) || record.savedAt > now + 300000) throw new Error();
        if (now - record.savedAt >= CACHE_TTL_MS) return null;
        if (!record.keys || !record.registration || typeof record.prefix !== 'string') throw new Error();
        return record;
    } catch { throw fail('Invalid registration cache; request a fresh registration.'); }
}
export async function licenseFingerprint(license) {
    if (!license) return '';
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(license));
    return encode(new Uint8Array(digest));
}
