import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { normalizeAmneziaDomain, validateAmneziaRequest } from '../../src/core/amnezia.js';
import { normalizeWarpOptions } from '../../src/core/warp-options.js';
import { WARP_CPS_PAYLOADS, generateCps, hexToCps, validateCps } from '../../src/core/warp-cps.js';
import { applyAwgOptions, WARP_IPS, WARP_PORTS, profileCps } from '../../workers/api/src/awg-options.js';
import { generateWarpProfile, fetchAmneziaConfig, API_PREFIXES, generateWireGuardKeys, readBoundedJson, applyCpsPackets } from '../../workers/api/src/warp.js';
import { cacheKey, sealRegistration, openRegistration, CACHE_TTL_MS } from '../../workers/api/src/warp-cache.js';
import { fetchDomainSignature } from '../../workers/api/src/signature.js';
import { handleAmnezia } from '../../workers/api/src/amnezia.js';

export const ID = '01234567-89ab-cdef-0123-456789abcdef';
export const TOKEN = 'opaque-token-not-necessarily-a-uuid';
export const CACHE_SECRET = Buffer.alloc(32, 42).toString('base64');
export const fixture = (enabled = true) => ({
    id: ID, token: TOKEN, warp_enabled: enabled, account: { account_type: 'free', warp_plus: false },
    config: { interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110::123' } }, peers: [{ public_key: Buffer.alloc(32, 7).toString('base64') }] },
});
export const signaturePayload = (domain = 'example.com') => ({ ok: true, domain, i1: '<b 0x0102>', i2: '<b 0x0304>', i3: '<b 0x0506>', i4: '<b 0x0708>', i5: '<b 0x090a>' });
const field = (content, name) => content.match(new RegExp(`^${name} = (.+)$`, 'm'))?.[1];
const fake = (fn = () => Response.json(fixture())) => {
    const calls = [];
    const fetch = async (url, init) => { calls.push({ url, ...init }); return fn(url, init, calls.length); };
    return { fetch, calls };
};

test('domain validation retains IDN support and rejects configuration injection', () => {
    assert.equal(normalizeAmneziaDomain(' Example.COM. '), 'example.com');
    assert.equal(normalizeAmneziaDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
    for (const value of ['https://example.com', 'example.com:443', 'example.com/path', 'a@b.com', '127.0.0.1', '[::1]', 'localhost', '-a.com', 'a..com', 'a'.repeat(64) + '.com', 'a.com\nPrivateKey = bad']) assert.throws(() => normalizeAmneziaDomain(value));
});

test('CPS capture bytes match the pinned upstream source', () => {
    assert.deepEqual(WARP_CPS_PAYLOADS.map(p => createHash('sha256').update(Buffer.from(p.slice(5, -1), 'hex')).digest('hex')), [
        '219b6fdcf5fafd0cd1d98a455a9a7a1346e0182348e501327989bbb708f6e10c',
        '197fc316d2d12815a788c90feea34cb42a28914e11c8d90afa53c0b1a30d161b',
        'd01ff54b78c380861512a96e9976a8f6815896621cdafebcc341b33fa570ea89',
    ]);
});
for (const mask of ['random', 'quic', 'dns', 'sip']) test(`CPS ${mask} alias preserves upstream capture/padding generation`, () => {
    for (let n = 0; n < 25; n++) {
        const packets = generateCps(mask);
        assert.equal(packets.length, 5);
        assert(WARP_CPS_PAYLOADS.includes(packets[0]));
        for (const packet of packets.slice(1)) {
            assert.equal(validateCps(packet), packet);
            const blocks = [...packet.matchAll(/<b 0x([0-9a-f]+)>/g)];
            assert(blocks.length >= 1 && blocks.length <= 3);
            assert(blocks.every(x => x[1].length >= 32 && x[1].length <= 126));
        }
    }
});
test('hex conversion accepts byte separators and rejects short, odd, oversized and prose input', () => {
    assert.equal(hexToCps('ab:'.repeat(32)), `<b 0x${'ab'.repeat(32)}>`);
    assert.equal(hexToCps('0x' + 'AB'.repeat(32)), `<b 0x${'ab'.repeat(32)}>`);
    for (const input of ['abc', 'a'.repeat(65), 'zz'.repeat(32), 'a'.repeat(8194), '<script>', '0000: ' + 'ab'.repeat(32) + '  ASCII']) assert.throws(() => hexToCps(input));
    assert.deepEqual(generateCps('none'), []);
});
test('custom CPS expressions cannot inject config fields or allocate unbounded packets', () => {
    for (const value of ['<r 32><t><b 0xaabb>', '']) assert.equal(validateCps(value), value);
    for (const value of ['<b 0xa>', '<r -1>', '<r 99999>', '<r 1>\nEndpoint = bad', '<b 0xab> garbage']) assert.throws(() => validateCps(value));
});
test('generator options validate all fields and preserve explicit zero/empty overrides', () => {
    const o = normalizeWarpOptions({ awg: { jc: 0 }, cps: { i1: '' }, keepalive: 0, endpoint: '[2606:4700::1]:2408' });
    assert.equal(o.awg.jc, 0); assert.equal(o.cps.i1, ''); assert.equal(o.keepalive, 0);
    for (const options of [{ mtu: 1 }, { dns: 'example.com' }, { endpoint: '1.2.3.4:0' }, { endpoint: '999.2.3.4:2408' }, { endpoint: 'x\nPostUp=bad' }, { awg: { jmin: 90, jmax: 70 } }, { awg: { h1: '1-4' } }, { cps: { i6: 'bad' } }, { random_trailers: 'on' }, { license_key: 'a\r\nb' }, { mask: 'unknown' }, { ignored: true }]) assert.throws(() => normalizeWarpOptions(options));
    assert.throws(() => validateAmneziaRequest({ version: '2.0', freshRegistration: 'yes' }));
});
test('exported private key is clamped and derives the transmitted X25519 public key', async () => {
    const keys = await generateWireGuardKeys();
    const bytes = Buffer.from(keys.privateKey, 'base64');
    assert.equal(bytes.length, 32); assert.equal(bytes[0] & 7, 0); assert.equal(bytes[31] & 128, 0); assert.equal(bytes[31] & 64, 64);
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), bytes]), format: 'der', type: 'pkcs8' });
    assert.equal(createPublicKey(privateKey).export({ format: 'jwk' }).x, Buffer.from(keys.publicKey, 'base64').toString('base64url'));
});
for (const version of ['1.5', '2.0', '3.0', '3.1']) test(`direct registration produces a version-scoped AWG ${version} profile`, async () => {
    const { fetch, calls } = fake();
    const content = await fetchAmneziaConfig(version, fetch);
    assert.equal(calls.length, 1);
    const request = calls[0];
    assert.equal(request.url, `https://api.cloudflareclient.com/${API_PREFIXES[0]}/reg`);
    assert.equal(request.method, 'POST'); assert.equal(request.redirect, 'manual');
    const sent = JSON.parse(request.body);
    assert.equal(sent.install_id, ''); assert.equal(sent.model, 'PC'); assert.match(sent.serial_number, /^[0-9a-f]{16}$/);
    assert.equal(sent.key.length, 44); assert(!request.body.includes(field(content, 'PrivateKey')));
    assert.equal(field(content, 'Address'), '172.16.0.2/32, 2606:4700:110::123/128');
    assert.equal(field(content, 'AllowedIPs'), '0.0.0.0/0, ::/0');
    assert.equal(field(content, 'Jc'), '4'); assert.equal(field(content, 'Jmin'), '40'); assert.equal(field(content, 'Jmax'), '70');
    assert.equal(field(content, 'H1'), '1'); assert.equal(field(content, 'S1'), '0'); assert.equal(field(content, 'S2'), '0');
    if (version === '1.5') assert.doesNotMatch(content, /^(S3|S4|I[1-5]) =/m);
    else assert(WARP_CPS_PAYLOADS.includes(field(content, 'I1')));
    if (version.startsWith('3.')) { assert.equal(field(content, 'RekeyAfterTime'), '100-120'); assert.equal(field(content, 'RejectAfterTime'), '150-180'); }
    else assert.doesNotMatch(content, /ContentPaddingAddition|RekeyAfterTime/);
    if (version === '3.1') { assert.equal(field(content, 'RandomTrailers'), 'on'); assert.equal(field(content, 'DisableCookies'), 'on'); }
    else assert.doesNotMatch(content, /RandomTrailers|DisableCookies/);
    const [ip, port] = field(content, 'Endpoint').split(':'); assert(WARP_IPS.includes(ip)); assert(WARP_PORTS.includes(Number(port)));
});
test('fresh generations never share private keys or plaintext registrations', async () => {
    const first = await generateWarpProfile({ version: '2.0' }, fake().fetch);
    const second = await generateWarpProfile({ version: '2.0' }, fake().fetch);
    assert.notEqual(field(first.content, 'PrivateKey'), field(second.content, 'PrivateKey'));
    assert.equal(first.registrationCache, null); assert(!JSON.stringify(first).includes(TOKEN));
});
test('wrapped responses and opaque bearer tokens are supported', async () => {
    const result = await generateWarpProfile({ version: '2.0' }, fake(() => Response.json({ success: true, result: fixture() })).fetch);
    assert.match(result.content, /^PrivateKey = /m);
});
test('prefix fallback only follows unsupported routes and activation uses the successful prefix', async () => {
    const { fetch, calls } = fake((url, init, count) => {
        if (count === 1) return new Response(null, { status: 404 });
        if (init.method === 'POST') return Response.json(fixture(false));
        assert.equal(url, `https://api.cloudflareclient.com/${API_PREFIXES[1]}/reg/${ID}`);
        assert.equal(init.headers.Authorization, `Bearer ${TOKEN}`);
        return Response.json({ warp_enabled: true });
    });
    await generateWarpProfile({ version: '2.0' }, fetch);
    assert.deepEqual(calls.map(x => x.method), ['POST', 'POST', 'PATCH']);
});
for (const status of [429, 500, 403, 302]) test(`registration HTTP ${status} is not retried`, async () => {
    const { fetch, calls } = fake(() => new Response('secret upstream error', { status }));
    await assert.rejects(generateWarpProfile({ version: '2.0' }, fetch), e => e.status === (status === 429 ? 429 : 502) && !e.message.includes('secret'));
    assert.equal(calls.length, 1);
});
test('ambiguous registration network failure never creates a second device', async () => {
    const { fetch, calls } = fake(() => { throw new Error('sensitive transport detail'); });
    await assert.rejects(generateWarpProfile({ version: '2.0' }, fetch), /Could not reach Cloudflare/);
    assert.equal(calls.length, 1);
});
test('activation with an empty response is confirmed by GET', async () => {
    const { fetch, calls } = fake((url, init) => init.method === 'POST' ? Response.json(fixture(false)) : init.method === 'PATCH' ? new Response(null, { status: 204 }) : Response.json({ warp_enabled: true }));
    await generateWarpProfile({ version: '2.0' }, fetch);
    assert.deepEqual(calls.map(x => x.method), ['POST', 'PATCH', 'GET']);
});
for (const failure of ['false', 'http', 'invalid-profile']) test(`failed activation/profile (${failure}) triggers best-effort cleanup`, async () => {
    const { fetch, calls } = fake((url, init) => {
        if (init.method === 'DELETE') return new Response(null, { status: 204 });
        if (init.method === 'POST') { const r = fixture(failure === 'invalid-profile'); if (failure === 'invalid-profile') r.config.peers = []; return Response.json(r); }
        return failure === 'http' ? new Response(null, { status: 500 }) : Response.json({ warp_enabled: false });
    });
    await assert.rejects(generateWarpProfile({ version: '2.0' }, fetch));
    assert.equal(calls.at(-1).method, 'DELETE');
    assert.equal(calls.at(-1).url, `https://api.cloudflareclient.com/${API_PREFIXES[0]}/reg/${ID}`);
});
test('WARP+ license application is confirmed and failure is not reported as success', async () => {
    const { fetch, calls } = fake((url, init) => {
        if (init.method === 'GET') return Response.json({ account: { warp_plus: true, account_type: 'unlimited' } });
        if (init.method === 'PATCH') { assert.deepEqual(JSON.parse(init.body), { license_key: 'test-license' }); return Response.json({}); }
        return Response.json(fixture());
    });
    const result = await generateWarpProfile({ version: '2.0', options: { license_key: 'test-license' } }, fetch);
    assert.equal(result.warpPlus, true); assert.deepEqual(calls.map(x => x.method), ['POST', 'PATCH', 'GET']);
    await assert.rejects(generateWarpProfile({ version: '2.0', options: { license_key: 'test-license' } }, fake().fetch), /did not confirm WARP\+/);
});
test('bounded streaming JSON rejects oversized responses without trusting Content-Length', async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(270000)); }, cancel() { cancelled = true; } }));
    await assert.rejects(readBoundedJson(response), /oversized/); assert(cancelled);
    await assert.rejects(readBoundedJson(new Response('not JSON')), /invalid JSON/);
});
test('invalid user options fail before registration', async () => {
    const { fetch, calls } = fake();
    await assert.rejects(generateWarpProfile({ version: '2.0', options: { endpoint: 'x\nPostUp=bad' } }, fetch), e => e.status === 400);
    assert.equal(calls.length, 0);
});
test('transport none really produces plain WireGuard; mask none disables automatic CPS only', async () => {
    const content = await fetchAmneziaConfig('3.1', fake().fetch, { transport: 'none', cps: { i1: '<r 32>' } });
    assert.doesNotMatch(content, /^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|RandomTrailers|DisableCookies|ContentPaddingAddition|RekeyAfterTime) =/m);
    assert.equal(field(content, 'AllowedIPs'), '0.0.0.0/0, ::/0');
    const noCps = await fetchAmneziaConfig('2.0', fake().fetch, { mask: 'none' });
    assert.doesNotMatch(noCps, /^I[1-5] =/m); assert.equal(field(noCps, 'Jc'), '4');
});
test('manual endpoint, zero settings, headers and AWG 3.1 opt-outs survive formatting', async () => {
    const content = await fetchAmneziaConfig('3.1', fake().fetch, { endpoint: '[2606:4700::1]:2408', keepalive: 0, awg: { jc: 0 }, random_trailers: false, disable_cookies: false });
    assert.equal(field(content, 'Endpoint'), '[2606:4700::1]:2408'); assert.equal(field(content, 'PersistentKeepalive'), '0');
    assert.equal(field(content, 'Jc'), '0'); assert.equal(field(content, 'RandomTrailers'), 'off'); assert.equal(field(content, 'DisableCookies'), 'off');
});
test('CPS precedence is builtin < domain < from_hex < explicit I override', () => {
    const domain = Object.values(signaturePayload()).slice(2);
    const options = normalizeWarpOptions({ from_hex: 'ab'.repeat(32), cps: { i2: '', i3: '<r 16>' } });
    const packets = profileCps('2.0', options, domain);
    assert.equal(packets[0], `<b 0x${'ab'.repeat(32)}>`); assert.equal(packets[1], ''); assert.equal(packets[2], '<r 16>'); assert.equal(packets[4], domain[4]);
    options.cps.i1 = '<r 32>'; assert.equal(profileCps('2.0', options, domain)[0], '<r 32>');
});
test('section-aware overlays preserve peer/keys, CRLF and do not duplicate timer fields', async () => {
    const base = await fetchAmneziaConfig('3.1', fake().fetch);
    const options = { version: '3.1', options: { endpoint: 'engage.cloudflareclient.com:2408' } };
    const content = applyAwgOptions(applyAwgOptions(base.replace(/\n/g, '\r\n'), options), options);
    assert.doesNotMatch(content, /(?<!\r)\n/);
    assert.equal((content.match(/^RekeyAfterTime =/gm) || []).length, 1);
    assert.equal(field(content, 'PrivateKey'), field(base, 'PrivateKey'));
    assert.equal((content.match(/^Endpoint =/gm) || []).length, 1);
    assert.equal(applyCpsPackets(base, null), base);
});
test('cache reuse is encrypted, client-held, expires after 90 days and fresh bypasses it', async () => {
    const env = { WARP_CACHE_KEY: CACHE_SECRET };
    const { fetch, calls } = fake();
    const first = await generateWarpProfile({ version: '2.0' }, fetch, env);
    assert(first.registrationCache.startsWith('v1.')); assert.equal(first.cached, false);
    assert(!first.registrationCache.includes(TOKEN)); assert(!first.registrationCache.includes(field(first.content, 'PrivateKey')));
    const second = await generateWarpProfile({ version: '3.1', registrationCache: first.registrationCache }, fetch, env);
    assert.equal(calls.length, 1); assert.equal(second.cached, true); assert.equal(field(first.content, 'PrivateKey'), field(second.content, 'PrivateKey'));
    const key = await cacheKey(CACHE_SECRET);
    const record = await openRegistration(first.registrationCache, key);
    assert.equal(await openRegistration(first.registrationCache, key, record.savedAt + CACHE_TTL_MS), null);
    const expired = await sealRegistration({ ...record, savedAt: Date.now() - CACHE_TTL_MS - 1 }, key);
    await generateWarpProfile({ version: '2.0', registrationCache: expired }, fetch, env); assert.equal(calls.length, 2);
    await generateWarpProfile({ version: '2.0', registrationCache: first.registrationCache, freshRegistration: true }, fetch, env); assert.equal(calls.length, 3);
});
test('tampered/cross-deployment cache and new license do not silently create registrations', async () => {
    const env = { WARP_CACHE_KEY: CACHE_SECRET };
    const first = await generateWarpProfile({ version: '2.0' }, fake().fetch, env);
    const { fetch, calls } = fake();
    await assert.rejects(generateWarpProfile({ version: '2.0', registrationCache: first.registrationCache.slice(0, 20) + (first.registrationCache[20] === 'A' ? 'B' : 'A') + first.registrationCache.slice(21) }, fetch, env), e => e.status === 400);
    await assert.rejects(generateWarpProfile({ version: '2.0', registrationCache: first.registrationCache }, fetch, { WARP_CACHE_KEY: Buffer.alloc(32, 43).toString('base64') }), e => e.status === 400);
    await assert.rejects(generateWarpProfile({ version: '2.0', registrationCache: first.registrationCache, options: { license_key: 'different' } }, fetch, env), /fresh registration/);
    assert.equal(calls.length, 0);
});
test('signature service validates all packets and binds them to the requested domain', async () => {
    const packets = await fetchDomainSignature('example.com', async (url, init) => {
        assert.equal(url, 'https://junk.web2core.workers.dev/signature?domain=example.com');
        assert.equal(init.redirect, 'manual'); return Response.json(signaturePayload());
    });
    assert.deepEqual(packets, Object.values(signaturePayload()).slice(2));
    await assert.rejects(fetchDomainSignature('example.com', async () => Response.json(signaturePayload('other.example'))), /another domain/);
});
let ipCounter = 10;
const request = (body, headers = {}) => new Request('https://api.web2core.workers.dev/amnezia', { method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': `192.0.2.${ipCounter++}`, ...headers }, body: JSON.stringify(body) });
test('handler validates media type, JSON, body size and generator settings', async () => {
    assert.equal((await handleAmnezia(request({}, { 'Content-Type': 'text/plain' }), {})).status, 415);
    assert.equal((await handleAmnezia(request({ version: '3' }), {})).status, 400);
    assert.equal((await handleAmnezia(request({ version: '2.0', options: { mtu: 0 } }), {})).status, 400);
    assert.equal((await handleAmnezia(request({ data: 'a'.repeat(65536) }), {})).status, 413);
});
test('handler preserves no-store/CORS and falls back to local CPS when signature fails', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fake().fetch;
    try {
        const response = await handleAmnezia(request({ version: '3.1', domain: 'example.com' }), { 'Access-Control-Allow-Origin': 'https://web2core.workers.dev' }, { JUNK: { fetch: async () => new Response(null, { status: 422 }) } });
        assert.equal(response.status, 200); assert.equal(response.headers.get('Cache-Control'), 'no-store'); assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://web2core.workers.dev');
        const result = await response.json(); assert.equal(result.signatureApplied, false); assert(WARP_CPS_PAYLOADS.includes(field(result.content, 'I1')));
    } finally { globalThis.fetch = originalFetch; }
});
test('handler applies domain packets but skips capture entirely for plain WireGuard', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fake().fetch;
    let captureCalls = 0;
    const env = { JUNK: { fetch: async () => { captureCalls++; return Response.json(signaturePayload()); } } };
    try {
        const response = await handleAmnezia(request({ version: '2.0', domain: 'example.com' }), {}, env);
        const result = await response.json(); assert.equal(result.signatureApplied, true); assert.equal(field(result.content, 'I1'), '<b 0x0102>');
        const plain = await handleAmnezia(request({ version: '3.1', domain: 'example.com', options: { transport: 'none' } }), {}, env);
        assert.equal(captureCalls, 1); assert.equal((await plain.json()).filename, 'warp-wireguard.conf');
    } finally { globalThis.fetch = originalFetch; }
});
test('handler enforces its per-IP request limit', async () => {
    const originalFetch = globalThis.fetch; globalThis.fetch = fake().fetch;
    try {
        for (let i = 0; i < 10; i++) assert.equal((await handleAmnezia(request({ version: '2.0' }, { 'CF-Connecting-IP': '198.51.100.99' }), {})).status, 200);
        assert.equal((await handleAmnezia(request({ version: '2.0' }, { 'CF-Connecting-IP': '198.51.100.99' }), {})).status, 429);
    } finally { globalThis.fetch = originalFetch; }
});
