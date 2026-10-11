import test from 'node:test';
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { normalizeAmneziaDomain } from '../../src/core/amnezia.js';
import { applyAwgOptions, WARP_IPS, WARP_PORTS } from '../../workers/api/src/awg-options.js';
import { generateWarpProfile, fetchAmneziaConfig, API_PREFIXES, generateWireGuardKeys, readBoundedJson } from '../../workers/api/src/warp.js';
import { fetchDomainSignature } from '../../workers/api/src/signature.js';
import { handleAmnezia } from '../../workers/api/src/amnezia.js';

export const ID = '01234567-89ab-cdef-0123-456789abcdef';
export const TOKEN = 'opaque-token-not-necessarily-a-uuid';
export const fixture = (enabled = true) => ({
    id: ID, token: TOKEN, warp_enabled: enabled, account: { account_type: 'free', warp_plus: false },
    config: { interface: { addresses: { v4: '172.16.0.2', v6: '2606:4700:110::123' } }, peers: [{ public_key: Buffer.alloc(32, 7).toString('base64') }] },
});
export const signaturePayload = (domain = 'example.com') => ({ ok: true, domain, i1: '<b 0x0102>', i2: '<b 0x0304>', i3: '<b 0x0506>', i4: '<b 0x0708>', i5: '<b 0x090a>' });
const field = (content, name) => content.match(new RegExp(`^${name} = (.+)$`, 'm'))?.[1];
const fake = (fn = () => Response.json(fixture())) => {
    const calls = [];
    const signatures = [];
    const fetch = async (url, init) => {
        if (String(url).startsWith('https://junk.web2core.workers.dev/signature?')) {
            const domain = new URL(url).searchParams.get('domain');
            signatures.push(domain);
            return Response.json(signaturePayload(domain));
        }
        calls.push({ url, ...init }); return fn(url, init, calls.length);
    };
    return { fetch, calls, signatures };
};

test('domain validation retains IDN support and rejects configuration injection', () => {
    assert.equal(normalizeAmneziaDomain(' Example.COM. '), 'example.com');
    assert.equal(normalizeAmneziaDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
    for (const value of ['https://example.com', 'example.com:443', 'example.com/path', 'a@b.com', '127.0.0.1', '[::1]', 'localhost', '-a.com', 'a..com', 'a'.repeat(64) + '.com', 'a.com\nPrivateKey = bad']) assert.throws(() => normalizeAmneziaDomain(value));
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
    else for (let i = 1; i <= 5; i++) assert.equal(field(content, `I${i}`), signaturePayload()[`i${i}`]);
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
    assert.deepEqual(Object.keys(first).sort(), ['content', 'domain', 'filename', 'version']); assert(!JSON.stringify(first).includes(TOKEN));
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
test('bounded streaming JSON rejects oversized responses without trusting Content-Length', async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(270000)); }, cancel() { cancelled = true; } }));
    await assert.rejects(readBoundedJson(response), /oversized/); assert(cancelled);
    await assert.rejects(readBoundedJson(new Response('not JSON')), /invalid JSON/);
});
test('section-aware overlays preserve peer/keys, CRLF and do not duplicate timer fields', async () => {
    const base = await fetchAmneziaConfig('3.1', fake().fetch);
    const options = { version: '3.1' };
    const packets = Object.values(signaturePayload()).slice(2);
    const content = applyAwgOptions(applyAwgOptions(base.replace(/\n/g, '\r\n'), options, packets), options, packets);
    assert.doesNotMatch(content, /(?<!\r)\n/);
    assert.equal((content.match(/^RekeyAfterTime =/gm) || []).length, 1);
    assert.equal(field(content, 'PrivateKey'), field(base, 'PrivateKey'));
    assert.equal((content.match(/^Endpoint =/gm) || []).length, 1);
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
test('handler validates media type, JSON, body size and version', async () => {
    assert.equal((await handleAmnezia(request({}, { 'Content-Type': 'text/plain' }), {})).status, 415);
    assert.equal((await handleAmnezia(request({ version: '3' }), {})).status, 400);
    assert.equal((await handleAmnezia(request({ data: 'a'.repeat(65536) }), {})).status, 413);
});
test('handler returns an error with no-store/CORS before registration when capture fails', async () => {
    const originalFetch = globalThis.fetch;
    const mocked = fake(); globalThis.fetch = mocked.fetch;
    try {
        const response = await handleAmnezia(request({ version: '3.1', domain: 'example.com' }), { 'Access-Control-Allow-Origin': 'https://web2core.workers.dev' }, { JUNK: { fetch: async () => new Response(null, { status: 422 }) } });
        assert.equal(response.status, 502); assert.equal(response.headers.get('Cache-Control'), 'no-store'); assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://web2core.workers.dev');
        assert.equal(mocked.calls.length, 0);
        const result = await response.json(); assert.equal(result.content, undefined); assert.match(result.error, /Signature service/);
    } finally { globalThis.fetch = originalFetch; }
});
test('handler applies domain packets but skips capture for AWG 1.5', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = fake().fetch;
    let captureCalls = 0;
    const env = { JUNK: { fetch: async () => { captureCalls++; return Response.json(signaturePayload()); } } };
    try {
        const response = await handleAmnezia(request({ version: '2.0', domain: 'example.com' }), {}, env);
        const result = await response.json(); assert.equal(result.signatureApplied, true); assert.equal(field(result.content, 'I1'), '<b 0x0102>');
        const plain = await handleAmnezia(request({ version: '1.5', domain: 'example.com' }), {}, env);
        assert.equal(captureCalls, 1); const legacy = await plain.json(); assert.equal(legacy.filename, 'amnezia-awg-1.5.conf'); assert.equal(legacy.signatureApplied, false); assert.doesNotMatch(legacy.content, /^I[1-5] =/m);
    } finally { globalThis.fetch = originalFetch; }
});
test('handler enforces its per-IP request limit', async () => {
    const originalFetch = globalThis.fetch; globalThis.fetch = fake().fetch;
    try {
        for (let i = 0; i < 10; i++) assert.equal((await handleAmnezia(request({ version: '2.0' }, { 'CF-Connecting-IP': '198.51.100.99' }), {})).status, 200);
        assert.equal((await handleAmnezia(request({ version: '2.0' }, { 'CF-Connecting-IP': '198.51.100.99' }), {})).status, 429);
    } finally { globalThis.fetch = originalFetch; }
});

test('requests only use version and domain; removed settings cannot alter the profile', async () => {
    const { fetch, calls } = fake();
    const result = await generateWarpProfile({ version: '2.0', options: { transport: 'none', license_key: 'unused' }, registrationCache: 'unused' }, fetch);
    assert.equal(calls.length, 1);
    assert.match(result.content, /^Jc = 4$/m);
    assert(!JSON.stringify(calls).includes('unused'));
    assert(!JSON.stringify(result).includes(TOKEN));
});
test('invalid version fails before registration', async () => {
    const { fetch, calls } = fake();
    await assert.rejects(generateWarpProfile({ version: '3' }, fetch), e => e.status === 400);
    assert.equal(calls.length, 0);
});

for (const domain of [undefined, '', '   ']) test(`empty domain (${JSON.stringify(domain)}) captures github.com without changing packet bytes`, async () => {
    const mocked = fake();
    const result = await generateWarpProfile({ version: '2.0', domain }, mocked.fetch);
    assert.deepEqual(mocked.signatures, ['github.com']);
    assert.equal(result.domain, 'github.com');
    for (let i = 1; i <= 5; i++) assert.equal(field(result.content, `I${i}`), signaturePayload()[`i${i}`]);
});
test('explicit domain is captured and AWG 1.5 does not request any packets', async () => {
    const mocked = fake();
    await generateWarpProfile({ version: '2.0', domain: 'example.com' }, mocked.fetch);
    await generateWarpProfile({ version: '1.5' }, mocked.fetch);
    assert.deepEqual(mocked.signatures, ['example.com']);
});
test('formatter refuses to fabricate missing I1-I5', () => {
    assert.throws(() => applyAwgOptions('[Interface]\n\n[Peer]\n', { version: '2.0' }), /Real I1-I5/);
});
