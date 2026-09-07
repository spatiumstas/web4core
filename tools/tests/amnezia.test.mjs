import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import { normalizeAmneziaDomain } from '../../src/core/amnezia.js';
import { generateTlsPayload } from '../../src/vendor/amnezia/tls.js';
import { generateAmneziaConfig } from '../../src/vendor/amnezia/warp.js';
import worker from '../../workers/api/dist/worker.mjs';

function readSni(packet) {
    assert.equal(packet[0], 0x16);
    assert.equal(packet.readUInt16BE(3), packet.length - 5);
    assert.equal(packet[5], 1);
    assert.equal(packet.readUIntBE(6, 3), packet.length - 9);
    let offset = 9 + 2 + 32;
    offset += 1 + packet[offset];
    offset += 2 + packet.readUInt16BE(offset);
    offset += 1 + packet[offset];
    const end = offset + 2 + packet.readUInt16BE(offset);
    assert.equal(end, packet.length);
    offset += 2;
    let hostname;
    while (offset < end) {
        const type = packet.readUInt16BE(offset);
        const size = packet.readUInt16BE(offset + 2);
        offset += 4;
        assert(offset + size <= end);
        if (type === 0) {
            assert.equal(packet.readUInt16BE(offset), size - 2);
            assert.equal(packet[offset + 2], 0);
            const length = packet.readUInt16BE(offset + 3);
            assert.equal(length, size - 5);
            hostname = packet.subarray(offset + 5, offset + 5 + length).toString('ascii');
        }
        offset += size;
    }
    return hostname;
}
const peerKey = Buffer.alloc(32, 1).toString('base64');
const config = { peers: [{ public_key: peerKey }], interface: { addresses: { v4: '172.16.0.2' } } };
function fakeCloudflare(calls) {
    return async (url, init) => {
        calls.push({ url, ...init });
        return Response.json(init.method === 'POST'
            ? { result: { id: 'test-id', token: 'test-token', config } }
            : { result: { config } });
    };
}

test('domain validation normalizes IDN and rejects URLs, IPs and config injection', () => {
    assert.equal(normalizeAmneziaDomain(' Example.COM. '), 'example.com');
    assert.equal(normalizeAmneziaDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
    for (const value of ['', 'https://example.com', 'example.com:443', 'example.com/path',
        'a@b.com', '127.0.0.1', '[::1]', 'localhost', '-a.com', 'a..com', 'a'.repeat(64)+'.com',
        'a.com\nPrivateKey = bad']) assert.throws(() => normalizeAmneziaDomain(value));
});

test('TLS lengths and SNI remain valid across random payloads and long domains', () => {
    const longDomain = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
    for (const domain of ['example.com', 'xn--e1afmkfd.xn--p1ai', longDomain]) {
        for (let i = 0; i < 20; i++) {
            const packet = generateTlsPayload(domain);
            assert(packet.length <= 1000);
            assert.equal(readSni(packet), domain);
        }
    }
    assert.notDeepEqual(generateTlsPayload('example.com'), generateTlsPayload('example.com'));
});

for (const version of ['1.5', '2.0']) test(`AWG ${version}: registration, keys and WARP-safe config`, async () => {
    const calls = [];
    const result = await generateAmneziaConfig({ version, domain: 'example.com' }, fakeCloudflare(calls));
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, 'https://api.cloudflareclient.com/v0i1909051800/reg');
    assert.equal(calls[1].headers.Authorization, 'Bearer test-token');
    assert.deepEqual(JSON.parse(calls[1].body), { warp_enabled: true });
    const fields = Object.fromEntries(result.content.split('\n').filter(x=>x.includes(' = ')).map(x=>x.split(' = ')));
    const derived = nacl.box.keyPair.fromSecretKey(Buffer.from(fields.PrivateKey, 'base64'));
    assert.equal(Buffer.from(derived.publicKey).toString('base64'), JSON.parse(calls[0].body).key);
    assert.equal(fields.PublicKey, peerKey);
    assert.equal(fields.Address, '172.16.0.2/32');
    assert.equal(fields.MTU, '1280');
    assert.equal(fields.AllowedIPs, '0.0.0.0/0');
    for (let n = 1; n <= 4; n++) assert.equal(fields['H'+n], String(n));
    for (let n = 1; n <= (version === '2.0' ? 4 : 2); n++) assert.equal(fields['S'+n], '0');
    if (version === '1.5') assert.equal(fields.S3, undefined);
    else { assert(Number(fields.Jmin) >= 64); assert(Number(fields.Jmax) > Number(fields.Jmin)); assert(Number(fields.Jmax) <= 1024); }
    assert.equal(readSni(Buffer.from(fields.I1.slice(5, -1), 'hex')), 'example.com');
    assert.equal(fields.i1, undefined);
    assert(!result.content.includes('test-token'));
    assert.equal(result.filename, `amnezia-awg-${version}.conf`);
});

test('invalid input never registers a device; upstream errors and malformed configs fail', async () => {
    let called = false;
    await assert.rejects(generateAmneziaConfig({ version: '3', domain: 'example.com' }, () => { called = true; }));
    assert.equal(called, false);
    await assert.rejects(generateAmneziaConfig({ version: '2.0', domain: 'example.com' }, async()=>new Response('', {status:429})), /ограничил/);
    await assert.rejects(generateAmneziaConfig({ version: '2.0', domain: 'example.com' }, async()=>Response.json({result:{id:'id',token:'token',config:{}}})), /неполную/);
});

test('Worker: CORS, body limits, validation and no-store responses', async () => {
    const request = (body, origin = 'https://web2core.workers.dev') => new Request('https://api.web2core.workers.dev/amnezia', {
        method:'POST', headers: {'Content-Type':'application/json', Origin:origin}, body:JSON.stringify(body),
    });
    assert.equal((await worker.fetch(request({}, 'https://untrusted.example'))).status, 403);
    assert.equal((await worker.fetch(request({ version:'3', domain:'example.com' }))).status, 400);
    assert.equal((await worker.fetch(request({ domain:'a'.repeat(2100) }))).status, 413);
    const originalFetch = globalThis.fetch;
    try {
        globalThis.fetch = fakeCloudflare([]);
        const response = await worker.fetch(request({ version:'2.0', domain:'example.com' }));
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('Cache-Control'), 'no-store');
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://web2core.workers.dev');
        assert((await response.json()).content.includes('I1 = <b 0x'));
    } finally { globalThis.fetch = originalFetch; }
});
