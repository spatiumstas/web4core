import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAmneziaDomain, validateAmneziaRequest } from '../../src/core/amnezia.js';
import { applyAwgOptions } from '../../workers/api/src/awg-options.js';
import { fetchDomainSignature } from '../../workers/api/src/signature.js';
import { applyCpsPackets, fetchAmneziaConfig } from '../../workers/api/src/warp.js';
import worker from '../../workers/api/dist/worker.mjs';

const upstreamConfig = `[Interface]
PrivateKey = private-key
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280
Jc = 3
Jmin = 64
Jmax = 128
S1 = 0
S2 = 0
S3 = 0
S4 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0xdeadbeef>

[Peer]
PublicKey = peer-key
AllowedIPs = 0.0.0.0/0
Endpoint = engage.cloudflareclient.com:4500
`;

function signaturePayload(domain = 'example.com') {
    return {
        ok: true, domain,
        i1: '<b 0x0102>', i2: '<b 0x0304>', i3: '<b 0x0506>',
        i4: '<b 0x0708>', i5: '<b 0x090a>',
    };
}

function upstreamPayload(config = upstreamConfig) {
    return { success: true, content: Buffer.from(config).toString('base64') };
}

function assertSignaturePackets(content) {
    for (let index = 1; index <= 5; index++) {
        const hex = `${(index * 2 - 1).toString(16).padStart(2, '0')}${(index * 2).toString(16).padStart(2, '0')}`;
        assert.match(content, new RegExp(`^I${index} = <b 0x${hex}>$`, 'm'));
    }
    assert.doesNotMatch(content, /deadbeef/);
}

test('domain validation normalizes IDN and rejects URLs, IPs and config injection', () => {
    assert.equal(normalizeAmneziaDomain(' Example.COM. '), 'example.com');
    assert.equal(normalizeAmneziaDomain('пример.рф'), 'xn--e1afmkfd.xn--p1ai');
    for (const value of ['https://example.com', 'example.com:443', 'example.com/path',
        'a@b.com', '127.0.0.1', '[::1]', 'localhost', '-a.com', 'a..com', 'a'.repeat(64)+'.com',
        'a.com\nPrivateKey = bad']) assert.throws(() => normalizeAmneziaDomain(value));
});

test('signature service validates all packets and binds them to the requested domain', async () => {
    const packets = await fetchDomainSignature('example.com', async (url, init) => {
        assert.equal(url, 'https://junk.web2core.workers.dev/signature?domain=example.com');
        assert.equal(init.headers.Accept, 'application/json');
        return Response.json(signaturePayload());
    });
    assert.deepEqual(packets, Object.values(signaturePayload()).slice(2));
    await assert.rejects(fetchDomainSignature('example.com', async () => Response.json(signaturePayload('other.example'))), /another domain/);
});

for (const [version, mode] of [['1.5', 'legacy'], ['2.0', 'awg2'], ['3.0', 'awg2'], ['3.1', 'awg2']]) test(`external Amnezia API uses ${mode} mode for AWG ${version}`, async () => {
    const config = await fetchAmneziaConfig(version, async (url, init) => {
        assert.equal(url, 'https://valokda-amnezia.vercel.app/api/warp');
        assert.equal(init.method, 'POST');
        assert.deepEqual(JSON.parse(init.body), { mode });
        return Response.json(upstreamPayload());
    });
    assert.equal(config, upstreamConfig);
});

function assertOnlyEndpointChanged(content) {
    assert.match(content, /^Endpoint = 162\.159\.(192|195)\.([1-9]|10):(500|1701|2408|4500)$/m);
    assert.equal(content.replace(/^Endpoint = .+$/m, 'Endpoint = engage.cloudflareclient.com:4500'), upstreamConfig);
}

test('AWG overlays preserve keys and sections, keep timers ordered and replace fields once', () => {
    for (const version of ['1.5', '2.0']) assertOnlyEndpointChanged(applyAwgOptions(upstreamConfig, { version }));
    for (const version of ['3.0', '3.1']) {
        for (let i = 0; i < 50; i++) {
            const options = validateAmneziaRequest({ version });
            const config = applyAwgOptions(applyAwgOptions(upstreamConfig, options), options);
            const [iface, peer] = config.split('[Peer]');
            const value = key => iface.match(new RegExp(`^${key} = (.+)$`, 'm'))[1];
            const rekey = value('RekeyAfterTime').split('-').map(Number);
            const reject = value('RejectAfterTime').split('-').map(Number);
            assert(rekey[0] <= rekey[1] && rekey[1] < reject[0] && reject[0] <= reject[1]);
            assert.equal((iface.match(/^ContentPaddingAddition =/gm) || []).length, 1);
            assert.match(iface, /^PrivateKey = private-key$/m);
            assert.doesNotMatch(iface, /HeaderProtectionKey|Endpoint =/);
            assert.match(peer, /^PublicKey = peer-key$/m);
            assert.match(peer, /^Endpoint = 162\.159\.(192|195)\.([1-9]|10):(500|1701|2408|4500)$/m);
            assert.equal((peer.match(/^Endpoint =/gm) || []).length, 1);
            if (version === '3.1') {
                assert.equal(value('RandomTrailers'), 'on');
                assert.equal(value('DisableCookies'), 'on');
            } else assert.doesNotMatch(iface, /RandomTrailers|DisableCookies/);
        }
    }
    const crlf = applyAwgOptions(upstreamConfig.replace(/\n/g, '\r\n'), { version: '3.1' });
    assert.doesNotMatch(crlf, /(?<!\r)\n/);
});

test('external Amnezia API rejects failed and malformed upstream responses', async () => {
    await assert.rejects(
        fetchAmneziaConfig('2.0', async () => Response.json({ success: false, message: 'upstream rejected request' }, { status: 429 })),
        /upstream rejected request/,
    );
    await assert.rejects(
        fetchAmneziaConfig('2.0', async () => Response.json(upstreamPayload('not an AWG config'))),
        /invalid configuration/,
    );
});

test('real signature packets replace the external generator CPS chain without changing the rest of its config', () => {
    const result = applyCpsPackets(upstreamConfig, Object.values(signaturePayload()).slice(2));
    assertSignaturePackets(result);
    assert.match(result, /^Endpoint = engage\.cloudflareclient\.com:4500$/m);
    assert.equal(applyCpsPackets(upstreamConfig, null), upstreamConfig);
});

test('Worker: CORS, body limits, external config generation and no-store responses', async () => {
    const request = (body, origin = 'https://web2core.workers.dev') => new Request('https://api.web2core.workers.dev/amnezia', {
        method:'POST', headers: {'Content-Type':'application/json', Origin:origin}, body:JSON.stringify(body),
    });
    assert.equal((await worker.fetch(request({}, 'https://untrusted.example'))).status, 403);
    const preflight = await worker.fetch(new Request('https://api.web2core.workers.dev/amnezia', {
        method: 'OPTIONS', headers: { Origin: 'https://spatiumstas.github.io' },
    }));
    assert.equal(preflight.status, 204);
    assert.equal(preflight.headers.get('Access-Control-Allow-Origin'), 'https://spatiumstas.github.io');
    const workersSubdomain = await worker.fetch(new Request('https://api.web2core.workers.dev/amnezia', {
        method: 'OPTIONS', headers: { Origin: 'https://preview.web2core.workers.dev' },
    }));
    assert.equal(workersSubdomain.status, 204);
    assert.equal(workersSubdomain.headers.get('Access-Control-Allow-Origin'), 'https://preview.web2core.workers.dev');
    assert.equal((await worker.fetch(request({ version:'3', domain:'example.com' }))).status, 400);
    assert.equal((await worker.fetch(request({ domain:'a'.repeat(2100) }))).status, 413);
    const originalFetch = globalThis.fetch;
    try {
        globalThis.fetch = async (url) => {
            const target = String(url);
            if (target === 'https://valokda-amnezia.vercel.app/api/warp') return Response.json(upstreamPayload());
            throw new Error(`Unexpected fetch target: ${target}`);
        };
        const response = await worker.fetch(request({ version:'2.0', domain:'example.com' }), {
            JUNK: { fetch: async (signatureRequest) => {
                assert.match(signatureRequest.url, /^https:\/\/junk\.web2core\.workers\.dev\/signature\?/);
                return Response.json(signaturePayload());
            } },
        });
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('Cache-Control'), 'no-store');
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://web2core.workers.dev');
        assertSignaturePackets((await response.json()).content);
    } finally { globalThis.fetch = originalFetch; }
});

test('Worker applies AWG 3.1 and endpoint options even when signature capture fails', async () => {
    const originalFetch = globalThis.fetch;
    try {
        globalThis.fetch = async (url, init) => {
            assert.equal(url, 'https://valokda-amnezia.vercel.app/api/warp');
            assert.deepEqual(JSON.parse(init.body), { mode: 'awg2' });
            return Response.json(upstreamPayload());
        };
        const response = await worker.fetch(new Request('https://api.web2core.workers.dev/amnezia', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '192.0.2.31' },
            body: JSON.stringify({ version: '3.1', domain: 'example.com' }),
        }), { JUNK: { fetch: async () => new Response(null, { status: 422 }) } });
        assert.equal(response.status, 200);
        const result = await response.json();
        assert.equal(result.signatureApplied, false);
        assert.equal(result.filename, 'amnezia-awg-3.1.conf');
        assert.match(result.content, /^RandomTrailers = on$/m);
        assert.match(result.content, /^DisableCookies = on$/m);
        assert.match(result.content, /^I1 = <b 0xdeadbeef>$/m);
        assert.match(result.content, /^Endpoint = 162\.159\./m);
        assert.match(result.content, /^PrivateKey = private-key$/m);
    } finally { globalThis.fetch = originalFetch; }
});

test('Worker falls back to the Valokda profile when the signature service rejects a domain', async () => {
    const createRequest = () => new Request('https://api.web2core.workers.dev/amnezia', {
        method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://web2core.workers.dev' },
        body: JSON.stringify({ version: '2.0', domain: 'example.com' }),
    });
    const originalFetch = globalThis.fetch;
    try {
        globalThis.fetch = async (url) => {
            if (String(url) === 'https://valokda-amnezia.vercel.app/api/warp') return Response.json(upstreamPayload());
            throw new Error(`Unexpected fetch target: ${url}`);
        };
        const response = await worker.fetch(createRequest(), {
            JUNK: { fetch: async () => Response.json({ error: 'No signature for this domain' }, { status: 422 }) },
        });
        assert.equal(response.status, 200);
        assertOnlyEndpointChanged((await response.json()).content);

        const withoutBinding = await worker.fetch(createRequest(), {});
        assert.equal(withoutBinding.status, 200);
        assertOnlyEndpointChanged((await withoutBinding.json()).content);
    } finally { globalThis.fetch = originalFetch; }
});
