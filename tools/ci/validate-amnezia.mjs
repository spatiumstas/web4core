// Unit tests run against the actual source; integration tests use the bundled Worker.
import './warp-generator.test.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { fixture, signaturePayload } from './warp-generator.test.mjs';
import worker from '../../workers/api/dist/worker.mjs';

const request = (body, origin = 'https://web2core.workers.dev') => new Request('https://api.web2core.workers.dev/amnezia', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Origin: origin, 'CF-Connecting-IP': '203.0.113.8' }, body: JSON.stringify(body),
});
test('bundled Worker preserves CORS allowlist and preflight handling', async () => {
    assert.equal((await worker.fetch(request({}, 'https://untrusted.example'))).status, 403);
    for (const origin of ['https://spatiumstas.github.io', 'https://preview.web2core.workers.dev']) {
        const response = await worker.fetch(new Request('https://api.web2core.workers.dev/amnezia', { method: 'OPTIONS', headers: { Origin: origin } }));
        assert.equal(response.status, 204); assert.equal(response.headers.get('Access-Control-Allow-Origin'), origin);
    }
});
test('bundled Worker rejects malformed and oversized requests before registration', async () => {
    assert.equal((await worker.fetch(request({ version: '3' }))).status, 400);
    assert.equal((await worker.fetch(request({ options: { from_hex: 'a'.repeat(65536) } }))).status, 413);
});
test('bundled Worker generates locally, overlays signature packets and returns no-store', async () => {
    const originalFetch = globalThis.fetch;
    const calls = [];
    try {
        globalThis.fetch = async (url, init) => {
            assert.match(String(url), /^https:\/\/api\.cloudflareclient\.com\/v0[a-z0-9]+\/reg$/);
            assert.equal(init.method, 'POST'); calls.push(url);
            return Response.json(fixture());
        };
        const response = await worker.fetch(request({ version: '2.0', domain: 'example.com' }), {
            JUNK: { fetch: async req => { assert.match(req.url, /^https:\/\/junk\.web2core\.workers\.dev\/signature\?/); return Response.json(signaturePayload()); } },
        });
        assert.equal(response.status, 200); assert.equal(response.headers.get('Cache-Control'), 'no-store');
        assert.equal(response.headers.get('Access-Control-Allow-Origin'), 'https://web2core.workers.dev');
        const result = await response.json();
        assert.equal(result.signatureApplied, true); assert.match(result.content, /^I1 = <b 0x0102>$/m);
        assert.match(result.content, /^Address = 172\.16\.0\.2\/32, 2606:4700:110::123\/128$/m);
        assert.equal(calls.length, 1);
    } finally { globalThis.fetch = originalFetch; }
});
test('bundled Worker uses builtin CPS when no signature binding is configured', async () => {
    const originalFetch = globalThis.fetch;
    try {
        globalThis.fetch = async () => Response.json(fixture());
        const response = await worker.fetch(request({ version: '3.1', domain: 'example.com' }), {});
        assert.equal(response.status, 200);
        const result = await response.json();
        assert.equal(result.signatureApplied, false); assert.match(result.content, /^I1 = <b 0xc[0-9a-f]+>$/m);
        assert.match(result.content, /^RandomTrailers = on$/m); assert.match(result.content, /^DisableCookies = on$/m);
    } finally { globalThis.fetch = originalFetch; }
});
