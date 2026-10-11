import { validateAmneziaRequest } from '../../../src/core/amnezia.js';
import { fetchDomainSignature } from './signature.js';
import { generateWarpProfile } from './warp.js';

// Best-effort per-isolate bound; use an edge rate-limit rule for global enforcement.
const requests = new Map();
const MAX_BODY_BYTES = 64 * 1024; // Includes optional CPS overrides and sealed cache.
async function fetchOptionalCpsPackets(body, junk) {
    if (!body.domain || body.version === '1.5' || body.options.transport === 'none' || body.options.mask === 'none' || typeof junk?.fetch !== 'function') return null;
    try {
        return await fetchDomainSignature(body.domain, (url, init) => junk.fetch(new Request(url, init)));
    } catch {
        // Do not log domains, captured data or upstream error bodies.
        return null;
    }
}
export async function handleAmnezia(request, cors, env = {}) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), {
        status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    if (request.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase() !== 'application/json') return reply({ error: 'Content-Type must be application/json.' }, 415);
    let body;
    try {
        const reader = request.body?.getReader();
        if (!reader) return reply({ error: 'Request body is empty.' }, 400);
        let size = 0;
        const chunks = [];
        try {
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                size += value.length;
                if (size > MAX_BODY_BYTES) { await reader.cancel(); return reply({ error: 'Request body is too large.' }, 413); }
                chunks.push(value);
            }
        } finally { reader.releaseLock(); }
        const raw = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
        body = validateAmneziaRequest(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)));
    } catch (error) {
        return reply({ error: error instanceof SyntaxError || error instanceof TypeError ? 'Provide valid JSON generator settings.' : error.message }, 400);
    }
    const now = Date.now();
    for (const [key, entry] of requests) if (now >= entry.until) requests.delete(key);
    const ip = request.headers.get('CF-Connecting-IP') || 'local';
    const entry = requests.get(ip) || { count: 0, until: now + 60000 };
    if (entry.count >= 10 || (!requests.has(ip) && requests.size >= 10000)) return reply({ error: 'Too many requests. Please try again in a minute.' }, 429);
    entry.count++;
    requests.set(ip, entry);
    try {
        const packets = fetchOptionalCpsPackets(body, env?.JUNK);
        const result = await generateWarpProfile(body, fetch, env, packets);
        result.signatureApplied = Boolean(await packets);
        if (body.domain && !result.signatureApplied) result.warnings.push('Domain signature unavailable or disabled; the selected local CPS settings were retained.');
        return reply(result);
    } catch (error) { return reply({ error: error.status ? error.message : 'Could not generate the configuration.' }, error.status || 502); }
}
