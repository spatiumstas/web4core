// This endpoint links the AGPL-3.0-only generator; see src/vendor/amnezia/NOTICE.md.
import { generateAmneziaConfig } from '../../../src/vendor/amnezia/warp.js';
import { validateAmneziaRequest } from '../../../src/core/amnezia.js';

// Best-effort per-isolate bound; use an edge rate-limit rule for global enforcement.
const requests = new Map();
export async function handleAmnezia(request, cors) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), {
        status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    if (!request.headers.get('Content-Type')?.includes('application/json')) return reply({ error: 'Content-Type must be application/json.' }, 415);
    let body;
    try {
        const reader = request.body?.getReader();
        if (!reader) return reply({ error: 'Request body is empty.' }, 400);
        let size = 0;
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            if (size > 2048) { await reader.cancel(); return reply({ error: 'Request body is too large.' }, 413); }
            chunks.push(value);
        }
        const raw = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
        body = validateAmneziaRequest(JSON.parse(new TextDecoder().decode(raw)));
    } catch { return reply({ error: 'Provide a valid AWG version. If specifying a domain, omit the scheme, port, and path.' }, 400); }
    const now = Date.now();
    for (const [key, entry] of requests) if (now >= entry.until) requests.delete(key);
    const ip = request.headers.get('CF-Connecting-IP') || 'local';
    const entry = requests.get(ip) || { count: 0, until: now + 60000 };
    if (entry.count >= 10 || (!requests.has(ip) && requests.size >= 10000)) return reply({ error: 'Too many requests. Please try again in a minute.' }, 429);
    entry.count++;
    requests.set(ip, entry);
    try { return reply(await generateAmneziaConfig(body)); }
    catch (error) { return reply({ error: error.message || 'Could not generate the configuration.' }, error.status || 502); }
}
