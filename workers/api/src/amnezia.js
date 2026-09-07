// This endpoint links the AGPL-3.0-only generator; see src/vendor/amnezia/NOTICE.md.
import { generateAmneziaConfig } from '../../../src/vendor/amnezia/warp.js';
import { validateAmneziaRequest } from '../../../src/core/amnezia.js';

// Best-effort per-isolate bound; use an edge rate-limit rule for global enforcement.
const requests = new Map();
export async function handleAmnezia(request, cors) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), {
        status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
    });
    if (!request.headers.get('Content-Type')?.includes('application/json')) return reply({ error: 'Ожидается JSON.' }, 415);
    let body;
    try {
        const reader = request.body?.getReader();
        if (!reader) return reply({ error: 'Пустой запрос.' }, 400);
        let size = 0;
        const chunks = [];
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.length;
            if (size > 2048) { await reader.cancel(); return reply({ error: 'Слишком большой запрос.' }, 413); }
            chunks.push(value);
        }
        const raw = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { raw.set(chunk, offset); offset += chunk.length; }
        body = validateAmneziaRequest(JSON.parse(new TextDecoder().decode(raw)));
    } catch { return reply({ error: 'Укажите версию AWG и корректный домен без протокола и пути.' }, 400); }
    const now = Date.now();
    for (const [key, entry] of requests) if (now >= entry.until) requests.delete(key);
    const ip = request.headers.get('CF-Connecting-IP') || 'local';
    const entry = requests.get(ip) || { count: 0, until: now + 60000 };
    if (entry.count >= 10 || (!requests.has(ip) && requests.size >= 10000)) return reply({ error: 'Слишком много запросов. Повторите через минуту.' }, 429);
    entry.count++;
    requests.set(ip, entry);
    try { return reply(await generateAmneziaConfig(body)); }
    catch (error) { return reply({ error: error.message || 'Не удалось создать конфигурацию.' }, error.status || 502); }
}
