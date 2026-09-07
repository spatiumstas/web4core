const AMNEZIA_API = 'https://valokda-amnezia.vercel.app/api/warp';
const REQUEST_TIMEOUT_MS = 25_000;
const MAX_RESPONSE_BYTES = 256 * 1024;

function upstreamError(message, status = 502) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function decodeConfig(encoded) {
    if (typeof encoded !== 'string' || !encoded || encoded.length > MAX_RESPONSE_BYTES ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
        throw upstreamError('Amnezia generator returned an invalid configuration.');
    }
    try {
        const binary = atob(encoded);
        const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
        const config = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        if (!config.startsWith('[Interface]') || !/^\[Peer\]$/m.test(config)) throw new Error('invalid config');
        return config;
    } catch {
        throw upstreamError('Amnezia generator returned an invalid configuration.');
    }
}

export function applyCpsPackets(config, cpsPackets) {
    if (!cpsPackets) return config;
    const peerOffset = config.search(/^\[Peer\]\s*$/m);
    if (peerOffset < 0) throw upstreamError('Amnezia generator returned an invalid configuration.');

    const interfaceLines = config.slice(0, peerOffset).split('\n').filter(line => !/^I[1-5]\s*=/i.test(line));
    const peerBlock = config.slice(peerOffset);
    let insertAt = interfaceLines.findIndex(line => /^H4\s*=/.test(line));
    if (insertAt < 0) insertAt = interfaceLines.length - 1;
    else insertAt += 1;
    const fields = cpsPackets.map((packet, index) => `I${index + 1} = ${packet}`);
    interfaceLines.splice(insertAt, 0, ...fields);
    return `${interfaceLines.join('\n')}${peerBlock}`;
}

export async function fetchAmneziaConfig(version, fetchFn = fetch) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetchFn(AMNEZIA_API, {
            method: 'POST',
            signal: controller.signal,
            // Cloudflare Workers does not implement redirect: 'error'. A 3xx
            // response is not followed and is rejected by the status check.
            redirect: 'manual',
            headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify({ mode: version === '1.5' ? 'legacy' : 'awg2' }),
        });
        const contentLength = Number(response.headers.get('Content-Length'));
        if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
            throw upstreamError('Amnezia generator returned an oversized response.');
        }
        const raw = await response.text();
        if (new TextEncoder().encode(raw).byteLength > MAX_RESPONSE_BYTES) {
            throw upstreamError('Amnezia generator returned an oversized response.');
        }
        let result;
        try { result = JSON.parse(raw); }
        catch { throw upstreamError('Amnezia generator returned invalid JSON.'); }
        if (!response.ok || result?.success !== true) {
            const message = typeof result?.message === 'string' && result.message.length <= 200
                ? result.message : 'Could not generate the configuration.';
            throw upstreamError(message, response.status === 429 ? 429 : 502);
        }
        return decodeConfig(result.content);
    } catch (error) {
        if (controller.signal.aborted) throw upstreamError('Amnezia generator request timed out. Please try again.');
        if (error?.status) throw error;
        throw upstreamError('Could not reach the Amnezia generator.');
    } finally {
        clearTimeout(timer);
    }
}
