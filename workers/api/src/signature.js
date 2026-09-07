import { normalizeAmneziaDomain } from '../../../src/core/amnezia.js';

const SIGNATURE_API = 'https://junk.web2core.workers.dev/signature';
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 128 * 1024;
const MAX_PACKET_HEX_LENGTH = 32 * 1024;

function upstreamError(message, status = 502) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function validatePackets(payload, requestedDomain) {
    if (!payload || payload.ok !== true) throw upstreamError('Signature service did not return a valid result.');
    let returnedDomain;
    try { returnedDomain = normalizeAmneziaDomain(payload.domain); }
    catch { throw upstreamError('Signature service returned an invalid domain.'); }
    if (returnedDomain !== requestedDomain) throw upstreamError('Signature service returned a result for another domain.');

    const packets = [];
    for (let index = 1; index <= 5; index++) {
        const value = payload[`i${index}`];
        const match = typeof value === 'string' && /^<b 0x([0-9a-f]+)>$/.exec(value);
        if (!match || match[1].length % 2 || match[1].length > MAX_PACKET_HEX_LENGTH) {
            throw upstreamError(`Signature service returned an invalid I${index} packet.`);
        }
        packets.push(value);
    }
    return packets;
}

// The domain is normalized before this call and URL-encoded below, so it
// cannot alter the fixed upstream request target.
export async function fetchDomainSignature(domain, fetchFn = fetch) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetchFn(`${SIGNATURE_API}?domain=${encodeURIComponent(domain)}`, {
            signal: controller.signal,
            headers: { Accept: 'application/json' },
            // Cloudflare Workers does not implement redirect: 'error'. A 3xx
            // response is not followed and is rejected by the status check.
            redirect: 'manual',
        });
        const contentLength = Number(response.headers.get('Content-Length'));
        if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
            throw upstreamError('Signature service returned an oversized response.');
        }
        if (!response.ok) {
            throw upstreamError(`Signature service returned HTTP ${response.status}.`, response.status === 429 ? 429 : 502);
        }
        const raw = await response.text();
        if (new TextEncoder().encode(raw).byteLength > MAX_RESPONSE_BYTES) {
            throw upstreamError('Signature service returned an oversized response.');
        }
        let payload;
        try { payload = JSON.parse(raw); }
        catch { throw upstreamError('Signature service returned invalid JSON.'); }
        return validatePackets(payload, domain);
    } catch (error) {
        if (controller.signal.aborted) throw upstreamError('Signature request timed out. Please try again.');
        if (error?.status) throw error;
        const detail = typeof error?.message === 'string' ? error.message.slice(0, 180) : '';
        throw upstreamError(`Could not retrieve real I1-I5 packets for this domain${detail ? `: ${detail}` : '.'}`);
    } finally {
        clearTimeout(timer);
    }
}
