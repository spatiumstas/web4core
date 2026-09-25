const CLOUDFLARE_API = 'https://api.cloudflareclient.com/v0a2158/reg';
const CLOUDFLARE_CLIENT_VERSION = 'a-6.10-2158';
const REQUEST_TIMEOUT_MS = 25_000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function apiError(message, status = 502) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function base64UrlToBase64(value) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw apiError('Could not generate WireGuard keys.');
    }
    return value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
}

function decodeBase64Key(value) {
    if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(value)) {
        throw apiError('Cloudflare returned an invalid WARP profile.');
    }
    try {
        if (atob(value).length !== 32) throw new Error('invalid key length');
    } catch {
        throw apiError('Cloudflare returned an invalid WARP profile.');
    }
    return value;
}

function createInstallId() {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const limit = 256 - (256 % alphabet.length);
    const chars = [];
    while (chars.length < 22) {
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        for (const byte of bytes) {
            if (byte < limit) chars.push(alphabet[byte % alphabet.length]);
            if (chars.length === 22) break;
        }
    }
    return chars.join('');
}

async function generateWireGuardKeys() {
    try {
        const pair = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
        const [privateJwk, publicJwk] = await Promise.all([
            crypto.subtle.exportKey('jwk', pair.privateKey),
            crypto.subtle.exportKey('jwk', pair.publicKey),
        ]);
        return {
            privateKey: decodeBase64Key(base64UrlToBase64(privateJwk.d)),
            publicKey: decodeBase64Key(base64UrlToBase64(publicJwk.x)),
        };
    } catch (error) {
        if (error?.status) throw error;
        throw apiError('Could not generate WireGuard keys.');
    }
}

function readRegistration(payload) {
    const registration = payload?.result && typeof payload.result === 'object' ? payload.result : payload;
    const config = registration?.config;
    const peer = Array.isArray(config?.peers) ? config.peers[0] : null;
    const ipv4 = config?.interface?.addresses?.v4;
    const id = registration?.id;
    const token = registration?.token;

    if (!UUID_PATTERN.test(id || '') || !UUID_PATTERN.test(token || '') ||
        typeof ipv4 !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(ipv4) ||
        ipv4.split('.').some(part => Number(part) > 255) || !peer) {
        throw apiError('Cloudflare returned an invalid WARP profile.');
    }

    const endpoint = peer.endpoint?.host;
    return {
        id,
        token,
        address: `${ipv4}/32`,
        publicKey: decodeBase64Key(peer.public_key),
        endpoint: typeof endpoint === 'string' && /^[A-Za-z0-9.-]+:\d{1,5}$/.test(endpoint)
            ? endpoint : 'engage.cloudflareclient.com:2408',
    };
}

async function readJsonResponse(response, service) {
    const contentLength = Number(response.headers.get('Content-Length'));
    if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
        throw apiError(`${service} returned an oversized response.`);
    }
    const raw = await response.text();
    if (new TextEncoder().encode(raw).byteLength > MAX_RESPONSE_BYTES) {
        throw apiError(`${service} returned an oversized response.`);
    }
    try { return JSON.parse(raw); }
    catch { throw apiError(`${service} returned an invalid response.`); }
}

function configFromRegistration(keys, registration, version) {
    const sFields = version === '1.5'
        ? 'S1 = 0\nS2 = 0'
        : 'S1 = 0\nS2 = 0\nS3 = 0\nS4 = 0';
    return `[Interface]
PrivateKey = ${keys.privateKey}
Address = ${registration.address}
DNS = 1.1.1.1
MTU = 1280
Jc = 3
Jmin = 64
Jmax = 128
${sFields}
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = ${registration.publicKey}
AllowedIPs = 0.0.0.0/0
Endpoint = ${registration.endpoint}
PersistentKeepalive = 25
`;
}

export function applyCpsPackets(config, cpsPackets) {
    if (!cpsPackets) return config;
    const peerOffset = config.search(/^\[Peer\]\s*$/m);
    if (peerOffset < 0) throw apiError('Cloudflare returned an invalid WARP profile.');

    const interfaceLines = config.slice(0, peerOffset).split('\n').filter(line => !/^I[1-5]\s*=/i.test(line));
    const peerBlock = config.slice(peerOffset);
    let insertAt = interfaceLines.findIndex(line => /^H4\s*=/.test(line));
    if (insertAt < 0) insertAt = interfaceLines.length - 1;
    else insertAt += 1;
    const fields = cpsPackets.map((packet, index) => `I${index + 1} = ${packet}`);
    interfaceLines.splice(insertAt, 0, ...fields);
    return `${interfaceLines.join('\n')}${peerBlock}`;
}

async function fetchCloudflareJson(fetchFn, url, init, controller, service) {
    let response;
    try { response = await fetchFn(url, init); }
    catch (error) {
        if (controller.signal.aborted) throw apiError('Cloudflare WARP request timed out. Please try again.');
        throw apiError('Could not reach Cloudflare WARP. Please try again.');
    }
    if (!response.ok) {
        throw apiError(response.status === 429
            ? 'Cloudflare WARP is receiving too many requests. Please try again later.'
            : `${service} failed (HTTP ${response.status}).`, response.status === 429 ? 429 : 502);
    }
    return readJsonResponse(response, service);
}

export async function fetchAmneziaConfig(version, fetchFn = fetch) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const keys = await generateWireGuardKeys();
        const installId = createInstallId();
        const headers = {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            'CF-Client-Version': CLOUDFLARE_CLIENT_VERSION,
            'User-Agent': 'okhttp/3.12.1',
        };
        const payload = await fetchCloudflareJson(fetchFn, CLOUDFLARE_API, {
            method: 'POST',
            signal: controller.signal,
            redirect: 'manual',
            headers,
            body: JSON.stringify({
                install_id: installId,
                tos: new Date().toISOString(),
                key: keys.publicKey,
                fcm_token: '',
                model: 'PC',
                serial_number: installId,
                locale: 'en_US',
            }),
        }, controller, 'Cloudflare WARP registration');
        const registration = readRegistration(payload);

        let enabled;
        try {
            enabled = await fetchFn(`${CLOUDFLARE_API}/${registration.id}`, {
                method: 'PATCH',
                signal: controller.signal,
                redirect: 'manual',
                headers: { ...headers, Authorization: `Bearer ${registration.token}` },
                body: JSON.stringify({ warp_enabled: true }),
            });
        } catch {
            throw apiError(controller.signal.aborted
                ? 'Cloudflare WARP request timed out. Please try again.'
                : 'Could not activate the Cloudflare WARP profile. Please try again.');
        }
        if (!enabled.ok) {
            throw apiError(enabled.status === 429
                ? 'Cloudflare WARP is receiving too many requests. Please try again later.'
                : `Cloudflare WARP activation failed (HTTP ${enabled.status}).`, enabled.status === 429 ? 429 : 502);
        }

        return configFromRegistration(keys, registration, version);
    } catch (error) {
        if (error?.status) throw error;
        if (controller.signal.aborted) throw apiError('Cloudflare WARP request timed out. Please try again.');
        throw apiError('Could not generate the Cloudflare WARP profile.');
    } finally {
        clearTimeout(timer);
    }
}
