const CONFIG = {
  ALLOWED_ORIGINS: [
    'https://web2core.workers.dev',
    'https://api.web2core.workers.dev',
  ],
  SUBSCRIPTION_TIMEOUT: 15000,
  MAX_PAYLOAD_SIZE: 1024 * 1024,
};

let parseUriLoaded = false;
let buildFromRequestFn = null;
let fetchSubscriptionFn = null;

async function ensureParseUri() {
  if (parseUriLoaded) return;
  if (typeof URL === 'function') {
    parseUriLoaded = true;
    return;
  }
  await import('../../../src/parseuri.min.js');
  parseUriLoaded = true;
}

async function getBuildFromRequest() {
  if (buildFromRequestFn) return buildFromRequestFn;
  await ensureParseUri();
  const module = await import('../../../src/build.js');
  buildFromRequestFn = module.buildFromRequest;
  return buildFromRequestFn;
}

async function getFetchSubscription() {
  if (fetchSubscriptionFn) return fetchSubscriptionFn;
  await ensureParseUri();
  const module = await import('../../../src/core/subscription.js');
  fetchSubscriptionFn = module.fetchSubscription;
  return fetchSubscriptionFn;
}

import README_MD from '../README.md';

const ALLOWED_ORIGINS = new Set(CONFIG.ALLOWED_ORIGINS);

function corsHeadersFor(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
  if (!origin) return headers;
  if (ALLOWED_ORIGINS.has(origin)) headers['Access-Control-Allow-Origin'] = origin;
  return headers;
}

function splitLines(raw) {
  const str = String(raw || '');
  const lines = [];
  for (const line of str.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (trimmed) lines.push(trimmed);
  }
  return lines;
}

async function fetchWithTimeout(fetchFn, url, timeout) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const result = await fetchFn(url, {signal: controller.signal});
    clearTimeout(timeoutId);
    return result;
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === 'AbortError') {
      throw new Error('Subscription fetch timeout');
    }
    throw e;
  }
}

async function expandSubscriptionsIfNeeded(input, options) {
  const raw = String(input || '');
  if (options && options.mihomoSubscriptionMode === true) return raw;

  const lines = splitLines(raw);
  if (lines.length !== 1) return raw;

  const url = lines[0];
  if (!/^https?:\/\//i.test(url)) return raw;

  try {
    const u = new URL(url);
    if (u.username || u.password) return raw;
    if (!u.pathname || u.pathname === '/' || u.pathname === '') return raw;
  } catch {
    return raw;
  }

  const fetchSubscription = await getFetchSubscription();
  const body = await fetchWithTimeout(fetchSubscription, url, CONFIG.SUBSCRIPTION_TIMEOUT);
  const expanded = splitLines(body);
  if (!expanded.length) throw new Error('Subscription returned no valid links');
  return expanded.join('\n');
}

function json(textOrObj, status = 200, extraHeaders = {}) {
  const body = typeof textOrObj === 'string' ? textOrObj : JSON.stringify(textOrObj, null, 2);
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

function text(body, contentType, status = 200, extraHeaders = {}) {
  return new Response(body || '', {
    status,
    headers: {
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const originHeader = request.headers.get('Origin');
    const origin = originHeader === 'null' ? '' : (originHeader || '');
    const cors = corsHeadersFor(origin);

    if (request.method === 'OPTIONS') {
      if (origin && !ALLOWED_ORIGINS.has(origin)) {
        return new Response(null, { status: 403, headers: cors });
      }
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method === 'GET') {
      if (url.pathname === '/' || url.pathname === '') {
        return text(README_MD, 'text/markdown; charset=utf-8', 200, cors);
      }
      return json({ error: 'Not found' }, 404, cors);
    }

    if (request.method !== 'POST') return json({ error: 'Method not allowed' }, 405, cors);
    if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ error: 'CORS origin not allowed' }, 403, cors);
    if (url.pathname !== '/api' && url.pathname !== '/') return json({ error: 'Not found' }, 404, cors);

    const contentType = request.headers.get('Content-Type') || '';
    if (!contentType.includes('application/json')) {
      return json({error: 'Content-Type must be application/json'}, 415, cors);
    }

    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > CONFIG.MAX_PAYLOAD_SIZE) {
      return json({error: 'Payload too large'}, 413, cors);
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400, cors);
    }

    const core = String(body?.core || '').toLowerCase();
    if (!core) return json({ error: 'Missing core' }, 400, cors);
    if (core !== 'singbox' && core !== 'xray' && core !== 'mihomo') {
      return json({ error: 'Invalid core: ' + core }, 400, cors);
    }
    const input = String(body?.input || '');
    if (!input.trim()) return json({ error: 'No input provided' }, 400, cors);
    const options = body && typeof body.options === 'object' && body.options ? body.options : {};

    try {
      const buildFromRequest = await getBuildFromRequest();
      const expandedInput = await expandSubscriptionsIfNeeded(input, options);
      const result = buildFromRequest({ core, input: expandedInput, options });
      if (result.kind === 'yaml') {
        return text(result.data, 'text/yaml; charset=utf-8', 200, cors);
      }
      return json(result.data, 200, cors);
    } catch (e) {
      return json({ error: e && e.message ? e.message : String(e) }, 400, cors);
    }
  },
};


