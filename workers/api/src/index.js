import '../../../src/parseuri.min.js';
import { buildFromRequest } from '../../../src/build.js';
import { fetchSubscription } from '../../../src/core/subscription.js';
import README_MD from '../README.md';

const ALLOWED_ORIGINS = new Set([
  'https://web2core.workers.dev',
  'https://api.web2core.workers.dev',
]);

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
  return String(raw || '')
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function shouldAutoExpandSubscription(input, options) {
  const lines = splitLines(input);
  if (lines.length !== 1) return false;
  const line = lines[0];
  if (!/^https?:\/\//i.test(line)) return false;
  try {
    const u = new URL(line);
    if (u.username || u.password) return false;
    return !!u.pathname && u.pathname !== '/' && u.pathname !== '';
  } catch {
    return false;
  }
}

async function expandSubscriptionsIfNeeded(input, options) {
  const raw = String(input || '');
  if (options && options.mihomoSubscriptionMode === true) return raw;

  if (!shouldAutoExpandSubscription(raw, options)) return raw;
  const url = splitLines(raw)[0] || '';
  const body = await fetchSubscription(url);
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

    let body;
    try {
      body = await request.json();
    } catch {
      return json({ error: 'Invalid JSON body' }, 400, cors);
    }

    const core = String(body?.core || '').toLowerCase();
    const input = String(body?.input || '');
    const options = body && typeof body.options === 'object' && body.options ? body.options : {};

    try {
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


