### Worker API:
- **sing-box**: JSON
- **Xray**: JSON
- **Mihomo**: YAML

### Endpoint

- **URL** `api.web2core.workers.dev`
- **POST** `/` or `/api`
- **OPTIONS** supported (CORS preflight)
- **GET** `/` returns a short help text

### Request (JSON)

Content-Type: `application/json`

```json
{
  "core": "singbox",
  "input": "vless://...\\nvmess://...\\n...",
  "options": {}
}
```

#### Fields
- **core**: `"singbox" | "xray" | "mihomo"`
- **input**: string, multi-line (links/profiles). For Mihomo subscription mode: put one subscription URL per line.
- **options**: object, optional. Unknown fields are ignored.

### Response

- **singbox/xray**: `application/json`
- **mihomo**: `text/yaml`

On error:

```json
{ "error": "Human readable message" }
```

HTTP status is usually **400** for invalid input, **405** for wrong method, **404** for wrong path.

### Options

#### sing-box
- **addTun**: boolean
- **addSocks**: boolean
- **perTunMixed**: boolean
- **tunName**: string
- **genClashSecret**: boolean
- **useExtended**: boolean (enables Mieru/SDNS/etc.)
- **androidMode**: boolean
- **detour**: boolean (when true and multiple outbounds: all but first detour to the first)

#### Xray
- **enableBalancer**: boolean
- **addTun**: boolean
- **addSocks**: boolean

#### Mihomo
- **addTun**: boolean
- **webUI**: boolean
- **mihomoPerProxyTun**: boolean
- **perProxyPort**: boolean
- **mihomoSubscriptionMode**: boolean
  - When enabled, `input` must contain one or more `http(s)://...` subscription URLs (one per line).
  - If a URL contains basic auth (`https://user:pass@...`) it is treated as an “extra proxy line” (not a provider URL).

### Examples

#### sing-box

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"singbox\",\"input\":\"vless://UUID@host:443?type=ws&security=tls#test\",\"options\":{\"addTun\":true,\"addSocks\":true,\"tunName\":\"tun0\",\"useExtended\":false}}"
```

#### Xray

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"xray\",\"input\":\"vless://UUID@host:443?type=ws&security=tls#test\",\"options\":{\"enableBalancer\":false}}"
```

#### Mihomo (YAML)

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"mihomo\",\"input\":\"vless://UUID@host:443?type=ws&security=tls#test\",\"options\":{\"webUI\":true,\"addTun\":false,\"perProxyPort\":false}}"
```

#### Mihomo subscription mode

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"mihomo\",\"input\":\"https://example.com/sub1\\nhttps://example.com/sub2\",\"options\":{\"mihomoSubscriptionMode\":true,\"webUI\":true}}"
```


### Amnezia WARP

`POST /amnezia` requests a fresh configuration from the upstream Amnezia WARP
generator and returns it in the format consumed by this frontend. It does not
provision an independent VPN server.

```json
{ "version": "2.0", "domain": "example.com" }
```

`version` is `"1.5"`, `"2.0"`, `"3.0"` or `"3.1"`. `domain` is an optional hostname (IDNs are accepted),
without a scheme, port, or path. The Worker requests the base profile from
`valokda-amnezia.vercel.app/api/warp` (using `legacy` or `awg2` mode). When a
domain is present, it also fetches captured real `I1`–`I5` packets from the
signature service, validates them and the echoed normalized domain, then
replaces the upstream CPS fields unchanged. If the domain is blank, the
signature service is unavailable, or it has no capture for the domain, the
original I fields are retained rather than failing the request.

Every profile gets a random endpoint from `162.159.192.1–10` or `162.159.195.1–10`
and port 500, 1701, 2408 or 4500. Selection is local, not a connectivity scan.
The pool is a conservative subset of the approach in
[warp-generation](https://github.com/warp-generation/warp-generation.github.io/blob/main/script.js).

AWG 3.0/3.1 use the upstream `awg2` profile with locally generated ranges for
ContentPaddingAddition and protocol timers. The minimum RejectAfterTime is
greater than the maximum RekeyAfterTime. HeaderProtectionKey is not added.
3.1 also enables RandomTrailers and DisableCookies. It is experimental with
WARP: importing successfully does not prove connectivity; try 3.0/2.0 if the
handshake fails. These modes require a compatible client.
Signature failure preserves the original I fields; version parameters and the
random endpoint are still applied. For 1.5/2.0 the fallback changes only Endpoint.

The JSON response includes `signatureApplied` (boolean), `content`, `filename`, `version`, and normalized
`domain`. `content` includes a private key: responses are `no-store`; the
application does not log or persist keys. Copy/download is handled locally.
Generation has a 25-second upstream deadline. Errors use JSON `{ "error": "…" }`:
400 invalid input, 413 oversized body, 415 unsupported content type, 429 rate
limit, 502 upstream error. There are no automatic registration retries, to avoid
creating duplicate devices on ambiguous network failures.

A best-effort per-isolate limiter allows 10 requests/minute per Cloudflare client
IP. For public deployments, configure an edge rate-limit rule for this endpoint
if a globally enforced limit is required.

Build and test: `npm run test:amnezia`. Deploy the updated API Worker alongside
the frontend; deploying only the static page will leave generation unavailable.
The frontend endpoint is configured by `<meta name="amnezia-api">` in
`src/index.html`. For local development, serve `src` on port 4173, run the built
Worker using Wrangler on port 8787, and temporarily set this meta value to
`http://localhost:8787/amnezia`. The allowed origins include localhost:4173,
127.0.0.1:4173, the existing workers.dev site, and dan0102dan.github.io.

The upstream generator is
[HereIamGosu/amnezia-config-gen](https://github.com/HereIamGosu/amnezia-config-gen).
The Worker treats it as an external API and does not use its vendored code for
the `/amnezia` route.
