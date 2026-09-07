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

`POST /amnezia` creates one fresh Cloudflare WARP registration and returns an
AmneziaWG configuration. It does not provision an independent VPN server.

```json
{ "version": "2.0", "domain": "example.com" }
```

`version` is `"1.5"` or `"2.0"`. `domain` is an optional hostname (IDNs are accepted),
without a scheme, port, or path. If omitted or blank, the generator chooses a
hostname from the upstream TLS domain pool. The selected domain is returned
in the response. It is encoded in TLS ClientHello SNI inside
uppercase `I1`–`I5`. Each of the five packets is a separately randomized TLS
ClientHello with the same SNI domain, in both AWG 1.5 and 2.0. The domain
itself is never contacted. Both versions use the
upstream WARP-compatible packet types and zero padding. The output routes IPv4
traffic through WARP (`0.0.0.0/0`) and uses `engage.cloudflareclient.com:4500`.

The JSON response contains `content`, `filename`, `version`, and normalized
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

The adapted generator is from
[HereIamGosu/amnezia-config-gen](https://github.com/HereIamGosu/amnezia-config-gen).
Its pinned revision, adaptation details, and AGPL-3.0 license are in
`src/vendor/amnezia/NOTICE.md` and `src/vendor/amnezia/LICENSE`.
The combined Worker includes AGPL code; provide corresponding source for the
version deployed. Keep the UI source link current when deploying a fork.
