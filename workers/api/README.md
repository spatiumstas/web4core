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
  --data "{\"core\":\"mihomo\",\"input\":\"vless://UUID@host:443?type=ws&security=tls#test\",\"options\":{\"addTun\":false,\"perProxyPort\":false}}"
```

#### Mihomo subscription mode

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"mihomo\",\"input\":\"https://example.com/sub1\\nhttps://example.com/sub2\",\"options\":{\"mihomoSubscriptionMode\":true}}"
```


### Amnezia WARP

`POST /amnezia` runs the JavaScript port of
[Skiro1/warp-awg-gen](https://github.com/Skiro1/warp-awg-gen), pinned to
`0381e919f6c841c4aa59e2db352d8234bd5f4277`. Key generation, Cloudflare registration,
CPS generation and profile formatting are implemented in this repository; no
external configuration-generator service or Go executable is used. This does
not provision an independent VPN server. Cloudflare remains the remote peer.
See [provenance and porting notes](vendor/warp-awg-gen/README.md) and the preserved
[MIT license](vendor/warp-awg-gen/LICENSE).

Existing `{ "version": "2.0", "domain": "example.com" }` requests still work.
The complete web request format is:

```json
{
  "version": "3.1",
  "domain": "",
  "freshRegistration": false,
  "registrationCache": "",
  "options": {
    "license_key": "",
    "endpoint": "",
    "dns": "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001",
    "mtu": 1280,
    "keepalive": 25,
    "mask": "random",
    "transport": "",
    "from_hex": "",
    "awg": { "jc": 4, "jmin": 40, "jmax": 70, "s1": 0, "s2": 0, "s3": 0, "s4": 0, "h1": "1", "h2": "2", "h3": "3", "h4": "4" },
    "cps": {},
    "random_trailers": true,
    "disable_cookies": true
  }
}
```

`version` supports `1.5`, `2.0`, `3.0`, `3.1`. Domain is an optional hostname
(IDNs supported), without a scheme, port or path. Unknown generator options,
invalid DNS/endpoint values and invalid AWG ranges are rejected before any
Cloudflare registration. CLI/YAML configuration becomes the `options` JSON
object; no user-controlled filesystem paths or shell commands are accepted.
The frontend exposes common controls plus an advanced JSON editor.

#### Validation

```bash
node --test tools/ci/warp-generator.test.mjs
npm run test:amnezia
```

The first command runs offline unit/route tests; the second builds the Worker
and includes bundled integration tests. The dedicated PR workflow also builds
the frontend. No tests register actual Cloudflare devices or validate a live
VPN handshake/WARP+ account. Those checks remain deployment acceptance tests.
