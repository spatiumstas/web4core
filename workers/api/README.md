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

`POST /amnezia` generates an Amnezia WARP profile inside this Worker.
It creates an X25519 key pair with Web Crypto, registers the public key directly
with Cloudflare WARP, and formats the `.conf` locally. No external configuration
generator, executable, or registration cache is required. Each request creates
a new device; the private key is returned only in the profile, and registration
tokens are not returned or stored.

```json
{ "version": "2.0", "domain": "example.com" }
```

- `version`: `"1.5"`, `"2.0"`, `"3.0"`, or `"3.1"`.
- `domain`: bare domain for I1–I5 capture; defaults to `github.com` when empty or omitted (not used for AWG 1.5).
- Other fields are ignored. There are no WARP+ or advanced generator settings.

The response contains `content`, `filename`, `version`, `domain`, and
`signatureApplied`, with `Cache-Control: no-store`.

AWG 1.5 omits S3/S4 and I1–I5. Later versions use real domain packets from
the JUNK Worker, via the `JUNK` service binding or its HTTPS endpoint.
If capture fails or returns invalid packets, generation fails before Cloudflare
registration. No random or bundled substitute packets are used for I1–I5.
Cloudflare is required for WARP registration. AWG 3.x requires a compatible client.

Registration failures return 502 (429 for rate limits). Unsupported registration
routes may fall back to another API prefix; ambiguous network failures are not
retried. Responses and request bodies are size-limited, requests have timeouts,
and failed newly registered devices are deleted on a best-effort basis.

Run `npm run test:amnezia` for offline registration, formatting, validation,
CORS and fallback tests. These use mocked Cloudflare responses and do not prove
connectivity through a live WARP tunnel.

The web QR dialog uses a single plain-text code for small profiles. Profiles
that exceed its capacity use the native AmneziaVPN QR series format; scan every
code with the same scanner session. Use `.conf` import in Shadowrocket or
AmneziaWG for these larger profiles. Packet bytes are preserved in full.
QR encoding, series framing and reconstruction are checked by `npm run test:amnezia`.
