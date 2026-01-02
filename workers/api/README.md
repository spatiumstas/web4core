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

#### Mihomo
- **webUI**: boolean
- **mihomoTun**: boolean
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
  --data "{\"core\":\"mihomo\",\"input\":\"vless://UUID@host:443?type=ws&security=tls#test\",\"options\":{\"webUI\":true,\"mihomoTun\":false,\"perProxyPort\":false}}"
```

#### Mihomo subscription mode

```bash
curl -sS -X POST "https://api.web2core.workers.dev/" ^
  -H "Content-Type: application/json" ^
  --data "{\"core\":\"mihomo\",\"input\":\"https://example.com/sub1\\nhttps://example.com/sub2\",\"options\":{\"mihomoSubscriptionMode\":true,\"webUI\":true}}"
```

