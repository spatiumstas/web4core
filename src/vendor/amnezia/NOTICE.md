# Amnezia generator attribution

Source: https://github.com/HereIamGosu/amnezia-config-gen
Revision: `4a9c10592c18c69316b835246b3f57651f699600`
Author: HereIamGosu and contributors
License: AGPL-3.0-only (see LICENSE).

`tls.js` adapts the TLS ClientHello generator from `src/server/cpsGenerator.js`.
`warp.js` adapts the WARP registration flow and WARP-safe AWG 1.5/2.0
configuration construction from `api/warp.js`.

Changes for web4core: ESM, Web Crypto randomness, Workers fetch and timeouts,
validated user-provided SNI, IPv4 full-tunnel output, no routing presets,
no telemetry, and no endpoint probing. The original WARP-safe S/H values
and uppercase I1 are preserved.

These adapted modules are AGPL-3.0-only. The existing BSD notice is retained
for original web4core code; it does not replace the AGPL terms for the
combined API Worker. Distributions and network deployments of the combined
Worker must provide its corresponding source under the AGPL terms.
The UI links to the web4core source repository; deployers must keep that link
pointing to the exact source they deploy, including local changes.
