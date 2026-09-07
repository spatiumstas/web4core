/*! SPDX-License-Identifier: AGPL-3.0-only
 * Derived from https://github.com/HereIamGosu/amnezia-config-gen
 * Copyright HereIamGosu and contributors. See src/vendor/amnezia/NOTICE.md.
 */
// Adapted from HereIamGosu/amnezia-config-gen, src/server/cpsGenerator.js.
// Changes: TLS-only extraction, caller-supplied SNI, Web Crypto randomness, ESM.
// See NOTICE.md and LICENSE in this directory.
import { Buffer } from 'buffer';

export function randomInt(min, max) {
    const range = max - min;
    const limit = Math.floor(0x100000000 / range) * range;
    let value;
    do { value = crypto.getRandomValues(new Uint32Array(1))[0]; } while (value >= limit);
    return min + value % range;
}
const randomBytes = (n) => Buffer.from(crypto.getRandomValues(new Uint8Array(n)));
const u8 = (v) => Buffer.from([v & 0xff]);
const u16be = (v) => { const b = Buffer.alloc(2); b.writeUInt16BE(v); return b; };
const concat = (...bufs) => Buffer.concat(bufs);

const tlsExt = (type, data) => concat(u16be(type), u16be(data.length), data);

/**
 * GREASE values per RFC 8701: reserved 0x?A?A pattern in cipher/extension/version slots.
 * Real Chrome/Firefox always insert these to keep middleboxes honest about unknown TLS values.
 * Their presence is itself a fingerprint marker — absence flags the client as non-browser.
 */
const TLS_GREASE_VALUES = [
  0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
  0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];
const pickGrease = () => TLS_GREASE_VALUES[randomInt(0, TLS_GREASE_VALUES.length)];

/** TLS record + handshake wrapping for a finished ClientHello body. */
const wrapTlsRecord = (chBody) => {
  const chLen = chBody.length;
  const handshake = concat(
    u8(0x01),
    u8((chLen >> 16) & 0xff), u8((chLen >> 8) & 0xff), u8(chLen & 0xff),
    chBody,
  );
  return concat(u8(0x16), u16be(0x0301), u16be(handshake.length), handshake);
};

/** Target ClientHello body size — Chrome aligns to 512 boundary via padding extension. */
const TLS_PADDED_TARGET = 512;

export const generateTlsPayload = (host) => {
  const clientRandom = randomBytes(32);
  const sessionId = randomBytes(32);
  const greaseCipher = pickGrease();
  const greaseExt = pickGrease();
  const greaseGroup = pickGrease();
  const greaseVersion = pickGrease();

  // SNI extension (0x0000)
  const hostBuf = Buffer.from(host, 'ascii');
  const sniEntry = concat(u8(0), u16be(hostBuf.length), hostBuf);
  const sniList = concat(u16be(sniEntry.length), sniEntry);
  const sniExt = tlsExt(0x0000, sniList);

  // supported_versions (0x002b): GREASE + TLS 1.3 + 1.2
  const versExt = tlsExt(0x002b, concat(u8(6), u16be(greaseVersion), u16be(0x0304), u16be(0x0303)));

  // supported_groups (0x000a): GREASE + x25519 + secp256r1
  const groupsExt = tlsExt(0x000a, concat(u16be(6), u16be(greaseGroup), u16be(0x001d), u16be(0x0017)));

  // ALPN (0x0010): h2, http/1.1
  const h2 = concat(u8(2), Buffer.from('h2'));
  const http11 = concat(u8(8), Buffer.from('http/1.1'));
  const alpnList = concat(u16be(h2.length + http11.length), h2, http11);
  const alpnExt = tlsExt(0x0010, alpnList);

  // signature_algorithms (0x000d): RSA-PSS-RSAE/SHA256, ECDSA-SHA256, RSA-PKCS1-SHA256
  const sigAlgs = tlsExt(0x000d, concat(u16be(8), u16be(0x0804), u16be(0x0403), u16be(0x0807), u16be(0x0401)));

  // psk_key_exchange_modes (0x002d): psk_dhe_ke (1)
  const pskModes = tlsExt(0x002d, concat(u8(1), u8(1)));

  // ec_point_formats (0x000b): uncompressed
  const ecPoints = tlsExt(0x000b, concat(u8(1), u8(0)));

  // extended_master_secret (0x0017): empty
  const ems = tlsExt(0x0017, Buffer.alloc(0));

  // renegotiation_info (0xff01): empty (1 byte length=0)
  const renegoInfo = tlsExt(0xff01, u8(0));

  // session_ticket (0x0023): empty
  const sessionTicket = tlsExt(0x0023, Buffer.alloc(0));

  // status_request (0x0005): OCSP, status_type=1, responder_id_list=0, request_extensions=0
  const statusReq = tlsExt(0x0005, concat(u8(1), u16be(0), u16be(0)));

  // signed_certificate_timestamp (0x0012): empty
  const sct = tlsExt(0x0012, Buffer.alloc(0));

  // key_share (0x0033): GREASE (1-byte placeholder) + x25519 with real pub key
  const greaseKsEntry = concat(u16be(greaseGroup), u16be(1), u8(0));
  const x25519Pub = randomBytes(32);
  const ksEntry = concat(u16be(0x001d), u16be(32), x25519Pub);
  const ksList = concat(greaseKsEntry, ksEntry);
  const ksExt = tlsExt(0x0033, concat(u16be(ksList.length), ksList));

  // Two GREASE extensions (Chrome puts GREASE at start AND end of ext list)
  const greaseExtFirst = tlsExt(greaseExt, Buffer.alloc(0));
  const greaseExtLast = tlsExt(pickGrease(), u8(0));

  // Mid extensions in randomized order (Chrome shuffles non-anchor extensions)
  const midExts = [sniExt, sigAlgs, pskModes, ecPoints, ems, renegoInfo, sessionTicket, statusReq, sct, alpnExt, versExt, groupsExt];
  for (let i = midExts.length - 1; i > 0; i -= 1) {
    const j = randomInt(0, i + 1);
    [midExts[i], midExts[j]] = [midExts[j], midExts[i]];
  }

  // Compose initial extensions (without padding) to compute padding size.
  const fixedExts = concat(greaseExtFirst, ...midExts, ksExt, greaseExtLast);

  // ClientHello body shell (without padding ext) — used to compute final padding length.
  // Cipher suites: GREASE + TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
  const ciphers = concat(u16be(greaseCipher), u16be(0x1301), u16be(0x1302), u16be(0x1303));
  const beforePad = concat(
    u16be(0x0303),
    clientRandom,
    u8(sessionId.length), sessionId,
    u16be(ciphers.length), ciphers,
    u8(1), u8(0),
    u16be(fixedExts.length), // placeholder, real length depends on padding ext
  );

  // padding ext header (4 bytes) + value bytes; choose value size so final body ≈ TLS_PADDED_TARGET.
  // Final ext-block length = fixedExts.length + 4 + padValueLen.
  // Final ch body = beforePad.length (without ext-len rewrite) + extBlockLen (we redo concat below).
  const baseBodyNoExtLen = beforePad.length - 2; // strip the 2-byte placeholder ext-len
  const targetExtBlockLen = Math.max(fixedExts.length, TLS_PADDED_TARGET - baseBodyNoExtLen - 2);
  const padValueLen = Math.max(0, targetExtBlockLen - fixedExts.length - 4);
  const paddingExt = tlsExt(0x0015, Buffer.alloc(padValueLen, 0));

  const extensions = concat(greaseExtFirst, ...midExts, ksExt, greaseExtLast, paddingExt);

  const chBody = concat(
    u16be(0x0303),
    clientRandom,
    u8(sessionId.length), sessionId,
    u16be(ciphers.length), ciphers,
    u8(1), u8(0),
    u16be(extensions.length), extensions,
  );

  return wrapTlsRecord(chBody);
};

