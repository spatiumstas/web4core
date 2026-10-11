import test from 'node:test';
import assert from 'node:assert/strict';
import { createConfigQrSeries, QrCapacityError } from '../../src/ui/components/config-qr.js';
import { renderQr } from '../../src/ui/components/qr-renderer.js';

// Read the encoded payload segments independently of the series encoder.
const payload = qr => qr.segments.map(segment => typeof segment.data === 'string'
    ? segment.data : Buffer.from(segment.data).toString('utf8')).join('');
const config = packets => `[Interface]\nPrivateKey = ${'a'.repeat(43)}=\nAddress = 172.16.0.2/32\n${packets}\n[Peer]\nPublicKey = ${'b'.repeat(43)}=\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 162.159.192.1:2408\n`;
const largeConfig = config(Array.from({ length: 5 }, (_, i) => `I${i + 1} = <b 0x${'abcdef012345'.repeat(90)}>`).join('\n'));

test('small profiles stay a single plain-text QR accepted by existing scanners', () => {
    const content = config('Jc = 4');
    const series = createConfigQrSeries(content);
    assert.equal(series.length, 1);
    assert.equal(payload(series[0]), content);
});

test('large profiles use native Amnezia frames and reassemble byte-for-byte', () => {
    const content = largeConfig + '# проверка UTF-8\n';
    const bytes = Buffer.from(content);
    const series = createConfigQrSeries(content);
    assert(series.length > 1);
    const chunks = [];
    for (let index = 0; index < series.length; index++) {
        const text = payload(series[index]);
        assert.match(text, /^[A-Za-z0-9_-]+$/);
        const frame = Buffer.from(text, 'base64url');
        assert.equal(frame.readInt16BE(0), 1984);
        assert.equal(frame[2], series.length);
        assert.equal(frame[3], index);
        assert.equal(frame.readUInt32BE(4), frame.length - 8);
        assert(frame.length - 8 <= 850);
        chunks.push(frame.subarray(8));
    }
    assert.deepEqual(Buffer.concat(chunks), bytes);
});

test('native frame count cannot overflow its one-byte field', () => {
    assert.throws(() => createConfigQrSeries(config('x'.repeat(850 * 255))), QrCapacityError);
    assert.throws(() => createConfigQrSeries(''), /empty/);
});

test('prepared single and multipart symbols render without animation and preserve every module', () => {
    for (const content of [config('Jc = 4'), largeConfig]) {
        for (const symbol of createConfigQrSeries(content)) {
            const draws = [];
            const context = { fillRect: (...rect) => draws.push(rect) };
            const canvas = { getContext: () => context };
            let ready = 0;
            renderQr(canvas, symbol, { animate: false, onReady: () => ready++ });
            assert.equal(ready, 1);
            assert.equal(canvas.width, (symbol.modules.size + 8) * 6);
            assert.equal(canvas.height, canvas.width);
            const blackCells = symbol.modules.data.reduce((sum, cell) => sum + cell, 0);
            assert.equal(draws.length, blackCells + 1);
            assert(draws.slice(1).every(([x, y, w, h]) => x >= 24 && y >= 24 && w === 6 && h === 6));
        }
    }
});
