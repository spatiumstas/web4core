import QRCode from 'qrcode';

const QR_OPTIONS = { errorCorrectionLevel: 'L' };
const CHUNK_BYTES = 850;
const AMNEZIA_QR_MAGIC = 1984;

export class QrCapacityError extends Error {}

// AmneziaVPN's QR series format: big-endian QDataStream fields followed by
// QByteArray data. The client reassembles the original .conf before importing.
// https://github.com/amnezia-vpn/amnezia-client/blob/master/client/core/utils/qrCodeUtils.cpp
export function createConfigQrSeries(content) {
    if (typeof content !== 'string' || !content) throw new Error('Configuration is empty.');
    try {
        return [QRCode.create(content, QR_OPTIONS)];
    } catch (error) {
        // Canvas and other rendering errors must not be reported as size errors.
        if (!error.message.includes('amount of data is too big')) throw error;
    }
    const bytes = new TextEncoder().encode(content);
    const count = Math.ceil(bytes.length / CHUNK_BYTES);
    if (count > 255) throw new QrCapacityError('Configuration exceeds the QR series capacity.');
    const series = [];
    for (let index = 0; index < count; index++) {
        const chunk = bytes.subarray(index * CHUNK_BYTES, (index + 1) * CHUNK_BYTES);
        const frame = new Uint8Array(8 + chunk.length);
        const header = new DataView(frame.buffer);
        header.setInt16(0, AMNEZIA_QR_MAGIC);
        header.setUint8(2, count);
        header.setUint8(3, index);
        header.setUint32(4, chunk.length);
        frame.set(chunk, 8);
        const encoded = btoa(String.fromCharCode(...frame))
            .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        series.push(QRCode.create(encoded, QR_OPTIONS));
    }
    return series;
}
