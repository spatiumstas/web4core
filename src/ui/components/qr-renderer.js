import QRCode from 'qrcode';

// Finish on the exact module grid, including a four-module quiet zone.
export function renderQr(canvas, content, { animate = true, onReady = () => {} } = {}) {
    const { modules } = QRCode.create(content, { errorCorrectionLevel: 'L' });
    const scale = 6;
    const margin = 4;
    const size = modules.size;
    canvas.width = canvas.height = (size + margin * 2) * scale;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('Canvas unavailable');
    const cells = [];
    for (let row = 0; row < size; row++) for (let col = 0; col < size; col++) {
        if (!modules.get(row, col)) continue;
        const marker = (row < 7 && (col < 7 || col >= size - 7)) || (row >= size - 7 && col < 7);
        const scatter = ((row * 73 + col * 151 + row * col * 19) % 101) / 100;
        const distance = Math.hypot(row - size / 2, col - size / 2) / size;
        cells.push({ row, col, delay: marker ? scatter * 100 : 180 + distance * 460 + scatter * 450 });
    }
    const draw = elapsed => {
        context.globalAlpha = 1;
        context.fillStyle = '#b8bdc5';
        context.fillRect(0, 0, canvas.width, canvas.height);
        context.fillStyle = '#111214';
        for (const cell of cells) {
            const progress = Math.max(0, Math.min(1, (elapsed - cell.delay) / 260));
            if (!progress) continue;
            const eased = 1 - (1 - progress) ** 3;
            const width = scale * eased;
            const inset = (scale - width) / 2;
            context.globalAlpha = eased;
            context.fillRect((cell.col + margin) * scale + inset, (cell.row + margin) * scale + inset, width, width);
        }
        context.globalAlpha = 1;
    };
    let frame;
    if (!animate) {
        draw(Infinity);
        onReady();
    } else {
        draw(0);
        let start;
        const tick = now => {
            start ??= now;
            const elapsed = now - start;
            draw(elapsed);
            if (elapsed < 1250) frame = requestAnimationFrame(tick);
            else { draw(Infinity); onReady(); }
        };
        frame = requestAnimationFrame(tick);
    }
    return () => cancelAnimationFrame(frame);
}
