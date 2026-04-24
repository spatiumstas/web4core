export function initSnowfall() {
    const month = new Date().getMonth();
    if (month !== 11 && month !== 0 && month !== 1) return;
    if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
    if (document.getElementById('snowfall')) return;

    const rand = (a, b) => Math.random() * (b - a) + a;
    const glyphs = ['❄', '✻', '✼', '❅', '❆'];
    const root = document.body.appendChild(Object.assign(document.createElement('div'), {
        id: 'snowfall',
        className: 'snowfall',
    }));
    root.setAttribute('aria-hidden', 'true');

    const frag = document.createDocumentFragment();
    for (let i = 0; i < 16; i++) {
        const flake = document.createElement('div');
        flake.className = 'snowfall__flake';
        flake.style.cssText =
            `left:${rand(0, 100).toFixed(2)}vw;` +
            `animation-duration:${rand(10, 20).toFixed(2)}s;` +
            `animation-delay:${rand(-14, 0).toFixed(2)}s;` +
            `--snowfall-size:${rand(10, 18).toFixed(1)}px;` +
            `--snowfall-opacity:${rand(0.35, 0.9).toFixed(2)};` +
            `--snowfall-sway:${rand(10, 28).toFixed(1)}px;`;

        const glyph = document.createElement('span');
        glyph.className = 'snowfall__glyph';
        glyph.textContent = glyphs[Math.floor(rand(0, glyphs.length))];

        flake.appendChild(glyph);
        frag.appendChild(flake);
    }
    root.appendChild(frag);
}
