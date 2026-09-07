import { header } from '../dom.js';

export function initHeaderReload() {
    header?.addEventListener('click', () => location.reload());
    const logo = header?.querySelector('pre');
    if (!logo) return;
    const lines = logo.textContent.replace(/^\n/, '').trimEnd().split('\n');
    logo.replaceChildren(...lines.map((line, index) => {
        const span = document.createElement('span');
        span.className = 'ascii-line';
        span.style.setProperty('--line', String(index));
        span.textContent = line || ' ';
        return span;
    }));
}
