import { el } from '../dom.js';

export function initShortcuts() {
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.code === 'KeyS') {
            e.preventDefault();
            el.gen?.click();
        }
    });
}
