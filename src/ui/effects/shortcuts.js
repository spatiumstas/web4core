import { el } from '../dom.js';

export function initShortcuts() {
    const modifier = document.getElementById('shortcutModifier');
    if (modifier && /Mac|iPhone|iPad/.test(navigator.platform)) modifier.textContent = '⌘';
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.code === 'KeyS') {
            e.preventDefault();
            el.gen?.click();
        }
    });
}
