import { header } from '../dom.js';

export function initHeaderReload() {
    header?.addEventListener('click', (e) => {
        const target = e?.target?.closest?.('a,button,input,textarea,select,label');
        if (target) return;
        setTimeout(() => location.reload(), 0);
    });
}
