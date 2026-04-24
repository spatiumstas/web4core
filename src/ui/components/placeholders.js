import { el } from '../dom.js';
import {
    PLACEHOLDER_MIHOMO,
    PLACEHOLDER_SINGBOX_BASE,
    PLACEHOLDER_SINGBOX_EXTENDED,
    PLACEHOLDER_XRAY,
} from '../constants.js';

export function updateLinksPlaceholder(core, useExtended) {
    if (!el.links) return;

    let lines = PLACEHOLDER_SINGBOX_BASE;
    if (core === 'singbox') {
        lines = useExtended
            ? [...PLACEHOLDER_SINGBOX_BASE, ...PLACEHOLDER_SINGBOX_EXTENDED]
            : PLACEHOLDER_SINGBOX_BASE;
    } else if (core === 'xray') {
        lines = PLACEHOLDER_XRAY;
    } else if (core === 'mihomo') {
        lines = PLACEHOLDER_MIHOMO;
    }

    el.links.placeholder = lines.join('\n') + '\n';
}
