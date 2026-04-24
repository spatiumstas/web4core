import { el } from '../dom.js';
import { MSG_SUB_EMPTY, MSG_SUB_FETCH } from '../constants.js';
import { canFetchSubscription, fetchSubscription } from '../services/web4core-api.js';
import { detectSubscriptionUrl } from '../services/subscription-input.js';
import { isMihomoSubscriptionMode } from '../components/core-toggle.js';
import {
    hideOutput,
    markInputError,
    scrollOutIntoView,
    setError,
    setGenerateEnabled,
    setInputLoading,
} from '../components/output-panel.js';
import { validateField } from './validation.js';

async function expandSubscriptions(raw, detected) {
    const texts = await Promise.all(detected.subUrls.map((u) => fetchSubscription(u)));
    const merged = [];
    for (const text of texts) {
        if (!text) throw new Error(MSG_SUB_EMPTY);
        merged.push(...text.split(/\r?\n/).map(s => s.trim()).filter(Boolean));
    }
    const combined = [...detected.others, ...merged].join('\n');
    if (!combined.trim()) throw new Error(MSG_SUB_EMPTY);
    return combined;
}

export function initGenerateController() {
    el.gen?.addEventListener('click', async () => {
        const raw = (el.links?.value || '').trim();
        const detected = detectSubscriptionUrl(raw);
        const hasSub = Array.isArray(detected.subUrls) && detected.subUrls.length > 0;
        const skipBecauseMihomoProvider = isMihomoSubscriptionMode();

        if (hasSub && !skipBecauseMihomoProvider && canFetchSubscription()) {
            setGenerateEnabled(false);
            setInputLoading(true);
            setError('');
            try {
                el.links.value = await expandSubscriptions(raw, detected);
                validateField(true);
                scrollOutIntoView();
            } catch (e) {
                const msg = (e && e.message) ? e.message : 'Network error';
                setError(MSG_SUB_FETCH(msg));
                hideOutput();
                markInputError(true);
            } finally {
                setGenerateEnabled(true);
                setInputLoading(false);
            }
            return;
        }

        const ok = validateField(true);
        if (ok) scrollOutIntoView();
    });
}
