export const MSG_SUB_URL = 'Provide one or more HTTP(S) URLs for Mihomo subscription (one per line)';
export const MSG_SUB_EMPTY = 'Subscription returned no valid links';
export const MSG_SUB_FETCH = (m) => 'Failed to fetch subscription: ' + (m || '');
export const MSG_NO_LINKS = 'No valid links or profiles provided';
export const MSG_EXTENDED_ENABLE = 'Enable Extended to generate Mieru/SDNS configurations';

export const PLACEHOLDER_SINGBOX_BASE = [
    'subscription links',
    'vless://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...',
    'tuic://...',
    'anytls://...'
];

export const PLACEHOLDER_SINGBOX_EXTENDED = [
    'mieru://... or mierus://... (or json)',
    'sdns://...'
];

export const PLACEHOLDER_XRAY = [
    'subscription links',
    'vless://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...'
];

export const PLACEHOLDER_MIHOMO = [
    'subscription links',
    'vless://...',
    'tt://...',
    'vmess://...',
    'trojan://...',
    'ss://...',
    'socks://...',
    'http://user:pass@host:port',
    'hy2://...',
    'tuic://...',
    'masque://...',
    'mieru://... or mierus://... (or json)'
];
