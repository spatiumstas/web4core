function api() {
    return globalThis.web4core || {};
}

const subscriptionHwids = new Map();

export function getUrlTestChoices() {
    return Array.isArray(api().URLTEST_CHOICES) ? api().URLTEST_CHOICES : [];
}

export function buildBeansFromInput(input) {
    return api().buildBeansFromInput(input);
}

export function validateBean(bean) {
    return api().validateBean(bean);
}

export function getAllowedCoreProtocols(core, options) {
    return api().getAllowedCoreProtocols ? api().getAllowedCoreProtocols(core, options) : [];
}

export function buildFromRequest(request) {
    return api().buildFromRequest(request);
}

export function buildMihomoSubscriptionConfig(subscriptionUrls, extraBeans, options) {
    return api().buildMihomoSubscriptionConfig?.(subscriptionUrls, extraBeans, { ...options, subscriptionHwids });
}

export function buildMihomoYaml(proxies, groups, providers, rules, listeners, options) {
    return api().buildMihomoYaml?.(proxies, groups, providers, rules, listeners, options);
}

export function parseWireGuardConf(text, nameHint) {
    return api().parseWireGuardConf?.(text, nameHint);
}

export function fetchSubscription(url, options) {
    return api().fetchSubscription?.(url, { ...options, subscriptionHwids });
}

export function canFetchSubscription() {
    return typeof api().fetchSubscription === 'function';
}
