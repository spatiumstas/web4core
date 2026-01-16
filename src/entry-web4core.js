import './parseuri.min.js';

import {
  buildBeansFromInput,
  computeTag,
  getAllowedCoreProtocols,
  validateBean,
} from './main.js';

import { buildSingBoxConfig, buildSingBoxOutbound } from './core/singbox.js';
import { buildXrayConfig, buildXrayOutbound } from './core/xray.js';
import { buildMihomoConfig, buildMihomoProxy, buildMihomoSubscriptionConfig } from './core/mihomo.js';
import { buildMihomoYaml } from './core/yaml.js';
import { fetchSubscription } from './core/subscription.js';
import { parseWireGuardConf } from './core/wireguard.js';
import { buildFromRequest } from './build.js';

globalThis.web4core = Object.assign({}, globalThis.web4core || {}, {
  buildBeansFromInput,
  validateBean,
  computeTag,
  getAllowedCoreProtocols,
  buildSingBoxOutbound,
  buildSingBoxConfig,
  buildXrayOutbound,
  buildXrayConfig,
  buildMihomoProxy,
  buildMihomoConfig,
  buildMihomoSubscriptionConfig,
  buildMihomoYaml,
  parseWireGuardConf,
  fetchSubscription,
  buildFromRequest,
});


