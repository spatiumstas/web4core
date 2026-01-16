const fs = require('fs');
const vm = require('vm');

function loadRuntimeJs() {
  const p = 'src/web4core.runtime.js';
  return fs.readFileSync(p, 'utf8');
}

function createSandbox() {
  const url = require('url');
  const sandbox = {
    console,
    require,
    module: { exports: {} },
    exports: {},
    global,
    process,
    Buffer,
    setTimeout,
    setInterval,
    clearTimeout,
    clearInterval,
    URL: url.URL,
    URLSearchParams: url.URLSearchParams,
    atob: (str) => Buffer.from(str, 'base64').toString('binary'),
    btoa: (str) => Buffer.from(str, 'binary').toString('base64'),
  };

  vm.createContext(sandbox);
  sandbox.globalThis = sandbox;
  return sandbox;
}

function loadWeb4core() {
  const sandbox = createSandbox();
  const runtimeJs = loadRuntimeJs();
  vm.runInContext(runtimeJs, sandbox);
  const api = sandbox.web4core || {};
  Object.assign(sandbox, api);
  return sandbox;
}

function splitLinksFromEnv(name) {
  const raw = process.env[name] || '';
  return raw
    .split('\n')
    .map((s) => s.trim())
    .filter((s) => s && !s.startsWith('//') && !s.startsWith('#'))
    .filter((s) => s.includes('://'));
}

function safeLinkLabel(link, index) {
  const rawHash = link.includes('#') ? link.substring(link.lastIndexOf('#') + 1) : '';
  let linkName = '';
  try { linkName = decodeURIComponent(rawHash || ''); } catch {}
  if (!linkName || /:\/\//.test(linkName)) linkName = `Link-${index + 1}`;
  return linkName;
}

function execOrThrow(cmd, opts) {
  const { execSync } = require('child_process');
  try {
    return execSync(cmd, Object.assign({ stdio: 'pipe', encoding: 'utf8' }, opts || {}));
  } catch (e) {
    const stdout = e && e.stdout ? String(e.stdout) : '';
    const stderr = e && e.stderr ? String(e.stderr) : '';
    const msg = [
      `Command failed: ${cmd}`,
      e && e.message ? `Error: ${e.message}` : '',
      stdout ? `--- STDOUT ---\n${stdout}` : '',
      stderr ? `--- STDERR ---\n${stderr}` : '',
    ].filter(Boolean).join('\n');
    const err = new Error(msg);
    err.cause = e;
    throw err;
  }
}

module.exports = {
  loadWeb4core,
  splitLinksFromEnv,
  safeLinkLabel,
  execOrThrow,
};

