/**
 * popup.js — AutoLogin extension popup logic
 */

// ─── TOTP (inline, for popup context) ────────────────────────────────────────

function base32Decode(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const s = base32.toUpperCase().replace(/[\s\-=]/g, '');
  let bits = 0, value = 0, index = 0;
  const output = new Uint8Array(Math.floor((s.length * 5) / 8));
  for (let i = 0; i < s.length; i++) {
    const idx = alphabet.indexOf(s[i]);
    if (idx === -1) throw new Error(`Invalid base32 char: ${s[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output[index++] = (value >>> (bits - 8)) & 0xff; bits -= 8; }
  }
  return output;
}

async function generateTOTP(secret, digits = 6, period = 30) {
  const keyBytes = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / period);
  const buf = new ArrayBuffer(8);
  const dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000), false);
  dv.setUint32(4, counter >>> 0, false);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = sig[sig.length - 1] & 0x0f;
  const code = (((sig[off] & 0x7f) << 24) | ((sig[off+1] & 0xff) << 16) | ((sig[off+2] & 0xff) << 8) | (sig[off+3] & 0xff)) % Math.pow(10, digits);
  return code.toString().padStart(digits, '0');
}

function totpSecondsRemaining(period = 30) {
  return period - (Math.floor(Date.now() / 1000) % period);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractDomain(url) {
  try { return new URL(url).hostname; } catch { return null; }
}

/**
 * Returns true if `pattern` matches `hostname`.
 * Supports a leading wildcard: *.gxc.io matches portal-dev.gxc.io and idp-dev.gxc.io.
 * Also supports mid-prefix wildcards like *dev.gxc.io.
 */
function matchesDomain(pattern, hostname) {
  if (pattern === hostname) return true;
  if (pattern.startsWith('*')) {
    const suffix = pattern.slice(1); // e.g. '.gxc.io' or 'dev.gxc.io'
    return hostname.endsWith(suffix);
  }
  return false;
}

/**
 * Find the config key (exact or wildcard) that matches `domain`.
 * Returns the key string, or null if none found.
 */
function findMatchingConfigKey(configs, domain) {
  if (configs[domain]) return domain;
  for (const key of Object.keys(configs)) {
    if (key.includes('*') && matchesDomain(key, domain)) return key;
  }
  return null;
}

async function getAllConfigs() {
  const r = await chrome.storage.local.get('siteConfigs');
  return r.siteConfigs || {};
}

async function saveConfig(key, config) {
  const all = await getAllConfigs();
  all[key] = config;
  await chrome.storage.local.set({ siteConfigs: all });
}

async function deleteConfig(key) {
  const all = await getAllConfigs();
  delete all[key];
  await chrome.storage.local.set({ siteConfigs: all });
}

// ─── Login steps helpers ──────────────────────────────────────────────────────

/**
 * Convert loginSteps array to multi-line text.
 * Format per line: urlPattern | action  (| linkText for clickLink)
 */
function stepsToText(steps) {
  if (!steps || steps.length === 0) return '';
  return steps.map(s => {
    const parts = [s.urlPattern, s.action];
    if (s.linkText) parts.push(s.linkText);
    return parts.join(' | ');
  }).join('\n');
}

/**
 * Parse multi-line text into loginSteps array.
 */
function textToSteps(text) {
  return text.split('\n')
    .map(line => line.trim())
    .filter(Boolean)
    .map(line => {
      const parts = line.split('|').map(p => p.trim());
      const step = { urlPattern: parts[0], action: parts[1] };
      if (parts[2]) step.linkText = parts[2];
      return step;
    })
    .filter(s => s.urlPattern && s.action);
}

function showToast(msg, type = '') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `show ${type}`;
  setTimeout(() => { t.className = ''; }, 2200);
}

// ─── State ────────────────────────────────────────────────────────────────────

let currentTab = null;
let currentDomain = null;
let totpInterval = null;

// ─── Tab switching ────────────────────────────────────────────────────────────

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`panel-${tab.dataset.tab}`).classList.add('active');
    if (tab.dataset.tab === 'sites') renderSitesList();
    if (tab.dataset.tab === 'totp') syncTotpPreviewFromConfig();
  });
});

// ─── Password toggles ─────────────────────────────────────────────────────────

function makeEyeToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  if (!btn || !input) return;
  btn.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    btn.querySelector('svg').innerHTML = show
      ? `<path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>`
      : `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
  });
}
makeEyeToggle('toggle-pass', 'password');
makeEyeToggle('toggle-totp', 'totp-secret');
makeEyeToggle('toggle-totp-preview', 'totp-preview-secret');

// ─── Advanced section toggle ───────────────────────────────────────────────────

document.getElementById('adv-toggle').addEventListener('click', () => {
  const body = document.getElementById('adv-body');
  const chevron = document.getElementById('adv-chevron');
  const open = body.classList.toggle('open');
  chevron.classList.toggle('open', open);
});

// ─── Load current tab & config ────────────────────────────────────────────────

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentTab = tab;
  currentDomain = tab?.url ? extractDomain(tab.url) : null;

  const urlEl = document.getElementById('current-url');
  const keyInput = document.getElementById('config-key');
  const dot = document.getElementById('status-dot');

  if (currentDomain) {
    urlEl.textContent = currentDomain;
    const configs = await getAllConfigs();
    // Find exact or wildcard match for the current domain
    const matchedKey = findMatchingConfigKey(configs, currentDomain);
    const cfg = matchedKey ? configs[matchedKey] : null;

    // Populate the editable key field (matched wildcard key, or current domain as default)
    keyInput.value = matchedKey || currentDomain;

    if (cfg) {
      // Populate form
      document.getElementById('username').value = cfg.username || '';
      document.getElementById('password').value = cfg.password || '';
      document.getElementById('totp-secret').value = cfg.totpSecret || '';
      document.getElementById('username-sel').value = cfg.usernameSelector || '';
      document.getElementById('password-sel').value = cfg.passwordSelector || '';
      document.getElementById('totp-sel').value = cfg.totpSelector || '';
      document.getElementById('login-steps').value = stepsToText(cfg.loginSteps);
      dot.classList.add('enabled');
    }
  } else {
    urlEl.textContent = 'No active tab';
    keyInput.value = '';
  }
}

init();

// ─── Save ─────────────────────────────────────────────────────────────────────

document.getElementById('btn-save').addEventListener('click', async () => {
  const configKey = document.getElementById('config-key').value.trim();
  if (!configKey) { showToast('No config key', 'error'); return; }

  const config = {
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value,
    totpSecret: document.getElementById('totp-secret').value.trim(),
    loginSteps: textToSteps(document.getElementById('login-steps').value),
    usernameSelector: document.getElementById('username-sel').value.trim(),
    passwordSelector: document.getElementById('password-sel').value.trim(),
    totpSelector: document.getElementById('totp-sel').value.trim(),
  };

  if (!config.username || !config.password) {
    showToast('Username and password required', 'error');
    return;
  }

  await saveConfig(configKey, config);
  document.getElementById('status-dot').classList.add('enabled');
  showToast('Saved ✓', 'success');
});

// ─── Clear ────────────────────────────────────────────────────────────────────

document.getElementById('btn-clear').addEventListener('click', async () => {
  const configKey = document.getElementById('config-key').value.trim() || currentDomain;
  if (!configKey) return;
  if (!confirm(`Clear config for ${configKey}?`)) return;
  await deleteConfig(configKey);
  ['username','password','totp-secret','login-steps','username-sel','password-sel','totp-sel']
    .forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('status-dot').className = 'tab-dot';
  showToast('Cleared', '');
});

// ─── Login Now ────────────────────────────────────────────────────────────────

document.getElementById('btn-login-now').addEventListener('click', async () => {
  if (!currentTab) { showToast('No active tab', 'error'); return; }

  const config = {
    username: document.getElementById('username').value.trim(),
    password: document.getElementById('password').value,
    totpSecret: document.getElementById('totp-secret').value.trim(),
    loginSteps: textToSteps(document.getElementById('login-steps').value),
    usernameSelector: document.getElementById('username-sel').value.trim(),
    passwordSelector: document.getElementById('password-sel').value.trim(),
    totpSelector: document.getElementById('totp-sel').value.trim(),
  };

  if (!config.username || !config.password) {
    showToast('Username and password required', 'error');
    return;
  }

  const btn = document.getElementById('btn-login-now');
  btn.disabled = true;
  btn.textContent = '...';

  const response = await chrome.runtime.sendMessage({
    action: 'triggerLogin',
    tabId: currentTab.id,
    tabUrl: currentTab.url,
    config
  });

  btn.disabled = false;
  btn.textContent = '▶ Login Now';

  if (response?.success) {
    showToast('Login triggered ✓', 'success');
  } else {
    showToast(`Error: ${response?.error || 'unknown'}`, 'error');
  }
});

// ─── TOTP Preview tab ─────────────────────────────────────────────────────────

async function syncTotpPreviewFromConfig() {
  if (!currentDomain) return;
  const configs = await getAllConfigs();
  const cfg = configs[currentDomain];
  if (cfg?.totpSecret) {
    document.getElementById('totp-preview-secret').value = cfg.totpSecret;
    startTotpPreview();
  }
}

function startTotpPreview() {
  if (totpInterval) clearInterval(totpInterval);
  updateTotpPreview();
  totpInterval = setInterval(updateTotpPreview, 1000);
}

async function updateTotpPreview() {
  const secret = document.getElementById('totp-preview-secret').value.trim();
  const codeEl = document.getElementById('totp-live-code');
  const secsEl = document.getElementById('timer-secs');
  const barEl = document.getElementById('timer-bar');

  if (!secret) {
    codeEl.textContent = '------';
    secsEl.textContent = '-- sec';
    barEl.style.width = '0%';
    return;
  }

  try {
    const code = await generateTOTP(secret);
    const remaining = totpSecondsRemaining();
    const pct = (remaining / 30) * 100;

    codeEl.textContent = code.slice(0, 3) + ' ' + code.slice(3);
    secsEl.textContent = `${remaining}s`;
    barEl.style.width = `${pct}%`;
    barEl.className = 'timer-bar' + (remaining <= 5 ? ' danger' : remaining <= 10 ? ' warn' : '');
  } catch {
    codeEl.textContent = 'ERR';
  }
}

document.getElementById('totp-preview-secret').addEventListener('input', () => {
  startTotpPreview();
});

document.getElementById('btn-copy-totp').addEventListener('click', async () => {
  const code = document.getElementById('totp-live-code').textContent.replace(/\s/g, '');
  if (code && code !== '------' && code !== 'ERR') {
    await navigator.clipboard.writeText(code);
    showToast('Copied!', 'success');
  }
});

// ─── Sites list ───────────────────────────────────────────────────────────────

async function renderSitesList() {
  const list = document.getElementById('sites-list');
  const configs = await getAllConfigs();
  const domains = Object.keys(configs);

  if (domains.length === 0) {
    list.innerHTML = '<div class="empty-state">No sites configured yet.</div>';
    return;
  }

  list.innerHTML = domains.map(domain => {
    const cfg = configs[domain];
    return `
      <div class="site-item">
        <div class="site-dot on"></div>
        <div class="site-info">
          <div class="site-domain">${domain}</div>
          <div class="site-user">${cfg.username || '—'} ${cfg.totpSecret ? '· TOTP ✓' : ''}</div>
        </div>
        <div class="site-actions">
          <button class="icon-btn del" title="Delete" data-action="delete" data-domain="${domain}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4h6v2"/>
            </svg>
          </button>
        </div>
      </div>
    `;
  }).join('');

  list.querySelectorAll('[data-action]').forEach(btn => {
    btn.addEventListener('click', async () => {
      const domain = btn.dataset.domain;
      const action = btn.dataset.action;
      const configs = await getAllConfigs();

      if (action === 'delete') {
        if (!confirm(`Delete config for ${domain}?`)) return;
        await deleteConfig(domain);
        renderSitesList();
      }
    });
  });
}
