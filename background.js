/**
 * background.js — Service worker
 * Monitors tabs for logout events and triggers auto-login injection.
 */

// Inject totp.js into service worker scope
importScripts('totp.js');

// ─── Helpers ────────────────────────────────────────────────────────────────

function extractDomain(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Load all saved site configs from storage.
 * Returns: { [domain]: { username, password, totpSecret, loginUrlPatterns, enabled } }
 */
async function getAllConfigs() {
  const result = await chrome.storage.local.get('siteConfigs');
  return result.siteConfigs || {};
}

/**
 * Check if a given URL matches any logout/login trigger patterns for a domain.
 */
function isLogoutUrl(url, patterns) {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some(p => p.trim() && url.includes(p.trim()));
}

// ─── Tab monitoring ──────────────────────────────────────────────────────────

async function handleTabUpdate(tabId, url) {
  if (!url || url.startsWith('chrome://')) return;

  const domain = extractDomain(url);
  if (!domain) return;

  const configs = await getAllConfigs();
  const config = configs[domain];

  if (!config || !config.enabled) return;
  if (!isLogoutUrl(url, config.loginUrlPatterns)) return;

  console.log(`[AutoLogin] Logout detected on ${domain}, injecting login script...`);

  // Small delay to let the page settle
  setTimeout(async () => {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['totp.js']
      });
      await chrome.scripting.executeScript({
        target: { tabId },
        func: performLogin,
        args: [config]
      });
    } catch (err) {
      console.error('[AutoLogin] Injection failed:', err);
    }
  }, 1200);
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    handleTabUpdate(tabId, tab.url);
  }
});

// ─── Manual trigger from popup ───────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'triggerLogin') {
    const { tabId, config } = message;
    (async () => {
      try {
        await chrome.scripting.executeScript({ target: { tabId }, files: ['totp.js'] });
        await chrome.scripting.executeScript({
          target: { tabId },
          func: performLogin,
          args: [config]
        });
        sendResponse({ success: true });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true; // async response
  }

  if (message.action === 'generateTOTP') {
    (async () => {
      try {
        const code = await generateTOTP(message.secret);
        const remaining = totpSecondsRemaining();
        sendResponse({ success: true, code, remaining });
      } catch (err) {
        sendResponse({ success: false, error: err.message });
      }
    })();
    return true;
  }
});

// ─── performLogin ─────────────────────────────────────────────────────────────
// This function is serialized and injected into the target page's context.
// It CANNOT reference any variables from the outer background.js scope.

function performLogin(config) {
  const log = (msg) => console.log(`[AutoLogin] ${msg}`);

  // ── Utility: wait for an element matching selector to appear ──────────────
  function waitForElement(selector, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const el = document.querySelector(selector);
      if (el) return resolve(el);
      const observer = new MutationObserver(() => {
        const found = document.querySelector(selector);
        if (found) {
          observer.disconnect();
          resolve(found);
        }
      });
      observer.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => {
        observer.disconnect();
        reject(new Error(`Timeout waiting for: ${selector}`));
      }, timeout);
    });
  }

  // ── Utility: fill a field and fire React/Vue-compatible events ────────────
  function fillField(el, value) {
    el.focus();
    // Native input value setter (works with React controlled inputs)
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    )?.set;
    if (nativeInputValueSetter) {
      nativeInputValueSetter.call(el, value);
    } else {
      el.value = value;
    }
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // ── Utility: find input by a list of selectors, first match wins ──────────
  function findInput(selectors) {
    for (const sel of selectors) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return null;
  }

  // ── Utility: find submit button ───────────────────────────────────────────
  function findSubmitButton() {
    return (
      document.querySelector('button[type="submit"]') ||
      document.querySelector('input[type="submit"]') ||
      document.querySelector('button:not([type="button"])') ||
      Array.from(document.querySelectorAll('button')).find(b =>
        /sign.?in|log.?in|continue|next|submit/i.test(b.textContent)
      )
    );
  }

  // ── TOTP generation (inline, since we can't import modules in injected fn) ─
  async function genTOTP(secret, digits = 6, period = 30) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const s = secret.toUpperCase().replace(/[\s\-=]/g, '');
    let bits = 0, value = 0, index = 0;
    const output = new Uint8Array(Math.floor((s.length * 5) / 8));
    for (let i = 0; i < s.length; i++) {
      const idx = alphabet.indexOf(s[i]);
      if (idx === -1) throw new Error(`Bad char: ${s[i]}`);
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) { output[index++] = (value >>> (bits - 8)) & 0xff; bits -= 8; }
    }
    const counter = Math.floor(Date.now() / 1000 / period);
    const buf = new ArrayBuffer(8);
    const dv = new DataView(buf);
    dv.setUint32(0, Math.floor(counter / 0x100000000), false);
    dv.setUint32(4, counter >>> 0, false);
    const key = await crypto.subtle.importKey('raw', output, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
    const off = sig[sig.length - 1] & 0x0f;
    const code = (((sig[off] & 0x7f) << 24) | ((sig[off+1] & 0xff) << 16) | ((sig[off+2] & 0xff) << 8) | (sig[off+3] & 0xff)) % Math.pow(10, digits);
    return code.toString().padStart(digits, '0');
  }

  // ── Main login flow ───────────────────────────────────────────────────────
  (async () => {
    try {
      log('Starting login flow...');

      const usernameSelectors = config.usernameSelector
        ? [config.usernameSelector]
        : [
            'input[name="username"]', 'input[name="email"]', 'input[name="user"]',
            'input[type="email"]', 'input[id*="user"]', 'input[id*="email"]',
            'input[autocomplete="username"]', 'input[autocomplete="email"]'
          ];

      const passwordSelectors = config.passwordSelector
        ? [config.passwordSelector]
        : [
            'input[type="password"]', 'input[name="password"]',
            'input[id*="pass"]', 'input[autocomplete="current-password"]'
          ];

      const totpSelectors = config.totpSelector
        ? [config.totpSelector]
        : [
            'input[name="token"]', 'input[name="otp"]', 'input[name="totp"]',
            'input[name="code"]', 'input[name="mfa"]', 'input[name="two_factor"]',
            'input[id*="otp"]', 'input[id*="totp"]', 'input[id*="mfa"]',
            'input[id*="code"]', 'input[autocomplete="one-time-code"]',
            'input[inputmode="numeric"]'
          ];

      // Step 1: Fill username
      let usernameField = findInput(usernameSelectors);
      if (!usernameField) {
        log('Username field not found immediately, waiting...');
        usernameField = await waitForElement(usernameSelectors[0]);
      }
      fillField(usernameField, config.username);
      log(`Filled username: ${config.username}`);
      await new Promise(r => setTimeout(r, 300));

      // Step 2: Fill password (may be on same page or after clicking Next)
      let passwordField = findInput(passwordSelectors);

      if (!passwordField) {
        // Some sites show user first, then password after clicking Next
        log('Password field not visible — trying Next button first...');
        const nextBtn = findSubmitButton();
        if (nextBtn) {
          nextBtn.click();
          log('Clicked Next/Continue...');
          await new Promise(r => setTimeout(r, 1500));
        }
        passwordField = findInput(passwordSelectors);
      }

      if (!passwordField) {
        log('Waiting for password field...');
        passwordField = await waitForElement(passwordSelectors[0]);
      }

      fillField(passwordField, config.password);
      log('Filled password.');
      await new Promise(r => setTimeout(r, 300));

      // Step 3: Submit credentials
      const submitBtn = findSubmitButton();
      if (submitBtn) {
        submitBtn.click();
        log('Submitted login form.');
      } else {
        passwordField.form?.submit();
        log('Submitted via form.submit().');
      }

      // Step 4: Wait for TOTP field (if secret provided)
      if (config.totpSecret) {
        log('Waiting for TOTP field...');
        await new Promise(r => setTimeout(r, 2000));

        let totpField = findInput(totpSelectors);
        if (!totpField) {
          try {
            // Try each TOTP selector
            for (const sel of totpSelectors) {
              try {
                totpField = await Promise.race([
                  waitForElement(sel, 5000),
                  new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000))
                ]);
                if (totpField) break;
              } catch { /* try next */ }
            }
          } catch {
            log('TOTP field not found. Skipping TOTP step.');
          }
        }

        if (totpField) {
          const code = await genTOTP(config.totpSecret);
          fillField(totpField, code);
          log(`Filled TOTP: ${code}`);
          await new Promise(r => setTimeout(r, 300));

          const totpSubmit = findSubmitButton();
          if (totpSubmit) {
            totpSubmit.click();
            log('Submitted TOTP form.');
          }
        }
      }

      log('Login flow complete.');
    } catch (err) {
      console.error('[AutoLogin] Login error:', err);
    }
  })();
}
