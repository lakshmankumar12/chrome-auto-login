/**
 * background.js — Service worker
 * Manual-only login injection triggered from the popup.
 */

// Inject totp.js into service worker scope
importScripts('totp.js');

// ─── Helpers ────────────────────────────────────────────────────────────────

async function getAllConfigs() {
  const result = await chrome.storage.local.get('siteConfigs');
  return result.siteConfigs || {};
}

// ─── Message handler ─────────────────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'triggerLogin') {
    const { tabId, tabUrl, config } = message;
    (async () => {
      try {
        await chrome.scripting.executeScript({ target: { tabId }, files: ['totp.js'] });
        // If the current URL matches a step in this config, run that step
        const step = tabUrl && config.loginSteps?.find(
          s => s.urlPattern && tabUrl.includes(s.urlPattern)
        );
        if (step) {
          await chrome.scripting.executeScript({
            target: { tabId },
            func: performStep,
            args: [config, step]
          });
        } else {
          await chrome.scripting.executeScript({
            target: { tabId },
            func: performLogin,
            args: [config]
          });
        }
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

// ─── performStep ──────────────────────────────────────────────────────────────
// Handles one step of a multi-page login flow.
// Serialized and injected into the target page — no outer-scope references allowed.

function performStep(config, step) {
  const log = (msg) => console.log(`[AutoLogin] ${msg}`);

  function waitForElement(selector, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const el = document.querySelector(selector);
      if (el) return resolve(el);
      const observer = new MutationObserver(() => {
        const found = document.querySelector(selector);
        if (found) { observer.disconnect(); resolve(found); }
      });
      observer.observe(document.body, { childList: true, subtree: true });
      setTimeout(() => { observer.disconnect(); reject(new Error(`Timeout: ${selector}`)); }, timeout);
    });
  }

  function fillField(el, value) {
    el.focus();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    // Clear first
    if (nativeSetter) { nativeSetter.call(el, ''); } else { el.value = ''; }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'deleteContentBackward' }));
    // Type each character to fire real keyboard events
    for (const char of value) {
      const next = el.value + char;
      el.dispatchEvent(new KeyboardEvent('keydown', { key: char, bubbles: true, cancelable: true, composed: true }));
      el.dispatchEvent(new KeyboardEvent('keypress', { key: char, charCode: char.charCodeAt(0), keyCode: char.charCodeAt(0), which: char.charCodeAt(0), bubbles: true, cancelable: true, composed: true }));
      if (nativeSetter) { nativeSetter.call(el, next); } else { el.value = next; }
      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, composed: true, inputType: 'insertText', data: char }));
      el.dispatchEvent(new KeyboardEvent('keyup', { key: char, bubbles: true, cancelable: true, composed: true }));
    }
    el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }

  function findInput(selectors) {
    for (const sel of selectors) {
      const els = document.querySelectorAll(sel);
      for (const el of els) {
        if (el.disabled || el.type === 'hidden') continue;
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') continue;
        return el;
      }
    }
    return null;
  }

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

  function hasCaptcha() {
    const selectors = [
      'iframe[src*="recaptcha"]',
      'iframe[src*="hcaptcha"]',
      'iframe[src*="captcha"]',
      'iframe[src*="challenges.cloudflare.com"]',
      '.g-recaptcha',
      '.h-captcha',
      '.cf-turnstile',
      '[data-sitekey]',
      '[class*="captcha"]',
      '[id*="captcha"]',
    ];
    return selectors.some(sel => document.querySelector(sel) !== null);
  }

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

  (async () => {
    try {
      log(`Step [${step.action}] on: ${window.location.href}`);

      if (hasCaptcha()) {
        log('Captcha detected — stopping auto-login on this page.');
        return;
      }

      if (step.action === 'clickLink') {
        // Find and click a link whose text or href contains linkText
        const linkText = (step.linkText || '').toLowerCase();
        const link = Array.from(document.querySelectorAll('a')).find(a =>
          a.textContent.trim().toLowerCase().includes(linkText) ||
          (a.href || '').toLowerCase().includes(linkText)
        );
        if (link) {
          link.click();
          log(`Clicked link: "${step.linkText}"`);
        } else {
          // Link not found — fall back to autoDetect so the page isn't wasted
          log(`Link not found: "${step.linkText}" — falling back to autoDetect`);
          step = { ...step, action: 'autoDetect' };
          // fall through to autoDetect below by re-invoking logic inline
          const _passSelectors = config.passwordSelector
            ? [config.passwordSelector]
            : ['input[type="password"]', 'input[name="password"]',
               'input[id*="pass"]', 'input[autocomplete="current-password"]'];
          const _emailSelectors = config.usernameSelector
            ? [config.usernameSelector]
            : ['input[type="email"]', 'input[name="email"]', 'input[name="username"]',
               'input[id*="email"]', 'input[id*="user"]',
               'input[autocomplete="username"]', 'input[autocomplete="email"]',
               'input[type="text"]'];
          const _totpSelectors = config.totpSelector
            ? [config.totpSelector]
            : ['input[name="token"]', 'input[name="otp"]', 'input[name="totp"]',
               'input[name="code"]', 'input[name="mfa"]', 'input[id*="otp"]',
               'input[id*="totp"]', 'input[id*="mfa"]', 'input[id*="code"]',
               'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]'];

          const _passField = findInput(_passSelectors);
          if (_passField) {
            let _emailField = findInput(_emailSelectors) ||
              Array.from(document.querySelectorAll('input')).find(el => {
                if (el.disabled || ['hidden','password','submit','button','checkbox','radio','file'].includes(el.type)) return false;
                const s = getComputedStyle(el);
                return s.display !== 'none' && s.visibility !== 'hidden';
              }) || null;
            if (_emailField) { fillField(_emailField, config.username); log('Filled email/username'); await new Promise(r => setTimeout(r, 300)); }
            fillField(_passField, config.password); log('Filled password');
            await new Promise(r => setTimeout(r, 300));
            const _btn = findSubmitButton();
            if (_btn) { _btn.click(); log('Submitted form'); } else { _passField.form?.submit(); }
          } else if (findInput(_totpSelectors)) {
            if (config.totpSecret) {
              const _tf = findInput(_totpSelectors);
              const _code = await genTOTP(config.totpSecret);
              fillField(_tf, _code); log(`Filled OTP: ${_code}`);
              await new Promise(r => setTimeout(r, 300));
              const _btn = findSubmitButton(); if (_btn) { _btn.click(); log('Submitted OTP form'); }
            }
          } else {
            // Only an email field — fill and submit
            let _emailField = findInput(_emailSelectors) ||
              Array.from(document.querySelectorAll('input')).find(el => {
                if (el.disabled || ['hidden','password','submit','button','checkbox','radio','file'].includes(el.type)) return false;
                const s = getComputedStyle(el);
                return s.display !== 'none' && s.visibility !== 'hidden';
              }) || null;
            if (_emailField) {
              fillField(_emailField, config.username); log('Filled email/username');
              await new Promise(r => setTimeout(r, 300));
              const _btn = findSubmitButton(); if (_btn) { _btn.click(); log('Submitted email form'); }
            } else {
              log('autoDetect fallback — no recognisable fields found');
            }
          }
        }

      } else if (step.action === 'fillEmail') {
        const emailSelectors = config.usernameSelector
          ? [config.usernameSelector]
          : ['input[type="email"]', 'input[name="email"]', 'input[name="username"]',
             'input[id*="email"]', 'input[id*="user"]',
             'input[autocomplete="email"]', 'input[autocomplete="username"]',
             'input[type="text"]'];
        let field = findInput(emailSelectors);
        if (!field) field = await waitForElement(emailSelectors[0]);
        fillField(field, config.username);
        log('Filled email');
        await new Promise(r => setTimeout(r, 300));
        // If a password field is also visible on this page, fill it too
        const passSelectors = config.passwordSelector
          ? [config.passwordSelector]
          : ['input[type="password"]', 'input[name="password"]',
             'input[id*="pass"]', 'input[autocomplete="current-password"]'];
        const passField = findInput(passSelectors);
        if (passField) {
          fillField(passField, config.password);
          log('Filled password (found alongside email field)');
          await new Promise(r => setTimeout(r, 300));
        }
        const btn = findSubmitButton();
        if (btn) { btn.click(); log('Submitted form'); }

      } else if (step.action === 'fillEmailPassword') {
        const emailSelectors = config.usernameSelector
          ? [config.usernameSelector]
          : ['input[type="email"]', 'input[name="email"]', 'input[name="username"]',
             'input[id*="email"]', 'input[id*="user"]',
             'input[autocomplete="username"]', 'input[autocomplete="email"]',
             'input[type="text"]'];
        let emailField = findInput(emailSelectors);
        if (!emailField) {
          // Last resort: first visible non-password text input
          emailField = Array.from(document.querySelectorAll('input')).find(el => {
            if (el.disabled || ['hidden','password','submit','button','checkbox','radio','file'].includes(el.type)) return false;
            const s = getComputedStyle(el);
            return s.display !== 'none' && s.visibility !== 'hidden';
          }) || null;
        }
        if (emailField) {
          fillField(emailField, config.username);
          log('Filled email/username');
          await new Promise(r => setTimeout(r, 300));
        } else {
          log('Email/username field not found');
        }
        const passSelectors = config.passwordSelector
          ? [config.passwordSelector]
          : ['input[type="password"]', 'input[name="password"]',
             'input[id*="pass"]', 'input[autocomplete="current-password"]'];
        let passField = findInput(passSelectors);
        if (!passField) passField = await waitForElement(passSelectors[0]);
        fillField(passField, config.password);
        log('Filled password');
        await new Promise(r => setTimeout(r, 300));
        const btn = findSubmitButton();
        if (btn) { btn.click(); log('Submitted email+password form'); }
        else { passField.form?.submit(); }

      } else if (step.action === 'fillOTP') {
        if (!config.totpSecret) { log('No TOTP secret configured, skipping'); return; }
        const totpSelectors = config.totpSelector
          ? [config.totpSelector]
          : ['input[name="token"]', 'input[name="otp"]', 'input[name="totp"]',
             'input[name="code"]', 'input[name="mfa"]', 'input[id*="otp"]',
             'input[id*="totp"]', 'input[id*="mfa"]', 'input[id*="code"]',
             'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]'];
        let totpField = findInput(totpSelectors);
        if (!totpField) {
          for (const sel of totpSelectors) {
            try {
              totpField = await Promise.race([
                waitForElement(sel, 5000),
                new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 5000))
              ]);
              if (totpField) break;
            } catch { /* try next */ }
          }
        }
        if (totpField) {
          const code = await genTOTP(config.totpSecret);
          fillField(totpField, code);
          log(`Filled OTP: ${code}`);
          await new Promise(r => setTimeout(r, 300));
          const btn = findSubmitButton();
          if (btn) { btn.click(); log('Submitted OTP form'); }
        } else {
          log('OTP field not found');
        }

      } else if (step.action === 'autoDetect') {
        // URL pattern matches multiple pages — detect by page content.
        // Priority: password field → fillEmailPassword; OTP field → fillOTP; link → clickLink
        const passSelectors = config.passwordSelector
          ? [config.passwordSelector]
          : ['input[type="password"]', 'input[name="password"]',
             'input[id*="pass"]', 'input[autocomplete="current-password"]'];
        const totpSelectors = config.totpSelector
          ? [config.totpSelector]
          : ['input[name="token"]', 'input[name="otp"]', 'input[name="totp"]',
             'input[name="code"]', 'input[name="mfa"]', 'input[id*="otp"]',
             'input[id*="totp"]', 'input[id*="mfa"]', 'input[id*="code"]',
             'input[autocomplete="one-time-code"]', 'input[inputmode="numeric"]'];

        const passField = findInput(passSelectors);
        if (passField) {
          log('autoDetect → password field found, running fillEmailPassword');
          const emailSelectors = config.usernameSelector
            ? [config.usernameSelector]
            : ['input[type="email"]', 'input[name="email"]', 'input[name="username"]',
               'input[id*="email"]', 'input[id*="user"]',
               'input[autocomplete="username"]', 'input[autocomplete="email"]',
               'input[type="text"]'];
          let emailField = findInput(emailSelectors);
          if (!emailField) {
            emailField = Array.from(document.querySelectorAll('input')).find(el => {
              if (el.disabled || ['hidden','password','submit','button','checkbox','radio','file'].includes(el.type)) return false;
              const s = getComputedStyle(el);
              return s.display !== 'none' && s.visibility !== 'hidden';
            }) || null;
          }
          if (emailField) {
            fillField(emailField, config.username);
            log('Filled email/username');
            await new Promise(r => setTimeout(r, 300));
          } else {
            log('autoDetect → email/username field not found');
          }
          fillField(passField, config.password);
          log('Filled password');
          await new Promise(r => setTimeout(r, 300));
          const btn = findSubmitButton();
          if (btn) { btn.click(); log('Submitted email+password form'); }
          else { passField.form?.submit(); }

        } else if (findInput(totpSelectors)) {
          log('autoDetect → OTP field found, running fillOTP');
          if (!config.totpSecret) { log('No TOTP secret configured, skipping'); return; }
          const totpField = findInput(totpSelectors);
          const code = await genTOTP(config.totpSecret);
          fillField(totpField, code);
          log(`Filled OTP: ${code}`);
          await new Promise(r => setTimeout(r, 300));
          const btn = findSubmitButton();
          if (btn) { btn.click(); log('Submitted OTP form'); }

        } else if (step.linkText) {
          // Fallback: try clicking a link (e.g. logout page with "here" link)
          const linkText = step.linkText.toLowerCase();
          const link = Array.from(document.querySelectorAll('a')).find(a =>
            a.textContent.trim().toLowerCase().includes(linkText)
          );
          if (link) { link.click(); log(`autoDetect → clicked link: "${step.linkText}"`); }
          else { log(`autoDetect → no recognisable fields or links found on page`); }

        } else {
          log('autoDetect → no recognisable fields found on this page, skipping');
        }
      }

      log(`Step [${step.action}] complete.`);
    } catch (err) {
      console.error('[AutoLogin] Step error:', err);
    }
  })();
}

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

  // ── Utility: fill a field by mimicking real character-by-character keyboard input ──
  function fillField(el, value) {
    el.focus();
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    // Clear first
    if (nativeSetter) { nativeSetter.call(el, ''); } else { el.value = ''; }
    el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, inputType: 'deleteContentBackward' }));
    // Type each character to fire real keyboard events
    for (const char of value) {
      const next = el.value + char;
      el.dispatchEvent(new KeyboardEvent('keydown', { key: char, bubbles: true, cancelable: true, composed: true }));
      el.dispatchEvent(new KeyboardEvent('keypress', { key: char, charCode: char.charCodeAt(0), keyCode: char.charCodeAt(0), which: char.charCodeAt(0), bubbles: true, cancelable: true, composed: true }));
      if (nativeSetter) { nativeSetter.call(el, next); } else { el.value = next; }
      el.dispatchEvent(new InputEvent('input', { bubbles: true, cancelable: true, composed: true, inputType: 'insertText', data: char }));
      el.dispatchEvent(new KeyboardEvent('keyup', { key: char, bubbles: true, cancelable: true, composed: true }));
    }
    el.dispatchEvent(new Event('change', { bubbles: true, composed: true }));
  }

  // ── Utility: find input by a list of selectors, first visible match wins ──
  function findInput(selectors) {
    for (const sel of selectors) {
      const els = document.querySelectorAll(sel);
      for (const el of els) {
        if (el.disabled || el.type === 'hidden') continue;
        const style = getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden') continue;
        return el;
      }
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

  // ── Captcha detection ─────────────────────────────────────────────────────
  function hasCaptcha() {
    const selectors = [
      'iframe[src*="recaptcha"]',
      'iframe[src*="hcaptcha"]',
      'iframe[src*="captcha"]',
      'iframe[src*="challenges.cloudflare.com"]',
      '.g-recaptcha',
      '.h-captcha',
      '.cf-turnstile',
      '[data-sitekey]',
      '[class*="captcha"]',
      '[id*="captcha"]',
    ];
    return selectors.some(sel => document.querySelector(sel) !== null);
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

      if (hasCaptcha()) {
        log('Captcha detected — stopping auto-login on this page.');
        return;
      }

      const usernameSelectors = config.usernameSelector
        ? [config.usernameSelector]
        : [
            'input[name="username"]', 'input[name="email"]', 'input[name="user"]',
            'input[type="email"]', 'input[id*="user"]', 'input[id*="email"]',
            'input[autocomplete="username"]', 'input[autocomplete="email"]',
            'input[type="text"]'
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
        log('Username field not found by selector, trying broad fallback...');
        // Immediately scan for any visible non-password text input
        usernameField = Array.from(document.querySelectorAll('input')).find(el => {
          if (el.disabled || ['hidden','password','submit','button','checkbox','radio','file'].includes(el.type)) return false;
          const s = getComputedStyle(el);
          return s.display !== 'none' && s.visibility !== 'hidden';
        }) || null;
      }
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
