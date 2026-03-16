# AutoLogin Chrome Extension

A Chrome extension for manually triggering login flows on sites that require frequent re-authentication. Supports username/password, TOTP (2FA), and multi-page login flows.

---

## Installation

1. Clone or download this repo
2. Open Chrome → `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked** → select this folder

---

## Usage

1. Navigate to the site you want to configure
2. Click the **AutoLogin** extension icon
3. Fill in your credentials and save
4. When you're on a login page, click **▶ Login Now**

---

## Configuration Fields

| Field | Description |
|---|---|
| **Config key** | Domain that identifies this config. Supports wildcards (`*.yourcompany.io`) and pipe-separated multi-domain (`portal-qa.yourcompany.io\|portal-idp.yourcompany.io`) |
| **Username / Email** | Your login username or email |
| **Password** | Your password |
| **TOTP Secret** | Base32 TOTP secret key for 2FA (e.g. from your authenticator app) |

---

## Advanced: Multi-page Login Steps

Some sites spread login across multiple pages (e.g. SSO portals). Use the **Multi-page login steps** textarea to define a step per line:

```
urlPattern | action | optionalParam
```

### Actions

| Action | Description |
|---|---|
| `clickLink` | Click an anchor whose text or href contains the param. Falls back to autoDetect if not found. |
| `fillEmail` | Fill the email/username field and submit. Also fills password if it's present on the same page. |
| `fillEmailPassword` | Fill both email/username and password, then submit. |
| `fillOTP` | Fill the TOTP/OTP field and submit. |
| `autoDetect` | Inspect the page and automatically pick the right action (password → fillEmailPassword, OTP → fillOTP, email-only → fillEmail). |

### Example

```
SLO?execution= | clickLink | here
/login | fillEmail
SSO?execution= | autoDetect
```

- **SLO page** (post-logout): clicks the "here" link to return to login. If the link isn't found, falls back to autoDetect.
- **/login page**: fills the email field (and password too if visible on same page).
- **SSO page**: detects what's on the page — fills email+password, or OTP, depending on which step you're at.

### Config key for multi-domain flows

If your login flow spans two different domains (e.g. the portal is on one domain and the IDP is on another), use a pipe-separated config key:

```
portal-qa.yourcompany.io|portal-idp.yourcompany.io
```

Both domains will load the same config and login steps.

---

## Advanced: Custom CSS Selectors

If the auto-detection doesn't find the right fields, you can pin exact CSS selectors under **Advanced selectors**:

| Field | Example |
|---|---|
| Username selector | `input[name="j_username"]` |
| Password selector | `input[name="j_password"]` |
| TOTP selector | `input[name="otp"]` |

Leave blank to use auto-detection.

---

## TOTP Tab

The **TOTP** tab lets you preview your live 2FA code with a countdown timer — useful for manually copying codes.

---

## Sites Tab

The **Sites** tab lists all saved configs. Click the trash icon to delete a config.

---

## Notes

- Input fields are filled by simulating real keyboard events (keydown/keypress/input/keyup per character) to ensure sites that watch for keyboard activity enable their submit buttons correctly.
- No data leaves your browser. Everything is stored in `chrome.storage.local`.
