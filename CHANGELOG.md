# Changelog

## [1.12.1] - 2026-10-13
### Security
- **Client IP behind a proxy could be spoofed**: with a trusted proxy configured, the plugin read the first address in `X-Forwarded-For`, which the visitor controls, so lockouts and rate limits could be dodged. The header is now read from the right, skipping trusted proxies.
- **Security key backups no longer store `wp-config.php`**: the Restore backup kept the whole file, database password included, in `wp_options`. It now keeps only the eight key lines, restores only those lines, and older backups are converted on upgrade.
- **Two-factor authentication**: see Changed below.

### Fixed
- **Fatal error when the plugin is installed twice** (`Cannot redeclare function adc_security()`): a second copy, such as an old `adc-core-security-1.3.7` folder next to `adc-security`, now stops loading and shows an admin notice naming the duplicate folder instead of crashing the site.

### Changed
- **2FA codes can only be used once** (RFC 6238 replay protection) at login, enrollment and re-authentication.
- **2FA brute-force limits per user**, in addition to the per-IP limit, and the pending login is cancelled after repeated failures.
- **Re-authentication for sensitive 2FA actions**: disabling 2FA or regenerating recovery codes needs a current authenticator or recovery code; an administrator disabling 2FA for another user confirms with their own password.
- **Audit and alerts**: successful 2FA logins and recovery-code use are logged, and the user is emailed when a recovery code is used or 2FA is turned off.
- **Stronger 2FA secret storage**: a separate derived key and authenticated encryption; existing secrets keep working and are upgraded on first use.
- Recovery codes cannot be spent twice by simultaneous requests, and the post-login redirect is validated.
- The CSP report endpoint is exempt from the general REST write limit; it has its own per-IP limit.

## [1.12.0] - 2026-10-13
### Added
- **Content-Security-Policy modes**: the single CSP checkbox is replaced by Off, Standard and Custom. Standard builds the policy from the sources you choose: service presets (Google Tag Manager, Google Analytics 4, and others, each with a description), plus an Advanced list per directive where each default source can be removed and extra domains can be added. A read-only preview shows the resulting policy as you edit. Custom sends the text you write and lists warnings for risky values such as `unsafe-eval` or wildcard sources.
- **Report-Only mode**: send `Content-Security-Policy-Report-Only` to test a policy without blocking anything. Reports are collected by a REST endpoint on the site and summarised in a new **Blocked sources** panel on the Hardening tab, with an **Allow** button per source (adds it to that directive) and a **Clear** button.
- **Referrer-Policy dropdown**: choose any of the eight valid values instead of the fixed `strict-origin-when-cross-origin`.
- **Permissions-Policy modes**: Standard keeps the existing camera, microphone, geolocation, payment and USB restrictions; Custom accepts feature entries such as `fullscreen=(self)` or `geolocation=(self "https://maps.example.com")`, validated on save.
- **HSTS settings**: configurable max age (minimum 300 seconds, default one year), an Include subdomains switch (on by default), and an opt-in Preload switch with a warning that preload is hard to undo.

### Fixed
- **Custom CSP ignored unless the CSP checkbox was ticked**: a saved custom policy now takes effect as soon as Custom mode is saved, with no off-and-on step. Sites that had CSP off stay off after the upgrade, and their existing custom text is kept for when they choose Custom.

## [1.11.0] - 2026-10-12
### Added
- **Virtual patching**: a new Hardening section with opt-in, request-level guards for WordPress core vulnerabilities that are exploited in the wild, so a site stays protected in the window between a CVE being published and the core update being installed. Three rules ship: `pagename` path traversal in any encoding depth (CVE-2026-87902, unauthenticated LFI/RCE in page-template resolution), unauthenticated `/wp-json/batch/v1` requests (CVE-2026-63030, the first half of the "wp2shell" pre-auth RCE chain) and `author__not_in` / `author__in` arguments passed over HTTP (CVE-2026-60137, the second half of the same chain). Rules are pattern-based rather than exploit-string based, match only attack-shaped input, and every hit is recorded in the Activity log as a `virtual_patch` event with the CVE reference. Rules are off by default.
- **Virtual patch monitor mode**: optional switch that logs rule hits without blocking, so the rules can be validated against real traffic before they enforce.
- **Known-vulnerability cross-reference (opt-in)**: the daily component scan can now match the installed WordPress core version and every active WordPress.org plugin against the free, open WPVulnerability database API — no API key and no account. Findings appear in the dashboard under the component health scan, count against the security score, and replace the previous assumption that real CVE data requires a paid feed. Lookups are cached for 12 hours and rotate across scan runs (max 25 component lookups per run), so a site with many plugins never fires an unbounded burst of HTTP requests. Only the core version and plugin slugs are sent — never users, URLs or content.
- **Auto-update support for the plugin itself**: the GitHub updater now registers the plugin in the `no_update` transient key when the installed version is current, exactly as a WordPress.org-hosted plugin does. Without it the plugin was missing from both transient keys, so `update-supported` stayed false and the per-plugin "Auto-updates" control on the Plugins screen had nothing to attach to.
- **Dashboard**: findings from the component health scan are now listed (component + detail, up to ten) instead of only being counted.
### Fixed
- **No confirmation when saving settings**: the settings form posts to `options.php`, which stores the standard "Settings saved." message (or a validation error) in the `settings_errors` transient and redirects back — but the settings screen never called `settings_errors()`, so the page silently reloaded and a save looked like it did nothing. The standard WordPress notice now appears on the tab the settings were saved from.
- **Release checksum asset**: the release workflow now publishes `adc-security.zip.sha256` alongside the archive. The SHA-256 verification added in 1.8.1 only runs when that asset exists, and no release had ever published one, so plugin updates were being installed without the integrity check the changelog claimed.

## [1.10.0] - 2026-09-17
### Added
- **WooCommerce checkout abuse protection** (new WooCommerce tab): server-side fraud prevention that covers both the classic (shortcode) checkout and the Checkout block (Store API). It throttles checkout submissions per IP, limits order velocity per IP, per billing email, per phone number and per billing address inside a configurable window, rejects disposable email domains, blocks bursts of failed orders (the card-testing signature), offers an invisible honeypot on the classic checkout, an optional Cloudflare Turnstile challenge before the order button, and a minimum interaction time measured once per session from the first cart or checkout interaction. Every blocked attempt is recorded in the Activity log. Monitor mode is on by default (log and flag, never block) so an upgrade does not start rejecting orders; uncheck it to enforce the rules.
- **Cart write throttle**: throttles add-to-cart and Store API cart writes per IP, so volumetric abuse is charged before it ever reaches checkout.
- **Origin / Referer enforcement (opt-in)**: can reject checkout requests that carry an Origin/Referer for another domain (or, in the stricter mode, no Origin/Referer at all) — the signature of API-only submissions that never loaded the store. Off by default because headless and multi-domain front-ends legitimately send a foreign origin.
- **Order security panel**: a Security meta box on the order edit screen shows the connection IP stored with the order and any monitor-mode flags with their reason codes. Registered with the official HPOS recipe (`shop_order` vs `wc_get_page_screen_id( 'shop-order' )`), so it shows on both the legacy orders screen and High-Performance Order Storage.
- **WooCommerce account-creation filters**: disposable/throwaway email domains (built-in list plus a custom domain textarea) are rejected at checkout and on registration; registration attempts are throttled per IP; the My Account form and the WordPress registration form get the same honeypot and filters; and two opt-in switches can remove the "create an account" option from checkout or hide the My Account registration form (including direct POSTs to it).
- **Disposable email domain filter**: the built-in provider list and the custom list can be extended from code with `adc_security_blocked_email_domains`.
- **Users screen columns**: the WordPress Users list now shows "Account Created" and "Last Login" (recorded on each successful login in `_adc_last_login`) and both columns are sortable, using the site's date and time formats. Sorting by last login keeps users who never logged in in the list instead of silently hiding them.
- The security score now includes a WooCommerce checkout protection check on stores where WooCommerce is active.
- Disposable email filter on the My Account **Account details** form, so a customer cannot switch to a throwaway address after registering.
- Lost-password protection: the login captcha/honeypot also run on `wp-login.php?action=lostpassword` and on the WooCommerce My Account reset form; Woo My Account resets are throttled per IP (wp-login.php POSTs already go through the login rate limiter).
- **Flagged** column and view on the orders list (legacy CPT and HPOS), so monitor-mode orders are visible without opening each order.
- Dashboard **WooCommerce** card: flagged vs blocked counts over 7 and 30 days when WooCommerce is active.

## [1.9.2] - 2026-08-19
### Added
- **Plugin/theme file integrity checks**: the weekly integrity scan now also compares every installed plugin and theme that's hosted on WordPress.org against its official checksums (`downloads.wordpress.org/plugin-checksums` / `theme-checksums`), not just WordPress core. This catches compromised plugin/theme files, which is where most real-world site compromises actually land. Premium/custom packages not on WordPress.org are silently skipped (no data available), same as core files would be if unreachable.
- **Have I Been Pwned password check**: opt-in check of new/reset passwords against the HIBP breached-password database using k-anonymity (only a 5-character SHA-1 hash prefix is sent; the password itself never leaves the server). Fails open on any API/network error so an HIBP outage never blocks logins.
- **Cron health monitoring**: the dashboard now warns when the audit-log cleanup, file integrity scan, or plugin health scan haven't run on schedule — the most common cause is WP-Cron being blocked or `DISABLE_WP_CRON` set without a real system cron replacing it, which would otherwise silently disable these features.

## [1.9.1] - 2026-08-18
### Changed
- **Documentation**: README now documents the Dashboard, 2FA, audit log, rate limiting, trusted-proxy support, and file integrity/plugin health scanning added in 1.9.0, plus configuration notes for the trusted proxy header and 2FA enrollment/recovery codes.
- **Admin CSS cleanup**: replaced the remaining inline `style="..."` attributes in the settings screens with classes in `assets/css/adc-admin.css`, so the admin UI's presentation lives in one stylesheet.

## [1.9.0] - 2026-08-18
### Fixed
- **"The link you followed has expired" on Login Security save**: the Blocked IP Addresses table rendered a nested `<form>` inside the Settings API's `options.php` form, which browsers flatten, corrupting the settings nonce whenever at least one IP was locked out. The table now renders after the settings form and unblocks via its own `admin-post.php` handler and nonce.
- Debug export report read the wrong option key for Blocked IPs and always showed "None".
- The plugin's "Settings" link on the Plugins page pointed at the wrong admin URL.
- `uninstall.php` now also removes the security-keys backup option and the per-IP/per-token brute-force and captcha transients.

### Added
- **Dashboard**: the Overview tab is now a real dashboard with four live cards — security score & checklist, login/lockout activity with a 30-day sparkline, users & sessions, and system/integrity status.
- **Audit Log**: a new `Activity` tab records logins, lockouts, denied IPs, user/role/plugin/theme changes, and settings changes to a dedicated database table, with filtering, pagination, CSV export, and a configurable retention window.
- **Two-Factor Authentication**: TOTP (RFC 6238) 2FA with QR-less manual-key enrollment, single-use recovery codes, a two-step login flow, per-role enforcement with a grace period, and an Application Passwords opt-out for roles required to use 2FA.
- **Password Policy**: optional minimum length and a common-password blocklist for new/reset passwords.
- **File Integrity Scanning**: weekly, chunked comparison of WordPress core files against official checksums, plus a scan of `wp-content/uploads` for PHP files and common webshell patterns.
- **Plugin Health Scanning**: flags active plugins that have been closed/removed from WordPress.org or haven't been updated in over two years.
- **Rate Limiting**: per-IP token-bucket throttling (429 + `Retry-After`) for `wp-login.php`, XML-RPC, `?author=` enumeration, and unauthenticated REST reads/writes.
- **Trusted Proxy Support**: an optional trusted-proxy header (Cloudflare `CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`) with a trusted-proxy IP/CIDR allowlist, so every IP-based feature sees the real visitor IP behind a CDN or load balancer.

## [1.8.1] - 2026-08-11
### Fixed
- **Custom Login URL Bypass**: `wp-login.php` could still be reached directly by appending any `?adc_login=` parameter, and the custom-login handler trusted the same raw parameter on any front-end URL. Both paths now require the request to have already been validated against the configured slug (via the rewrite rule / `parse_request` match), closing the obscurity bypass.
- **REST User-Enumeration Bypass**: The `wp/v2/users` block matched only the pretty-permalink REST path, so it could be bypassed via `?rest_route=/wp/v2/users` on sites using the plain permalink form. The check now runs on `rest_request_before_callbacks` against the resolved `$request->get_route()`, which cannot be spoofed by the request's URL form.
- **Turnstile Fail-Open**: If the Turnstile secret key was left blank, any login attempt was allowed through unverified. Missing configuration now fails closed with an admin-facing error instead of bypassing the CAPTCHA silently.
- **Update Package Verification**: Plugin updates are now verified against an optional SHA-256 checksum asset (`adc-security.zip.sha256`) published alongside each GitHub release before installation, guarding against a compromised or tampered release package.

## [1.8.0] - 2026-08-11
### Added
- **More Fixed .htaccess Rules**: Added reversible rules to disable PHP execution in `wp-includes` and `wp-content/cache`, block directory browsing (`Options -Indexes`), and extended the sensitive-files rule to cover `readme.html`, `license.txt`, `wp-config-sample.php`, `.git`, `.svn`, `composer.json`/`.lock`, and `package.json`/`package-lock.json`.
- **Dedicated Pingback Control**: Turning off pingbacks now removes the `X-Pingback` header, disables the `pingback.ping` XML-RPC method, and closes pingbacks for new posts, independently of the XML-RPC toggle.
- **Disable Admin Script Concatenation**: Optional `CONCATENATE_SCRIPTS` constant to disable admin script/style concatenation.
- **Default Admin Username Alert**: Dashboard notice when an administrator account still uses the default "admin" username. No account is renamed automatically.
- **Security Key Regeneration**: Regenerate AUTH_KEY/SALT values in `wp-config.php` from the official WordPress.org secret-key service, with an automatic backup and one-click restore.
- **Security Tests**: Added standalone tests for the new .htaccess rules and for wp-config.php key regeneration/restore/rollback behavior.

### Fixed
- **Key Regeneration Regex**: The wp-config.php key replacement no longer matches commented-out `define()` lines, which could otherwise create a duplicate live definition.
- **Key Backup Overwrite**: Regenerating security keys twice in a row no longer overwrites the original backup, so "Restore Previous Keys" always recovers the true original values.
- **Pingback Status Type**: `default_ping_status` is now forced to the string `'closed'` (matching WordPress core's expected enum value) instead of the integer `0`.

## [1.7.4] - 2026-07-23
### Fixed
- **CSP Common Services**: Allow Google Tag Manager and Cloudflare stylesheet resources in the generated `style-src` allowlist.

## [1.7.3] - 2026-07-23
### Fixed
- **Plugin Update Icon**: Include branded SVG icon metadata in custom WordPress update and plugin-information responses.

## [1.7.2] - 2026-07-23
### Changed
- **Security Headers**: Grouped all header controls under one admin section and made the generated CSP opt-in by default for WordPress themes and WooCommerce variation compatibility.

### Fixed
- **CSP Migration**: Existing installations upgrading from 1.7.0 or 1.7.1 no longer keep the generated CSP enabled automatically; other security headers remain active.

## [1.7.1] - 2026-07-23
### Added
- **Fine-tunable Security Headers**: Added fixed allowlist toggles for CSP, HSTS, framing, MIME sniffing, referrer policy, permissions policy, and legacy XSS protection.

### Fixed
- **WooCommerce Compatibility**: Content-Security-Policy can now be disabled independently when frontend variation templates require dynamic JavaScript evaluation.

## [1.7.0] - 2026-07-23
### Added
- **Fixed .htaccess Rules**: Added explicit, reversible Apache/LiteSpeed rules for XML-RPC, sensitive files, and PHP execution in uploads without accepting custom directives.
- **Frontend Dynamic Script Compatibility**: Added an opt-in frontend-only CSP mode for themes and plugins that require dynamic JavaScript template compilation.
- **Security Tests**: Added standalone tests for fixed .htaccess rules, rollback behavior, drift handling, and CSP contexts.

### Changed
- **CSP Architecture**: Extracted CSP policy generation and request classification into a dedicated module with strict default behavior.

## [1.6.3] - 2026-07-23
### Fixed
- **Content-Security-Policy**: Allow Google Maps iframe embeds from the required Google origins.

## [1.6.2] - 2026-07-23
### Fixed
- **Content-Security-Policy**: Allow HTTPS XHR/fetch requests for third-party integrations and Google Ads script loading.

## [1.6.1] - 2026-07-22
### Fixed
- **Content-Security-Policy**: Added the specific Google Fonts and Google Tag Manager origins required by the live site, plus Google Analytics endpoints for telemetry requests.

## [1.6.0] - 2026-07-22
### Changed
- **Content-Security-Policy**: Updated the default policy for WordPress page-builder compatibility by allowing inline configuration scripts and data fonts while keeping `unsafe-eval` disabled.
- **Cloudflare Turnstile**: Added the required Cloudflare origin to the default CSP and removed an unused inline script from the login integration.

## [1.5.1] - 2026-07-20
### Fixed
- **Automatic Updates**: Release packages now use the stable `adc-security/` plugin directory, preventing GitHub source archive folder names from breaking WordPress updates.

## [1.5.0] - 2026-07-20
### Security
- **Math Captcha (CRITICAL)**: Rewrote math captcha to use server-side transient storage. The answer hash is no longer exposed in the page source — an attacker can no longer brute-force the captcha in 18 attempts.
- **Content-Security-Policy**: Removed `'unsafe-inline'` and `'unsafe-eval'` from the default CSP. Added a configurable CSP textarea so admins can customise the policy. The secure default now blocks inline scripts.
- **HSTS**: The `Strict-Transport-Security` header is now only sent when HTTPS is active, preventing issues on HTTP-only sites.
- **Error Handlers**: The logger now chains to previously registered error/exception handlers instead of replacing them, preventing breakage with other plugins.
- **REQUEST_URI Sanitisation**: All `$_SERVER['REQUEST_URI']` access now uses `sanitize_text_field( wp_unslash( ... ) )`.

### Changed
- **Auto-Update Labels**: Clarified that plugin/theme auto-update controls affect ALL plugins/themes site-wide, not just ADC Security.
- **Settings Output**: Escaped all output in the system status table with `esc_html()`.

### Added
- **uninstall.php**: Plugin data is now cleaned up on deletion (options, transients, logs).

## [1.4.1] - 2026-07-20
### Changed
- **Updater**: Switched automatic updates from custom Cloudflare endpoint to GitHub Releases API. No manual upload needed — GitHub auto-generated source archives are used.
- **README**: Updated feature list and documentation for v1.4.0 additions.

## [1.4.0] - 2026-07-20
### Added
- **Admin Login Notification**: Email alert when an administrator logs in successfully, including user, time, IP, and user agent.
- **IP Allowlist & Denylist**: Manual IPv4, IPv6, and CIDR access control. Allowlisted addresses bypass the denylist and brute-force lockout. Denylist applies a 403 response on all HTTP requests.
- **User Enumeration Prevention**: Opt-in protection that redirects public `?author=N` queries to the homepage and blocks unauthenticated REST access to `wp/v2/users` endpoints.
- **Admin Session Expiration**: Configurable cookie lifetime (1–30 days) for administrators. Overrides the "Remember Me" duration when enabled.
### Changed
- IP handling is now centralised via a `get_client_ip()` helper using only `REMOTE_ADDR`; no proxy headers are trusted.
- Brute-force handlers skip counting and lockout for allowlisted IPs.
- Version bumped to 1.4.0.

## [1.3.8] - 2026-01-23
### Added
- **Error Logging System**: Implemented a background logger that captures PHP errors, exceptions, and fatal crashes specifically related to the ADC Security plugin.
- **Improved Debug Export**: The debug report now includes the last 50 error entries to help with technical support and troubleshooting.
- **Log Maintenance**: Added a feature to clear recorded logs from the Support settings tab.

## [1.3.7] - 2026-01-22
### Fixed
- **Custom Login URL**: Improved compatibility with maintenance mode plugins (e.g., Elementor) by loading the login template earlier in the execution cycle.
- **Redirect Logic**: Fixed an issue where the logout redirect would fail or loop back to the home page when using a custom login slug.

## [1.3.6] - 2026-01-13
### Added
- **Security Headers**: Added HSTS (HTTP Strict Transport Security) header enforcement for improved SSL security.
- **Auto-Update System**: Implemented a custom updater class to fetch plugin updates from a remote verified source.
- **Update Controls**: Added comprehensive settings to manage automatic updates for Plugins, Themes, and WordPress Core.
- **Changelog Interface**: Integrated a dedicated tab in settings to view technical changes directly within the dashboard.

### Fixed
- **Login Security**: Implemented a robust fallback mechanism for the Custom Login URL to prevent 404 errors on Nginx/Permalinks environments.
