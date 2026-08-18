# Changelog

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
