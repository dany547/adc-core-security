# Changelog

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
