# ADC Core Security

ADC Core Security is a lightweight WordPress plugin for protecting login access, reducing common attack surfaces, and monitoring plugin-specific issues. Originally built for ADcelerum clients, it is now available for public use.

## 🔒 Security Features

- **Dashboard**: a live security score (0-100) with a checklist of what to fix, login/lockout activity with a 30-day trend, an administrators/sessions overview, and system/integrity status — all in one screen.
- **Custom login path**: Move the default `wp-login.php` entry point to a path you choose.
- **Brute-force protection**: Track failed login attempts and lock out abusive IP addresses.
- **Rate limiting**: Per-IP request throttling (429 responses) for `wp-login.php`, XML-RPC, `?author=` enumeration, and unauthenticated REST reads/writes — independent of the brute-force lockout, which only tracks failed passwords.
- **IP allowlist and denylist**: Control access with IPv4, IPv6, and CIDR rules. Allowlisted addresses bypass denylist and lockout checks.
- **Trusted proxy support**: Optionally resolve the real visitor IP from a trusted CDN/proxy header (Cloudflare `CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`) so every IP-based feature works correctly behind a CDN or load balancer.
- **Two-factor authentication (TOTP)**: Standard 30-second time-based codes (compatible with Google Authenticator, Aegis, 1Password, etc.), single-use recovery codes, optional per-role enforcement with a grace period, and an Application Passwords opt-out for roles required to use 2FA.
- **Password policy**: Optional minimum password length, a common-password blocklist, and an opt-in check against the Have I Been Pwned breach database (k-anonymity — only a hash prefix is ever sent, never the password).
- **Audit log**: Logins, lockouts, denied IPs, user/role changes, plugin/theme activity, and settings changes recorded to a dedicated, filterable Activity log with CSV export and a configurable retention window.
- **File integrity scanning**: Weekly comparison of WordPress core files, and every installed plugin/theme that's hosted on WordPress.org, against their official checksums — plus a scan of `wp-content/uploads` for PHP files and common webshell patterns. Cron health is monitored too: the dashboard warns if these background scans stop firing (a common symptom of WP-Cron being blocked or misconfigured).
- **Plugin health scanning**: Flags active plugins that have been closed/removed from the WordPress.org directory or haven't been updated in over two years. Optionally cross-references the installed WordPress version and every active WordPress.org plugin against the free, public [WPVulnerability](https://www.wpvulnerability.com/) database to list known CVEs, with the CVSS score and whether a fixed release exists. Only the core version and the plugin slugs are sent — never users, URLs or content — and the feed is opt-in.
- **Administrator login alerts**: Email notifications when an administrator signs in.
- **User enumeration protection**: Block public `?author=N` requests and unauthenticated REST user endpoints.
- **Administrator session expiration**: Set a 1-30 day cookie lifetime for administrator sessions.
- **Security headers**: Configure HSTS (max age, subdomains, preload), Content-Security-Policy, Referrer-Policy, Permissions-Policy, X-Frame-Options, and related headers. The Content-Security-Policy has three modes: Off, Standard (built from the services you use, such as Google Tag Manager or Google Analytics, plus per-directive sources you can edit), and Custom (your own text). Report-Only mode tests a policy without blocking anything, and the Blocked sources panel lists what browsers reported, with an Allow button for each source.
- **Bot protection**: Use a simple math captcha, Cloudflare Turnstile, and a honeypot field on the login form and on the lost-password form (WordPress and WooCommerce My Account).
- **WooCommerce order & account abuse protection**: On stores running WooCommerce, server-side rules throttle checkout submissions and cart writes per IP, limit order velocity per IP, billing email, phone number and billing address, reject disposable email domains, and block bursts of failed orders (card testing). Account creation is filtered the same way across the My Account form, the checkout "create an account" option, and the WordPress registration form, with two opt-in switches to remove account creation from checkout or from the My Account page entirely. Disposable domains are also rejected when a customer changes their email on Account details. Lost-password requests on My Account are throttled and get the same honeypot as registration. A monitor mode flags orders instead of blocking them; the order edit screen and the orders list show the connection IP and flag reasons. Covers both the classic (shortcode) checkout and the Checkout block (Store API).
- **Users screen columns**: "Account Created" and "Last Login" columns on the WordPress Users list, both sortable, with users who never logged in kept in the list when sorting by last login.
- **Virtual patching**: Opt-in, request-level guards for WordPress core vulnerabilities that are being exploited in the wild, so a site stays protected between a CVE being published and the core update being installed. Shipped rules cover `pagename` path traversal in any encoding depth (CVE-2026-87902), unauthenticated `/wp-json/batch/v1` requests (CVE-2026-63030) and `author__not_in` / `author__in` arguments passed over HTTP (CVE-2026-60137). Rules are pattern-based rather than exploit-string based, only match attack-shaped input, can be logged without blocking first, and every hit is written to the Activity log with the CVE reference.
- **Hardening controls**: Disable XML-RPC, restrict REST API access, and hide WordPress version details.
- **System tools**: Review plugin status and diagnostic information from the WordPress admin area.

## Requirements

- WordPress 5.8 or later
- PHP 7.4 or later
- WooCommerce is optional. The WooCommerce tab only appears when WooCommerce is active (tested against the latest releases; both the classic checkout and the Checkout block are supported).

## Installation

1. Download `adc-security.zip` from the latest [GitHub Release](https://github.com/dany547/adc-core-security/releases).
2. In WordPress, go to **Plugins > Add New > Upload Plugin** and upload the ZIP file.
3. Activate **ADC Core Security**.
4. Open **ADC Core Security** from the WordPress sidebar to configure it.

## ⚙️ Configuration Notes

- Set a custom login path before exposing it to users, and keep a safe recovery procedure for administrators.
- Add trusted administrator IP addresses to the allowlist before enabling a restrictive denylist or lockout policy.
- Cloudflare Turnstile requires a site key and secret key from Cloudflare.
- Start with security headers in a staging environment when possible. A strict Content-Security-Policy can affect themes, page builders, analytics, and other plugins.
- XML-RPC and REST API restrictions can affect mobile apps, integrations, and headless WordPress sites. Enable them only after confirming the affected services do not require access.
- Only set the Trusted Proxy Header if the site actually sits behind that proxy/CDN, and list its real IP ranges under Trusted Proxy IPs. Setting a header without a matching trusted IP is ignored (fails safe), but a wrong or missing trusted-IP list on a site that genuinely is behind a proxy means every visitor appears to share the proxy's IP.
- Before requiring 2FA for a role, enroll your own account first and save the recovery codes somewhere safe — they are shown only once, right after enabling 2FA. A grace period (configurable, default 0 = immediate) gives already-logged-in users time to enroll before they're redirected to the 2FA tab on every wp-admin request.
- **Virtual patching is a stopgap, not a substitute for updating core**: enable the rules you need on the Hardening tab while a core security release is pending (or when a plugin or host incompatibility blocks the update), then rely on the patched core again. Start with Monitor Mode enabled when you are unsure: hits are logged as `virtual_patch` events in the Activity tab and nothing is blocked, so you can confirm legitimate traffic never matches. The `author__not_in` rule only inspects HTTP input, so plugins that build that argument internally are unaffected. Virtual patching and the vulnerability feed are enabled independently.
- **The known-vulnerability feed is a cross-reference, not a clean bill of health**: an empty result means nothing was found in the upstream database, not that a component is safe — coverage is only as complete as that database. Keep installing updates; use the feed to prioritise. Plugin lookups rotate (max 25 per scan run, cached for 12 hours), so on a site with many plugins the full picture builds up over a couple of daily runs.
- The plugin has no activation hook; new database tables/options are created on the first admin request after an update, via the existing version-check routine.
- WooCommerce checkout protection is enabled by default on stores where WooCommerce is active, using conservative thresholds (30 checkout attempts and 60 cart writes per IP per 10 minutes, 10 orders per IP, 20 per billing email, 5 per phone, 5 per billing address and 5 failed orders per hour, registration attempts limited to 10 per IP per hour, minimum interaction time 3 seconds). **Monitor Mode is on by default**: violations are logged and orders are flagged, but nothing is blocked, so an update never starts rejecting checkout. Uncheck Monitor Mode on the WooCommerce tab after you have reviewed the Activity log. Allowlisted IPs in the Login Security tab bypass every WooCommerce rule, so test orders from a trusted address are never affected. The cart-write throttle (HTTP 429) is separate from WooCommerce's own Store API rate limiter (`woocommerce_store_api_rate_limit_options`, off by default); both can run together.
- The phone and address limits are the first ones to raise on wholesale/B2B stores, on offices and for families sharing one address. Phone matching compares digits only (formatting and punctuation are ignored), so a number written with a different country prefix counts as a different number.
- **Origin / Referer check is off by default** because headless front-ends, cross-domain storefronts and some privacy setups legitimately send a foreign or missing Origin/Referer. Enable "Block foreign Origin/Referer" if the site itself serves the checkout (the common case); test with Monitor Mode first. Extend the accepted hosts from code with the `adc_security_checkout_allowed_hosts` filter if the store legitimately spans several domains.
- Orders that pass while Monitor Mode is active get `_adc_security_review` and `_adc_security_review_reasons` order meta, shown in the Security meta box of the order edit screen (legacy orders and High-Performance Order Storage). Use those to exclude the orders from conversion reporting while evaluating the rules.
- **Conversion hygiene matters as much as blocking**: fire the purchase conversion only for paid orders (`processing`/`completed`) instead of on the order-received page for every status, and exclude orders flagged for review. For cash-on-delivery orders — which never change payment status — correct the reporting afterwards (Google Ads offline conversion adjustment, GA4 `refund` event, Meta Conversions API refund).
- "Turnstile On Checkout" reuses the Cloudflare Turnstile keys from the Captcha tab and applies to the classic (shortcode) checkout only, since the Checkout block renders its form in the browser; the honeypot is limited to the classic checkout for the same reason. The minimum interaction time and the cart/checkout throttles work on both checkouts because they read the WooCommerce session.
- Do not combine "Disable Account Creation At Checkout" with a store that requires accounts (guest checkout disabled): the Checkout block refuses to place an order in that configuration, and the classic checkout keeps creating the required account anyway. The setting is meant for stores that accept guest orders.

## Automatic Updates

Updates are delivered through the normal WordPress plugin update screen from [GitHub Releases](https://github.com/dany547/adc-core-security/releases). Each release provides an `adc-security.zip` package with the directory structure WordPress expects, plus an `adc-security.zip.sha256` checksum that is verified before the package is installed.

If an automatic update is unavailable, download the latest ZIP from the Releases page and install it through **Plugins > Add New > Upload Plugin**. Review the [changelog](CHANGELOG.md) before updating.

## Data and Uninstall

The plugin stores its settings, lockout data, audit-log events (in a dedicated database table), and plugin-specific log data in WordPress. Two-factor secrets are stored encrypted in user meta (derived from the site's WordPress salts) and recovery codes are stored hashed, never in plaintext. Diagnostic exports and the Activity log may include IP addresses and activity details, so handle them as sensitive information. When the vulnerability feed is enabled, the installed core version and the active plugin slugs are sent to the public WPVulnerability API and the answers are cached in transients for 12 hours; nothing else about the site is transmitted. When WooCommerce protection is active, each new order keeps the connecting IP in an order meta field (`_adc_security_order_ip`, shown in the order's Security meta box) for fraud review, and each successful login timestamp is stored in the `_adc_last_login` user meta to power the Users screen columns.

Deleting the plugin removes its options, transients, the audit-log database table, and all per-user 2FA data (plus the last-login user meta). Hidden order IP meta is left in place so the store keeps its fraud-review records. Back up any information you need before deletion.

## License

This project is licensed under the GPL v2 License. See [LICENSE](LICENSE) for details.

## Support

Report bugs and feature requests through the [GitHub issue tracker](https://github.com/dany547/adc-core-security/issues). For custom WordPress development or general questions, contact [adcelerum.ro](https://adcelerum.ro).

---

Created by Dan Mutu at ADcelerum.
