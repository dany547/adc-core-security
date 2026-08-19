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
- **Plugin health scanning**: Flags active plugins that have been closed/removed from the WordPress.org directory or haven't been updated in over two years.
- **Administrator login alerts**: Email notifications when an administrator signs in.
- **User enumeration protection**: Block public `?author=N` requests and unauthenticated REST user endpoints.
- **Administrator session expiration**: Set a 1-30 day cookie lifetime for administrator sessions.
- **Security headers**: Configure HSTS, Content-Security-Policy, X-Frame-Options, and related headers.
- **Bot protection**: Use a simple math captcha, Cloudflare Turnstile, and a honeypot field.
- **Hardening controls**: Disable XML-RPC, restrict REST API access, and hide WordPress version details.
- **System tools**: Review plugin status and diagnostic information from the WordPress admin area.

## Requirements

- WordPress 5.8 or later
- PHP 7.4 or later

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
- The plugin has no activation hook; new database tables/options are created on the first admin request after an update, via the existing version-check routine.

## Automatic Updates

Updates are delivered through the normal WordPress plugin update screen from [GitHub Releases](https://github.com/dany547/adc-core-security/releases). Each release provides an `adc-security.zip` package with the directory structure WordPress expects.

If an automatic update is unavailable, download the latest ZIP from the Releases page and install it through **Plugins > Add New > Upload Plugin**. Review the [changelog](CHANGELOG.md) before updating.

## Data and Uninstall

The plugin stores its settings, lockout data, audit-log events (in a dedicated database table), and plugin-specific log data in WordPress. Two-factor secrets are stored encrypted in user meta (derived from the site's WordPress salts) and recovery codes are stored hashed, never in plaintext. Diagnostic exports and the Activity log may include IP addresses and activity details, so handle them as sensitive information.

Deleting the plugin removes its options, transients, the audit-log database table, and all per-user 2FA data. Back up any information you need before deletion.

## License

This project is licensed under the GPL v2 License. See [LICENSE](LICENSE) for details.

## Support

Report bugs and feature requests through the [GitHub issue tracker](https://github.com/dany547/adc-core-security/issues). For custom WordPress development or general questions, contact [adcelerum.ro](https://adcelerum.ro).

---

Created by Dan Mutu at ADcelerum.
