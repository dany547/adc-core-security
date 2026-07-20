# ADC Core Security

ADC Core Security is a lightweight WordPress plugin for protecting login access, reducing common attack surfaces, and monitoring plugin-specific issues. Originally built for ADcelerum clients, it is now available for public use.

## 🔒 Security Features

- **Custom login path**: Move the default `wp-login.php` entry point to a path you choose.
- **Brute-force protection**: Track failed login attempts and lock out abusive IP addresses.
- **IP allowlist and denylist**: Control access with IPv4, IPv6, and CIDR rules. Allowlisted addresses bypass denylist and lockout checks.
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

## Automatic Updates

Updates are delivered through the normal WordPress plugin update screen from [GitHub Releases](https://github.com/dany547/adc-core-security/releases). Each release provides an `adc-security.zip` package with the directory structure WordPress expects.

If an automatic update is unavailable, download the latest ZIP from the Releases page and install it through **Plugins > Add New > Upload Plugin**. Review the [changelog](CHANGELOG.md) before updating.

## Data and Uninstall

The plugin stores its settings, lockout data, and plugin-specific log data in WordPress. Diagnostic exports may include IP addresses and activity details, so handle them as sensitive information.

Deleting the plugin removes its options, transients, and log data. Back up any information you need before deletion.

## License

This project is licensed under the GPL v2 License. See [LICENSE](LICENSE) for details.

## Support

Report bugs and feature requests through the [GitHub issue tracker](https://github.com/dany547/adc-core-security/issues). For custom WordPress development or general questions, contact [adcelerum.ro](https://adcelerum.ro).

---

Created by Dan Mutu at ADcelerum.
