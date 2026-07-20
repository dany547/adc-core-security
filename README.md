# ADC Core Security

**ADC Core Security** is a lightweight, robust security plugin for WordPress. Originally developed as an internal tool for ADcelerum clients, it is now available to the public to help keep the WordPress ecosystem safe.

## Key Features

*   **Custom Login URL**: Protect your admin area by changing the default `wp-login.php` to a secret slug.
*   **Brute Force Shield**: Automatically track and block malicious IP addresses.
*   **IP Allowlist & Denylist**: Control access by IP address with IPv4, IPv6, and CIDR support. Allowlisted addresses bypass the denylist and brute-force lockout.
*   **Admin Login Notifications**: Receive an email alert when an administrator logs in successfully.
*   **User Enumeration Prevention**: Block public `?author=N` queries and REST API user endpoints for unauthenticated visitors.
*   **Admin Session Expiration**: Enforce a configurable cookie lifetime (1–30 days) for administrators.
*   **Security Headers**: One-click implementation of **HSTS**, **Content Security Policy**, **X-Frame-Options**, and more.
*   **Privacy-Friendly Captcha**: Support for Simple Math and **Cloudflare Turnstile**.
*   **Advanced Hardening**: Disable XML-RPC, Restrict REST API, and hide WordPress version strings.
*   **Honeypot Protection**: Invisible traps to catch automated bots.
*   **System & Support**: Built-in debugging tools and system status monitoring.

## Installation

1. Upload the `adc-security` folder to the `/wp-content/plugins/` directory.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **ADC Core Security** in your sidebar to configure your settings.

## Automatic Updates

This plugin supports automatic updates via GitHub Releases. Updates are fetched from the [repository](https://github.com/dany547/adc-core-security) and delivered through the standard WordPress update mechanism.

## License

This project is licensed under the GPL v2 License - see the [LICENSE](LICENSE) file for details.

## Support

If you need custom WordPress development or have questions about this plugin, feel free to contact us at [adcelerum.ro](https://adcelerum.ro).

---
*Created by Dan Mutu - ADcelerum*
