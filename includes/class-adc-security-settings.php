<?php
/**
 * ADC Security Settings Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Settings {

	/**
	 * Option Name
	 */
	const OPTION_NAME = 'adc_security_options';

	/**
	 * Fixed-rule .htaccess manager.
	 *
	 * @var ADC_Security_Htaccess
	 */
	private $htaccess;

	/**
	 * Security key (salt) manager.
	 *
	 * @var ADC_Security_Keys
	 */
	private $keys;

	/**
	 * Constructor.
	 */
	public function __construct( $htaccess = null, $keys = null ) {
		$this->htaccess = $htaccess instanceof ADC_Security_Htaccess ? $htaccess : new ADC_Security_Htaccess();
		$this->keys     = $keys instanceof ADC_Security_Keys ? $keys : new ADC_Security_Keys();
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'handle_debug_export' ) );
        add_action( 'admin_init', array( $this, 'handle_clear_logs' ) );
		add_action( 'admin_post_adc_security_apply_htaccess', array( $this, 'handle_apply_htaccess' ) );
		add_action( 'admin_post_adc_security_revert_htaccess', array( $this, 'handle_revert_htaccess' ) );
		add_action( 'admin_post_adc_security_regenerate_keys', array( $this, 'handle_regenerate_keys' ) );
		add_action( 'admin_post_adc_security_restore_keys', array( $this, 'handle_restore_keys' ) );
		add_action( 'admin_post_adc_security_unblock_ip', array( $this, 'handle_unblock_ip' ) );
		add_action( 'admin_post_adc_security_export_events', array( $this, 'handle_export_events' ) );
        // Removed global admin_head hook to prevent interference and fix warnings
	}

	/**
	 * Register settings.
	 */
	public function register_settings() {
		register_setting( self::OPTION_NAME, self::OPTION_NAME, array( $this, 'sanitize_settings' ) );

		add_settings_section(
			'adc_security_login_section',
			'Login & Authentication',
			null,
			'adc_security_login'
		);

		add_settings_field(
			'custom_login_slug',
			'Custom Login URL Slug',
			array( $this, 'render_text_field' ),
			'adc_security_login',
			'adc_security_login_section',
			array(
				'label_for' => 'custom_login_slug',
				'description' => 'Enter a custom slug for your login page (e.g., "my-secret-login"). This hides the default <code>wp-login.php</code> and redirects unauthorized access to the home page.',
			)
		);

		add_settings_field(
			'brute_force_protection',
			'Brute Force Protection',
			array( $this, 'render_checkbox_field' ),
			'adc_security_login',
			'adc_security_login_section',
			array(
				'label_for' => 'brute_force_protection',
				'description' => 'Enable protection against brute force attacks. This tracks failed login attempts by IP and blocks them after the threshold is reached.',
			)
		);

        add_settings_field(
			'bf_max_attempts',
			'Max Login Attempts',
			array( $this, 'render_number_field' ),
			'adc_security_login',
			'adc_security_login_section',
			array(
				'label_for' => 'bf_max_attempts',
				'description' => 'The number of failed login attempts allowed before an IP is locked out (default: 5).',
                'min' => 1,
			)
		);

        add_settings_field(
			'bf_lockout_duration',
			'Lockout Duration (Minutes)',
			array( $this, 'render_number_field' ),
			'adc_security_login',
			'adc_security_login_section',
			array(
				'label_for' => 'bf_lockout_duration',
				'description' => 'How many minutes the IP address will be blocked for after exceeding max attempts (default: 60).',
                'min' => 1,
			)
		);

        add_settings_field(
			'login_notification',
			'Failed Login Notification',
			array( $this, 'render_checkbox_field' ),
			'adc_security_login',
			'adc_security_login_section',
			array(
				'label_for' => 'login_notification',
				'description' => 'Receive an email notification when an IP is locked out due to too many failed login attempts.',
			)
		);

        add_settings_field(
            'login_success_notification',
            'Admin Login Notification',
            array( $this, 'render_checkbox_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'login_success_notification',
                'description' => 'Receive an email notification when an administrator logs in successfully. The alert includes the user, time, IP, and user agent.',
            )
        );

        add_settings_field(
            'ip_allowlist',
            'IP Allowlist',
            array( $this, 'render_textarea_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'ip_allowlist',
                'description' => 'One IP, IPv6, or CIDR rule per line. Allowlisted addresses bypass the denylist and brute-force lockout. Only use for trusted administrative addresses.',
            )
        );

        add_settings_field(
            'ip_denylist',
            'IP Denylist',
            array( $this, 'render_textarea_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'ip_denylist',
                'description' => 'One IP, IPv6, or CIDR rule per line. Denied addresses receive a 403 response on all HTTP requests (frontend, wp-admin, REST, XML-RPC).',
            )
        );

        add_settings_field(
            'rate_limiting_enabled',
            'Rate Limiting',
            array( $this, 'render_checkbox_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for'   => 'rate_limiting_enabled',
                'description' => 'Throttle wp-login.php, XML-RPC, author-enumeration, and unauthenticated REST requests per IP with a 429 response. Complements brute-force lockout, which tracks failed passwords rather than raw request volume.',
            )
        );

        add_settings_field(
            'trusted_proxy_header',
            'Trusted Proxy Header',
            array( $this, 'render_select_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for'   => 'trusted_proxy_header',
                'description' => 'Only set this if the site sits behind a reverse proxy or CDN (e.g. Cloudflare). Every IP-based feature (lockouts, allow/deny lists, rate limiting) will read the visitor IP from this header instead of the connecting IP, but only for connections coming from a trusted proxy IP below.',
                'options'     => array(
                    ''                 => 'None (use the connecting IP)',
                    'CF-Connecting-IP' => 'CF-Connecting-IP (Cloudflare)',
                    'X-Real-IP'        => 'X-Real-IP',
                    'X-Forwarded-For'  => 'X-Forwarded-For',
                ),
            )
        );

        add_settings_field(
            'trusted_proxies',
            'Trusted Proxy IPs',
            array( $this, 'render_textarea_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for'   => 'trusted_proxies',
                'description' => 'One IP or CIDR range per line. The trusted proxy header above is only honored when the connecting IP (REMOTE_ADDR) matches one of these. Leave empty to disable header-based IP resolution entirely.',
            )
        );

        add_settings_field(
            'admin_session_expiration_enabled',
            'Limit Admin Session Duration',
            array( $this, 'render_checkbox_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'admin_session_expiration_enabled',
                'description' => 'Override the default cookie lifetime for administrators. When enabled, admin sessions expire after the configured number of days regardless of "Remember Me".',
            )
        );

        add_settings_field(
            'admin_session_expiration_days',
            'Admin Session Expiration (Days)',
            array( $this, 'render_number_field' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'admin_session_expiration_days',
                'description' => 'Number of days before an admin session expires (1&ndash;30). Default: 7.',
                'min' => 1,
                'max' => 30,
            )
        );

        // --- Captcha Section ---
        add_settings_section(
            'adc_security_captcha_section',
            'Captcha Settings',
            null,
            'adc_security_captcha'
        );

        add_settings_field(
            'captcha_type',
            'Captcha Type',
            array( $this, 'render_select_field' ),
            'adc_security_captcha',
            'adc_security_captcha_section',
            array(
                'label_for' => 'captcha_type',
                'description' => 'Select the type of CAPTCHA to protect the login form.',
                'options' => array(
                    'none'      => 'None',
                    'math'      => 'Simple Math Captcha',
                    'turnstile' => 'Cloudflare Turnstile',
                ),
            )
        );

        add_settings_field(
            'turnstile_site_key',
            'Turnstile Site Key',
            array( $this, 'render_text_field' ),
            'adc_security_captcha',
            'adc_security_captcha_section',
            array(
                'label_for' => 'turnstile_site_key',
                'description' => 'Required for Cloudflare Turnstile. To get your keys, you need to create a free Cloudflare account and generate them in the <a href="https://www.cloudflare.com/en-au/application-services/products/turnstile/" target="_blank" rel="noopener noreferrer">Turnstile section</a>.',
            )
        );

        add_settings_field(
            'turnstile_secret_key',
            'Turnstile Secret Key',
            array( $this, 'render_text_field' ),
            'adc_security_captcha',
            'adc_security_captcha_section',
            array(
                'label_for' => 'turnstile_secret_key',
                'description' => 'Required if using Cloudflare Turnstile.',
            )
        );

        add_settings_field(
            'login_honeypot',
            'Honeypot Protection',
            array( $this, 'render_checkbox_field' ),
            'adc_security_captcha',
            'adc_security_captcha_section',
            array(
                'label_for' => 'login_honeypot',
                'description' => 'Add a hidden field to the login form. If a bot fills it out, the login is blocked.',
            )
        );

		add_settings_section(
			'adc_security_hardening_section',
			'Hardening',
			null,
			'adc_security_hardening'
		);

		add_settings_field(
			'hide_wp_version',
			'Hide WordPress Version',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for' => 'hide_wp_version',
				'description' => 'Removes the WordPress version number from the site\'s source code and RSS feeds, making it harder for attackers to identify vulnerabilities.',
			)
		);

        add_settings_field(
			'disable_xmlrpc',
			'Disable XML-RPC',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for' => 'disable_xmlrpc',
				'description' => 'Completely disables XML-RPC. Proceed with caution if you use the WordPress mobile app or external services like Jetpack.',
			)
		);

        add_settings_field(
			'disable_file_editor',
			'Disable File Editor',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for' => 'disable_file_editor',
				'description' => 'Disables the theme and plugin file editor in the WordPress dashboard (Appearance > Theme File Editor), preventing code execution if an admin account is compromised.',
			)
		);

		add_settings_field(
			'htaccess_rules',
			'Safe .htaccess Rules',
			array( $this, 'render_htaccess_rules_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for'   => 'htaccess_rules',
				'description' => 'Select fixed server rules to apply explicitly. The plugin never accepts custom .htaccess text and never changes these rules automatically.',
			)
		);

        add_settings_field(
			'disable_rest_api',
			'Disable REST API (Public)',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for' => 'disable_rest_api',
				'description' => 'Restricts access to the REST API endpoints to logged-in users only. This prevents improved reconnaissance by bots.',
			)
		);

		add_settings_section(
			'adc_security_virtual_patch_section',
			'Virtual Patching (Exploited Core CVEs)',
			array( $this, 'render_virtual_patch_section_intro' ),
			'adc_security_hardening'
		);

		add_settings_field(
			'virtual_patch_rules',
			'Active Rules',
			array( $this, 'render_virtual_patch_rules_field' ),
			'adc_security_hardening',
			'adc_security_virtual_patch_section',
			array(
				'label_for'   => 'virtual_patch_rules',
				'description' => 'Each rule is a fixed, pattern-based guard for one exploited WordPress core vulnerability. Nothing is blocked unless you select the rule here.',
			)
		);

		add_settings_field(
			'virtual_patch_monitor',
			'Monitor Mode',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_virtual_patch_section',
			array(
				'label_for'   => 'virtual_patch_monitor',
				'description' => 'Record every rule hit in the Activity log without blocking the request. Use it for a few days to confirm legitimate traffic never matches; uncheck it to enforce. Monitor mode is off by default.',
			)
		);

		add_settings_section(
			'adc_security_vulnerability_feed_section',
			'Known Vulnerability Feed',
			array( $this, 'render_vulnerability_feed_section_intro' ),
			'adc_security_hardening'
		);

		add_settings_field(
			'vulnerability_feed_enabled',
			'Cross-reference CVEs',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_vulnerability_feed_section',
			array(
				'label_for'   => 'vulnerability_feed_enabled',
				'description' => 'Match the installed WordPress version and every active WordPress.org plugin against the free, public WPVulnerability database. Only the core version and the plugin slugs are sent, never users, URLs or content. A result is a cross-reference, not a clean bill of health, so keep installing updates.',
			)
		);

		add_settings_section(
			'adc_security_headers_section',
			'Security Headers',
			null,
			'adc_security_hardening'
		);

		add_settings_field(
			'security_headers',
			'Enable Security Headers',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_headers_section',
			array(
				'label_for' => 'security_headers',
				'description' => 'Adds the following HTTP security headers to protect your site:<br>
                <ul>
                    <li><strong>X-Content-Type-Options:</strong> nosniff (Prevents MIME-type sniffing)</li>
                    <li><strong>X-Frame-Options:</strong> SAMEORIGIN (Prevents clickjacking)</li>
                    <li><strong>X-XSS-Protection:</strong> 1; mode=block (Enables XSS filtering)</li>
                    <li><strong>Referrer-Policy:</strong> strict-origin-when-cross-origin (Controls referrer info)</li>
                    <li><strong>Content-Security-Policy:</strong> Optional and configurable below</li>
                    <li><strong>Permissions-Policy:</strong> Disables sensitive features (Camera, Mic, etc.)</li>
                    <li><strong>Strict-Transport-Security:</strong> Sent only when HTTPS is active (Enforces HTTPS)</li>
                </ul>',
			)
		);

        add_settings_field(
            'security_headers_csp',
            'Content-Security-Policy',
            array( $this, 'render_textarea_field' ),
            'adc_security_hardening',
            'adc_security_headers_section',
            array(
                'label_for' => 'security_headers_csp',
                'description' => 'Optional custom Content-Security-Policy value. Enable CSP in the fine-tuning list below before using this field. Existing custom values override the generated policy.',
            )
        );

		add_settings_field(
			'security_header_toggles',
			'Fine-tune Security Headers',
			array( $this, 'render_security_header_toggles_field' ),
			'adc_security_hardening',
			'adc_security_headers_section',
			array(
				'label_for'   => 'security_header_toggles',
				'description' => 'Choose which fixed headers are emitted when Enable Security Headers is active. CSP can be disabled independently when a theme or plugin requires dynamic JavaScript templates.',
			)
		);

		add_settings_field(
			'csp_dynamic_scripts_compatibility',
			'Frontend Dynamic Script Compatibility',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_headers_section',
			array(
				'label_for'   => 'csp_dynamic_scripts_compatibility',
				'description' => 'Allows JavaScript template compilation required by some WooCommerce and theme scripts on frontend pages only. This adds <code>unsafe-eval</code> to the default CSP and remains disabled by default. A custom CSP value overrides this setting.',
			)
		);

        add_settings_field(
            'prevent_user_enumeration',
            'Prevent User Enumeration',
            array( $this, 'render_checkbox_field' ),
            'adc_security_hardening',
            'adc_security_hardening_section',
            array(
                'label_for' => 'prevent_user_enumeration',
                'description' => 'Blocks public access to <code>?author=N</code> queries and the REST <code>wp/v2/users</code> endpoints. Unauthenticated visitors are redirected or receive a 403. Disable if you rely on public author archives.',
            )
        );

		add_settings_field(
			'disable_pingbacks',
			'Turn Off Pingbacks',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for'   => 'disable_pingbacks',
				'description' => 'Removes the X-Pingback header, disables the pingback.ping XML-RPC method, and closes pingbacks for new posts. Existing posts are unaffected.',
			)
		);

		add_settings_field(
			'disable_script_concat',
			'Disable Admin Script Concatenation',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for'   => 'disable_script_concat',
				'description' => 'Disables the WordPress admin script/style concatenation feature (<code>CONCATENATE_SCRIPTS</code>), which can otherwise be used to probe loaded admin scripts.',
			)
		);

		add_settings_field(
			'alert_admin_username',
			'Alert on Default Admin Username',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for'   => 'alert_admin_username',
				'description' => 'Shows a dashboard notice to administrators when an account still uses the default "admin" username. The plugin never renames or deletes accounts automatically.',
			)
		);

        // --- Auto Updates Section ---
        add_settings_section(
            'adc_security_updates_section',
            'Automatic Updates',
            null,
            'adc_security_hardening'
        );

        add_settings_field(
            'auto_update_plugins',
            'Plugin Updates (Site-Wide)',
            array( $this, 'render_select_field' ),
            'adc_security_hardening',
            'adc_security_updates_section',
            array(
                'label_for' => 'auto_update_plugins',
                'description' => 'Controls automatic updates for ALL plugins on this site, not just ADC Security.',
                'options' => array(
                    'default' => 'Default (Manual)',
                    'enable'  => 'Enable All',
                    'disable' => 'Disable All',
                ),
            )
        );

        add_settings_field(
            'auto_update_themes',
            'Theme Updates (Site-Wide)',
            array( $this, 'render_select_field' ),
            'adc_security_hardening',
            'adc_security_updates_section',
            array(
                'label_for' => 'auto_update_themes',
                'description' => 'Controls automatic updates for ALL themes on this site.',
                'options' => array(
                    'default' => 'Default (Manual)',
                    'enable'  => 'Enable All',
                    'disable' => 'Disable All',
                ),
            )
        );

        add_settings_field(
            'auto_update_core',
            'WordPress Core Updates',
            array( $this, 'render_select_field' ),
            'adc_security_hardening',
            'adc_security_updates_section',
            array(
                'label_for' => 'auto_update_core',
                'description' => 'Control automatic updates for WordPress core.',
                'options' => array(
                    'minor'   => 'Default (Minor & Security Only)',
                    'major'   => 'Enable All (Major & Minor)',
                    'disable' => 'Disable All',
                ),
            )
        );

        add_settings_section(
            'adc_security_2fa_section',
            'Two-Factor Authentication Policy',
            null,
            'adc_security_2fa'
        );

        add_settings_field(
            '2fa_required_roles',
            'Require 2FA For',
            array( $this, 'render_role_checkboxes_field' ),
            'adc_security_2fa',
            'adc_security_2fa_section',
            array(
                'label_for'   => '2fa_required_roles',
                'description' => 'Users with these roles must have two-factor authentication enabled to keep using wp-admin once the grace period below ends.',
            )
        );

        add_settings_field(
            '2fa_grace_days',
            'Enrollment Grace Period (Days)',
            array( $this, 'render_number_field' ),
            'adc_security_2fa',
            'adc_security_2fa_section',
            array(
                'label_for'   => '2fa_grace_days',
                'description' => 'Days a required user is allowed to keep using wp-admin before enrolling. 0 enforces immediately.',
                'min'         => 0,
            )
        );

        add_settings_field(
            '2fa_disable_application_passwords',
            'Application Passwords',
            array( $this, 'render_checkbox_field' ),
            'adc_security_2fa',
            'adc_security_2fa_section',
            array(
                'label_for'   => '2fa_disable_application_passwords',
                'description' => 'Disable Application Passwords for roles required to use 2FA (otherwise they could bypass 2FA via an application password).',
            )
        );

        add_settings_section(
            'adc_security_password_policy_section',
            'Password Policy',
            null,
            'adc_security_2fa'
        );

        add_settings_field(
            'password_min_length',
            'Minimum Password Length',
            array( $this, 'render_number_field' ),
            'adc_security_2fa',
            'adc_security_password_policy_section',
            array(
                'label_for'   => 'password_min_length',
                'description' => 'New and reset passwords must be at least this many characters. 0 disables the check.',
                'min'         => 0,
            )
        );

        add_settings_field(
            'password_block_common',
            'Block Common Passwords',
            array( $this, 'render_checkbox_field' ),
            'adc_security_2fa',
            'adc_security_password_policy_section',
            array(
                'label_for'   => 'password_block_common',
                'description' => 'Reject new and reset passwords found on a list of the most commonly leaked passwords.',
            )
        );

        add_settings_field(
            'password_check_hibp',
            'Check Against Known Breaches (HIBP)',
            array( $this, 'render_checkbox_field' ),
            'adc_security_2fa',
            'adc_security_password_policy_section',
            array(
                'label_for'   => 'password_check_hibp',
                'description' => 'Reject new and reset passwords found in the Have I Been Pwned breach database. Privacy: only the first 5 characters of the password\'s SHA-1 hash are ever sent to the API (k-anonymity) — the actual password never leaves the server. Opt-in because it makes an external HTTPS request on every password change.',
            )
        );

		// --- WooCommerce abuse prevention (only relevant when WooCommerce is active) ---
		if ( class_exists( 'WooCommerce' ) ) {
			$woo_options = get_option( self::OPTION_NAME, array() );

			add_settings_section(
				'adc_security_woo_checkout_section',
				'Checkout Protection',
				null,
				'adc_security_woocommerce'
			);

			add_settings_field(
				'woo_checkout_protection',
				'Checkout Abuse Protection',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_protection',
					'description' => 'Master switch for the checkout rules below. Protects both the classic (shortcode) checkout and the Checkout block (Store API). Every rule is evaluated server-side; nothing is trusted from the browser.',
				)
			);

			add_settings_field(
				'woo_monitor_mode',
				'Monitor Mode (Log Only)',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_monitor_mode',
					'description' => 'Record every rule violation in the Activity log <strong>without blocking</strong> the checkout or the registration. On by default so an update never starts rejecting orders before you have reviewed the log. Uncheck this to enforce the rules.',
				)
			);

			add_settings_field(
				'woo_checkout_honeypot',
				'Checkout Honeypot',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_honeypot',
					'description' => 'Add an invisible field to the classic checkout form. Bots that blindly fill every field are rejected. The Checkout block renders on the client, so it has no field to protect.',
				)
			);

			add_settings_field(
				'woo_checkout_min_seconds',
				'Minimum Checkout Time (Seconds)',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_min_seconds',
					'description' => 'Reject orders submitted faster than this many seconds after the session first touched the cart or the checkout page (measured once per session, so reloads and extra tabs never reset it). 0 disables the check. Catches scripts that add to cart and check out within the same second.',
					'min'         => 0,
					'max'         => 120,
				)
			);

			add_settings_field(
				'woo_checkout_referrer_check',
				'Origin / Referer Check',
				array( $this, 'render_select_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_referrer_check',
					'description' => 'Verifies that checkout requests come from this site. "Block foreign" rejects requests that send an Origin/Referer for another domain; "Require same-site" also rejects requests with no Origin/Referer at all (stricter, but browsers that strip the header will be blocked). Leave off for headless or multi-domain front-ends. Test with Monitor Mode first.',
					'options'     => array(
						'off'      => 'Off',
						'mismatch' => 'Block foreign Origin/Referer',
						'required' => 'Require same-site Origin/Referer',
					),
				)
			);

			add_settings_field(
				'woo_checkout_rate_limit',
				'Checkout Attempts Per IP',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_rate_limit',
					'description' => 'Maximum checkout submissions per IP address within 10 minutes. 0 disables the throttle. Allowlisted IPs and values without a detectable IP are always exempt.',
					'min'         => 0,
					'max'         => 500,
				)
			);

			add_settings_field(
				'woo_cart_write_limit',
				'Cart Updates Per IP',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_cart_write_limit',
					'description' => 'Maximum cart write requests (add to cart, cart updates, coupons) per IP address within 10 minutes, covering both the classic cart and the Store API. 0 disables the throttle. A volume guard that raises the cost before an abuser ever reaches checkout.',
					'min'         => 0,
					'max'         => 1000,
				)
			);

			add_settings_field(
				'woo_order_window_minutes',
				'Order Limit Window (Minutes)',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_order_window_minutes',
					'description' => 'Time window used by the two order limits below.',
					'min'         => 1,
					'max'         => 1440,
				)
			);

			add_settings_field(
				'woo_order_ip_limit',
				'Max Orders Per IP',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_order_ip_limit',
					'description' => 'Maximum orders a single IP address may create within the window above. 0 disables the limit. Useful against card-testing and fake-order floods from one source.',
					'min'         => 0,
					'max'         => 200,
				)
			);

			add_settings_field(
				'woo_order_email_limit',
				'Max Orders Per Email',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_order_email_limit',
					'description' => 'Maximum orders a single billing email address may create within the window above. 0 disables the limit. Catches bots that rotate their IP address.',
					'min'         => 0,
					'max'         => 500,
				)
			);

			add_settings_field(
				'woo_order_phone_limit',
				'Max Orders Per Phone',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_order_phone_limit',
					'description' => 'Maximum orders a single billing phone number may create within the window above. 0 disables the limit. Catches bots that rotate IPs and emails but keep reusing one phone number. Wholesale/B2B stores should raise this.',
					'min'         => 0,
					'max'         => 200,
				)
			);

			add_settings_field(
				'woo_order_address_limit',
				'Max Orders Per Address',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_order_address_limit',
					'description' => 'Maximum orders a single billing address (street + postcode) may create within the window above. 0 disables the limit. Raise it for offices, families or wholesale customers who legitimately ship to the same address.',
					'min'         => 0,
					'max'         => 200,
				)
			);

			add_settings_field(
				'woo_failed_order_limit',
				'Max Failed Orders Per IP / Email',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_failed_order_limit',
					'description' => 'Maximum failed orders from one IP address or billing email within the window above before further checkout attempts are rejected. 0 disables the rule. Targets card testing, where an attacker retries until a payment succeeds. Only failures reported shortly after the order was placed are counted, not back-office status changes or webhooks on old orders.',
					'min'         => 0,
					'max'         => 100,
				)
			);

			$turnstile_ready = isset( $woo_options['captcha_type'] ) && 'turnstile' === $woo_options['captcha_type']
				&& ! empty( $woo_options['turnstile_site_key'] ) && ! empty( $woo_options['turnstile_secret_key'] );

			add_settings_field(
				'woo_checkout_turnstile',
				'Turnstile On Checkout',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_checkout_section',
				array(
					'label_for'   => 'woo_checkout_turnstile',
					'description' => 'Require a Cloudflare Turnstile challenge before the classic checkout accepts an order (strongest bot protection). '
						. 'It reuses the keys from the Captcha tab, therefore <strong>Captcha Type must be Cloudflare Turnstile</strong>. '
						. 'Not supported by the Checkout block.'
						. ( $turnstile_ready ? '' : ' <strong>Turnstile keys are missing, so this setting currently has no effect.</strong>' ),
				)
			);

			add_settings_section(
				'adc_security_woo_registration_section',
				'Account Creation Protection',
				null,
				'adc_security_woocommerce'
			);

			add_settings_field(
				'woo_registration_protection',
				'Registration Abuse Protection',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_protection',
					'description' => 'Master switch for every account-creation rule below. Covers the WooCommerce My Account form, the "create an account" option at checkout, and (optionally) the WordPress registration form.',
				)
			);

			add_settings_field(
				'woo_registration_honeypot',
				'Registration Honeypot',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_honeypot',
					'description' => 'Add an invisible field to the registration forms. Bots that fill every field are rejected.',
				)
			);

			add_settings_field(
				'woo_registration_rate_limit',
				'Registrations Per IP (Hourly)',
				array( $this, 'render_number_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_rate_limit',
					'description' => 'Maximum registration attempts per IP address per hour, including submissions that fail WooCommerce validation. 0 disables the throttle. Ten attempts leave room for shoppers fixing form errors while still capping account farms.',
					'min'         => 0,
					'max'         => 100,
				)
			);

			add_settings_field(
				'woo_registration_disable_checkout_accounts',
				'Disable Account Creation At Checkout',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_disable_checkout_accounts',
					'description' => 'Remove the "create an account" option from checkout, so accounts can only be created from the My Account page. Do not enable this when guest checkout is disabled: the Checkout block refuses to place an order in that configuration, and the classic checkout keeps creating the account that the store settings require.',
				)
			);

			add_settings_field(
				'woo_registration_disable_myaccount_form',
				'Disable My Account Registration Form',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_disable_myaccount_form',
					'description' => 'Hide the registration form on the My Account page and reject direct POSTs to it, so new accounts must be created by the store. Existing customers can still log in and place orders.',
				)
			);

			add_settings_field(
				'woo_registration_protect_wp_form',
				'Also Protect The WordPress Registration Form',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_registration_section',
				array(
					'label_for'   => 'woo_registration_protect_wp_form',
					'description' => 'Apply the honeypot, the rate limit and the email filters to the WordPress registration form (<code>wp-login.php?action=register</code>) as well. Only relevant when "Anyone can register" is enabled in Settings &gt; General.',
				)
			);

			add_settings_section(
				'adc_security_woo_email_section',
				'Email Filtering',
				null,
				'adc_security_woocommerce'
			);

			add_settings_field(
				'woo_block_disposable_emails',
				'Block Disposable Email Domains',
				array( $this, 'render_checkbox_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_email_section',
				array(
					'label_for'   => 'woo_block_disposable_emails',
					'description' => 'Reject checkout and registration submissions that use a known disposable/throwaway mailbox provider (mailinator.com, yopmail.com and similar).',
				)
			);

			add_settings_field(
				'woo_blocked_email_domains',
				'Additional Blocked Domains',
				array( $this, 'render_textarea_field' ),
				'adc_security_woocommerce',
				'adc_security_woo_email_section',
				array(
					'label_for'   => 'woo_blocked_email_domains',
					'description' => 'One domain per line. Subdomains are blocked too. The built-in disposable provider list always applies; the <code>adc_security_blocked_email_domains</code> filter can extend the list from code.',
				)
			);
		}
	}

	/**
	 * Render role checkboxes for the "Require 2FA For" field.
	 *
	 * @param array $args Field arguments.
	 */
	public function render_role_checkboxes_field( $args ) {
		$options  = get_option( self::OPTION_NAME );
		$selected = isset( $options[ $args['label_for'] ] ) && is_array( $options[ $args['label_for'] ] ) ? $options[ $args['label_for'] ] : array();

		foreach ( wp_roles()->get_names() as $role_slug => $role_label ) {
			?>
			<label class="adc-block-label">
				<input type="checkbox"
					name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . '][]' ); ?>"
					value="<?php echo esc_attr( $role_slug ); ?>"
					<?php checked( in_array( $role_slug, $selected, true ) ); ?>>
				<?php echo esc_html( translate_user_role( $role_label ) ); ?>
			</label>
			<?php
		}
		echo '<p class="description">' . wp_kses_post( $args['description'] ) . '</p>';
	}


	/**
	 * Add admin menu.
	 */
	public function add_admin_menu() {
		$hook = add_menu_page(
			'ADC Core Security',
			'ADC Core Security',
			'manage_options',
			'adc-security',
			array( $this, 'render_settings_page' ),
			ADC_SECURITY_URL . 'assets/svg/icon.svg',
			80
		);

        // Common fix for "strip_tags" warning: add a hidden submenu with same slug to force title resolution
        add_submenu_page(
            'adc-security',
            'ADC Core Security',
            'ADC Core Security',
            'manage_options',
            'adc-security',
            array( $this, 'render_settings_page' )
        );
        
        add_action( 'admin_enqueue_scripts', array( $this, 'maybe_enqueue_admin_scripts' ) );
        add_action( 'admin_head', array( $this, 'add_menu_icon_styles' ) );
	}

    /**
     * Enqueue admin assets only on the plugin's own screen.
     *
     * @param string $hook_suffix Current admin page hook suffix.
     */
    public function maybe_enqueue_admin_scripts( $hook_suffix ) {
        if ( 'toplevel_page_adc-security' !== $hook_suffix ) {
            return;
        }

        $this->enqueue_admin_scripts();
    }

    /**
     * Add custom styles for the menu icon.
     */
    public function add_menu_icon_styles() {
        ?>
        <style>
            #toplevel_page_adc-security .wp-menu-image {
                float: left;
                width: 36px;
                height: 34px;
                margin: 0;
                text-align: center;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            #toplevel_page_adc-security .wp-menu-image img {
                width: 20px; /* Keeper icon size reasonable but container as requested */
                height: auto;
                padding: 0;
            }
        </style>
        <?php
    }

    /**
     * Enqueue Admin Scripts
     */
    public function enqueue_admin_scripts() {
        wp_enqueue_style( 'adc-admin-css', ADC_SECURITY_URL . 'assets/css/adc-admin.css', array(), ADC_SECURITY_VERSION );
        wp_enqueue_script( 'adc-admin-settings', ADC_SECURITY_URL . 'assets/js/adc-admin-settings.js', array( 'jquery' ), ADC_SECURITY_VERSION, true );
    }

    /**
     * Handle the debug info export.
     */
    public function handle_debug_export() {
        if ( ! isset( $_POST['adc_security_action'] ) || 'export_debug' !== $_POST['adc_security_action'] ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        check_admin_referer( 'adc_security_export_debug', 'adc_security_export_nonce' );

        $options = get_option( self::OPTION_NAME, array() );
        $blocked_ips = get_option( 'adc_locked_ips', array() );

        $report = "=== ADC CORE SECURITY DEBUG REPORT ===\r\n";
        $report .= "Generated: " . date( 'Y-m-d H:i:s' ) . "\r\n\r\n";

        $report .= "--- System Info ---\r\n";
        $report .= "WP Version: " . get_bloginfo( 'version' ) . "\r\n";
        $report .= "PHP Version: " . phpversion() . "\r\n";
        $report .= "Server: " . ( isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : 'Unknown' ) . "\r\n";
        $report .= "Active Theme: " . wp_get_theme()->get( 'Name' ) . "\r\n";
        $report .= "SSL: " . ( is_ssl() ? 'Yes' : 'No' ) . "\r\n\r\n";

        $report .= "--- Plugin Settings ---\r\n";
        foreach ( $options as $key => $value ) {
            if ( strpos( $key, 'key' ) !== false ) {
                $value = '****HIDDEN****'; // Don't export actual keys
            }
            $report .= $key . ": " . ( is_array( $value ) ? json_encode( $value ) : $value ) . "\r\n";
        }

        $report .= "\r\n--- Blocked IPs ---\r\n";
        if ( empty( $blocked_ips ) ) {
            $report .= "None\r\n";
        } else {
            foreach ( $blocked_ips as $ip => $expiry ) {
                $report .= "IP: $ip - Expires: " . date( 'Y-m-d H:i:s', $expiry ) . "\r\n";
            }
        }

        $report .= "\r\n--- Error & Activity Logs ---\r\n";
        $logs = ADC_Security_Logger::get_logs();
        if ( empty( $logs ) ) {
            $report .= "None recorded.\r\n";
        } else {
            foreach ( $logs as $log ) {
                $report .= sprintf( "[%s] [%s] %s | URL: %s\r\n", $log['timestamp'], $log['level'], $log['message'], $log['url'] );
            }
        }

        header( 'Content-Type: text/plain' );
        header( 'Content-Disposition: attachment; filename="adc-security-debug-report.txt"' );
        echo $report;
        exit;
    }

    /**
     * Handle the clear logs action.
     */
    public function handle_clear_logs() {
        if ( ! isset( $_POST['adc_security_action'] ) || 'clear_logs' !== $_POST['adc_security_action'] ) {
            return;
        }

        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        check_admin_referer( 'adc_security_clear_logs', 'adc_security_clear_nonce' );

        ADC_Security_Logger::clear_logs();

        add_action( 'admin_notices', function() {
            echo '<div class="updated"><p>ADC Security: Logs cleared successfully.</p></div>';
        } );
    }

	/**
	 * Apply the selected fixed .htaccess rules.
	 */
	public function handle_apply_htaccess() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to modify server rules.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_apply_htaccess', 'adc_security_htaccess_nonce' );

		$options = get_option( self::OPTION_NAME, array() );
		$rules   = isset( $options['htaccess_rules'] ) && is_array( $options['htaccess_rules'] ) ? $options['htaccess_rules'] : array();
		$result  = $this->htaccess->apply( $rules );

		if ( is_wp_error( $result ) ) {
			$this->redirect_htaccess_action( 'error', $result->get_error_code() );
		}

		$this->redirect_htaccess_action( 'applied' );
	}

	/**
	 * Revert only the managed ADC Security .htaccess block.
	 */
	public function handle_revert_htaccess() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to revert server rules.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_revert_htaccess', 'adc_security_htaccess_nonce' );

		$result = $this->htaccess->revert();
		if ( is_wp_error( $result ) ) {
			$this->redirect_htaccess_action( 'error', $result->get_error_code() );
		}

		$this->redirect_htaccess_action( 'reverted' );
	}

	/**
	 * Redirect back to the Hardening tab after a server-rule action.
	 *
	 * @param string $result Result key.
	 * @param string $error Error code when result is error.
	 */
	private function redirect_htaccess_action( $result, $error = '' ) {
		$args = array(
			'page'             => 'adc-security',
			'tab'              => 'hardening',
			'htaccess_result'  => sanitize_key( $result ),
		);

		if ( 'error' === $result && $error ) {
			$args['htaccess_error'] = sanitize_key( $error );
		}

		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Regenerate wp-config.php security keys from the WordPress.org API.
	 */
	public function handle_regenerate_keys() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to modify security keys.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_regenerate_keys', 'adc_security_keys_nonce' );

		$result = $this->keys->regenerate();

		if ( is_wp_error( $result ) ) {
			$this->redirect_keys_action( 'error', $result->get_error_code() );
		}

		$this->redirect_keys_action( 'regenerated' );
	}

	/**
	 * Restore wp-config.php security keys from the last backup.
	 */
	public function handle_restore_keys() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to modify security keys.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_restore_keys', 'adc_security_keys_nonce' );

		$result = $this->keys->restore();

		if ( is_wp_error( $result ) ) {
			$this->redirect_keys_action( 'error', $result->get_error_code() );
		}

		$this->redirect_keys_action( 'restored' );
	}

	/**
	 * Redirect back to the Hardening tab after a security-key action.
	 *
	 * @param string $result Result key.
	 * @param string $error Error code when result is error.
	 */
	private function redirect_keys_action( $result, $error = '' ) {
		$args = array(
			'page'         => 'adc-security',
			'tab'          => 'hardening',
			'keys_result'  => sanitize_key( $result ),
		);

		if ( 'error' === $result && $error ) {
			$args['keys_error'] = sanitize_key( $error );
		}

		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php' ) ) );
		exit;
	}

	/**
	 * Unblock a locked-out IP address.
	 */
	public function handle_unblock_ip() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to modify blocked IP addresses.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_unblock_ip', 'adc_unblock_nonce' );

		if ( ! empty( $_POST['adc_unblock_ip'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_POST['adc_unblock_ip'] ) );
			adc_security()->login->unblock_ip( $ip );
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'         => 'adc-security',
					'tab'          => 'login',
					'adc_notice'   => 'unblocked',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * Export the last 5000 audit-log events as a CSV download.
	 */
	public function handle_export_events() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to export the activity log.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_export_events', 'adc_security_events_export_nonce' );

		global $wpdb;
		$table = ADC_Security_Install::events_table();
		$rows  = $wpdb->get_results( "SELECT event_time, event_type, severity, user_id, username, ip, object, context FROM {$table} ORDER BY id DESC LIMIT 5000", ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName, WordPress.DB.PreparedSQL.NotPrepared

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="adc-security-activity-' . gmdate( 'Y-m-d' ) . '.csv"' );

		$output = fopen( 'php://output', 'w' );
		fputcsv( $output, array( 'Time', 'Type', 'Severity', 'User ID', 'Username', 'IP', 'Object', 'Context' ) );
		foreach ( (array) $rows as $row ) {
			fputcsv( $output, $row );
		}
		fclose( $output );
		exit;
	}

	/**
	 * Render settings page.
	 */
	public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $active_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'overview';
		?>
		<div class="wrap">
            <div class="adc-settings-header">
                <img src="<?php echo esc_url( ADC_SECURITY_URL . 'assets/svg/icon-menu.svg' ); ?>" class="adc-logo" alt="ADcelerum Core Security" width="60" height="60">
                <div class="adc-header-title">
                    <h1>ADcelerum Core Security</h1>
                    <p>Simple, Free, & Effective WordPress Security</p>
                </div>
            </div>

            <nav class="nav-tab-wrapper">
                <a href="?page=adc-security&tab=overview" class="nav-tab <?php echo 'overview' === $active_tab ? 'nav-tab-active' : ''; ?>">Dashboard</a>
                <a href="?page=adc-security&tab=login" class="nav-tab <?php echo 'login' === $active_tab ? 'nav-tab-active' : ''; ?>">Login Security</a>
                <a href="?page=adc-security&tab=2fa" class="nav-tab <?php echo '2fa' === $active_tab ? 'nav-tab-active' : ''; ?>">Two-Factor Auth</a>
                <a href="?page=adc-security&tab=captcha" class="nav-tab <?php echo 'captcha' === $active_tab ? 'nav-tab-active' : ''; ?>">Captcha</a>
                <?php if ( class_exists( 'WooCommerce' ) ) : ?>
                    <a href="?page=adc-security&tab=woocommerce" class="nav-tab <?php echo 'woocommerce' === $active_tab ? 'nav-tab-active' : ''; ?>">WooCommerce</a>
                <?php endif; ?>
                <a href="?page=adc-security&tab=hardening" class="nav-tab <?php echo 'hardening' === $active_tab ? 'nav-tab-active' : ''; ?>">Hardening</a>
                <a href="?page=adc-security&tab=activity" class="nav-tab <?php echo 'activity' === $active_tab ? 'nav-tab-active' : ''; ?>">Activity</a>
                <a href="?page=adc-security&tab=support" class="nav-tab <?php echo 'support' === $active_tab ? 'nav-tab-active' : ''; ?>">System & Support</a>
                <a href="?page=adc-security&tab=changelog" class="nav-tab <?php echo 'changelog' === $active_tab ? 'nav-tab-active' : ''; ?>">Changelog</a>
            </nav>

            <?php
            /*
             * Print the standard WordPress settings notices. The settings form posts to
             * options.php, which registers "Settings saved." (or a validation error) as a
             * settings error, drops it in the `settings_errors` transient and redirects
             * back here with ?settings-updated=true. Without settings_errors() the screen
             * simply reloads and the save looks like it did nothing.
             */
            settings_errors();
            ?>

            <?php if ( 'overview' === $active_tab ) : ?>
                <?php if ( class_exists( 'ADC_Security_Dashboard' ) ) : ?>
                    <?php ( new ADC_Security_Dashboard( $this->htaccess, $this->keys ) )->render(); ?>
                <?php endif; ?>
                <div class="adc-overview-content">
                    <h2>Welcome to ADcelerum Core Security</h2>
                    <p>Originally, this plugin was developed exclusively to provide my clients' websites with essential security features that are missing from WordPress by default. I have now decided to make it public, as I believe these tools can help other users secure their websites more effectively.</p>
                    <p><strong>This version of the plugin will remain free forever.</strong></p>
                    <h3>Why choose ADcelerum Core Security?</h3>
                    <ul>
                        <li><strong>Lightweight & Fast:</strong> Optimized code with minimal overhead for reliable performance.</li>
                        <li><strong>Secure & Robust:</strong> Built with security best practices to provide professional-grade protection.</li>
                        <li><strong>Custom Login URL:</strong> Hide your admin area from automated bot attacks and scanners.</li>
                        <li><strong>Brute Force Shield:</strong> Automatically detect and block malicious login attempts.</li>
                        <li><strong>IP Allowlist / Denylist:</strong> Control access by IP address with IPv4, IPv6, and CIDR support.</li>
                        <li><strong>Admin Login Alerts:</strong> Get notified when an administrator signs in.</li>
                        <li><strong>Advanced Hardening:</strong> Security Headers (HSTS, CSP), REST API controls, user enumeration prevention, and more.</li>
                        <li><strong>Privacy-Friendly Captcha:</strong> Math Captcha, Cloudflare Turnstile, and honeypot.</li>
                        <li><strong>Session Expiration:</strong> Enforce configurable admin cookie lifetime for tighter access control.</li>
                    </ul>

                    <hr class="adc-section-divider">

                    <div class="adc-contact-cta">
                        <h3 class="adc-no-top-margin">Do you want a custom plugin made?</h3>
                        <p>We can help you build custom solutions tailored to your specific needs.</p>
                        <a href="https://adcelerum.ro/servicii-marketing/contact-agentia-de-publicitate/" target="_blank" class="button button-primary button-large">Contact Us</a>
                    </div>
                </div>
            <?php elseif ( 'activity' === $active_tab ) : ?>
                <?php $this->render_activity_tab(); ?>
            <?php elseif ( 'support' === $active_tab ) : ?>
                <div class="adc-support-content adc-panel">
                    <h2>System Status & Support</h2>
                    <p>Use the information below for troubleshooting or when contacting support.</p>

                    <table class="widefat striped adc-status-table">
                        <tr><td><strong>WordPress Version</strong></td><td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td></tr>
                        <tr><td><strong>PHP Version</strong></td><td><?php echo esc_html( phpversion() ); ?></td></tr>
                        <tr><td><strong>Plugin Version</strong></td><td><?php echo esc_html( ADC_SECURITY_VERSION ); ?></td></tr>
                        <tr><td><strong>Active Theme</strong></td><td><?php echo esc_html( wp_get_theme()->get( 'Name' ) ); ?></td></tr>
                        <tr><td><strong>Web Server</strong></td><td><?php echo isset( $_SERVER['SERVER_SOFTWARE'] ) ? esc_html( $_SERVER['SERVER_SOFTWARE'] ) : 'Unknown'; ?></td></tr>
                        <tr><td><strong>HTTPS</strong></td><td><?php echo is_ssl() ? 'Yes' : 'No'; ?></td></tr>
                    </table>

                    <div class="adc-debug-export">
                        <div>
                            <h3 class="adc-no-top-margin">Export Debug Report</h3>
                            <p>Generate a text file containing your current site settings, blocked IPs, and error logs.</p>
                            <form method="post" action="">
                                <?php wp_nonce_field( 'adc_security_export_debug', 'adc_security_export_nonce' ); ?>
                                <input type="hidden" name="adc_security_action" value="export_debug">
                                <button type="submit" class="button button-secondary">Download .txt Report</button>
                            </form>
                        </div>
                        <div class="adc-debug-export-divider">
                            <h3 class="adc-no-top-margin">Maintenance</h3>
                            <p>Clear all recorded error and activity logs from the database.</p>
                            <form method="post" action="">
                                <?php wp_nonce_field( 'adc_security_clear_logs', 'adc_security_clear_nonce' ); ?>
                                <input type="hidden" name="adc_security_action" value="clear_logs">
                                <button type="submit" class="button button-link-delete" onclick="return confirm('Are you sure you want to clear all logs?');">Clear Error Logs</button>
                            </form>
                        </div>
                    </div>
                </div>
            <?php elseif ( 'changelog' === $active_tab ) : ?>
                <div class="adc-changelog-content adc-panel">
                    <?php
                    $changelog_file = ADC_SECURITY_DIR . 'CHANGELOG.md';
                    if ( file_exists( $changelog_file ) ) {
                        $content = file_get_contents( $changelog_file );
                        // Basic Markdown parsing for display
                        $content = preg_replace( '/^##\s+(.+)$/m', '<h2>$1</h2>', $content );
                        $content = preg_replace( '/^###\s+(.+)$/m', '<h3>$1</h3>', $content );
                        $content = preg_replace( '/^-\s+(.+)$/m', '<li>$1</li>', $content );
                        // Wrap lists
                        $content = preg_replace( '/(<li>.+<\/li>)/s', '<ul>$1</ul>', $content );
                        // Fix consecutive lists
                        $content = str_replace( '</ul><ul>', '', $content );
                        
                        echo wp_kses_post( nl2br( $content ) );
                    } else {
                        echo '<p>Changelog file not found.</p>'; 
                    }
                    ?>
                </div>
            <?php else : ?>
                <form action="options.php" method="post">
                    <?php
                    settings_fields( self::OPTION_NAME );
                    
                    if ( 'login' === $active_tab ) {
                        do_settings_sections( 'adc_security_login' );
                    } elseif ( 'captcha' === $active_tab ) {
                        do_settings_sections( 'adc_security_captcha' );
                    } elseif ( 'hardening' === $active_tab ) {
                        do_settings_sections( 'adc_security_hardening' );
                    } elseif ( '2fa' === $active_tab ) {
                        do_settings_sections( 'adc_security_2fa' );
                    } elseif ( 'woocommerce' === $active_tab && class_exists( 'WooCommerce' ) ) {
                        do_settings_sections( 'adc_security_woocommerce' );
                    }
                    
                     submit_button();
                     ?>
                 </form>
				<?php if ( 'hardening' === $active_tab ) : ?>
					<?php $this->render_htaccess_actions(); ?>
					<?php $this->render_keys_actions(); ?>
				<?php elseif ( 'login' === $active_tab ) : ?>
					<?php $this->render_locked_ips_table(); ?>
				<?php elseif ( '2fa' === $active_tab ) : ?>
					<?php if ( class_exists( 'ADC_Security_2fa' ) ) : ?>
						<?php ADC_Security_2fa::instance()->render_enrollment_panel( get_current_user_id() ); ?>
					<?php endif; ?>
				<?php endif; ?>
            <?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Sanitize settings.
	 * 
	 * @param array $input Input data.
	 * @return array Sanitized data.
	 */
	public function sanitize_settings( $input ) {
		$old_options = get_option( self::OPTION_NAME, array() );

		$new_input = $old_options;

		if ( isset( $input['custom_login_slug'] ) ) {
			$new_input['custom_login_slug'] = sanitize_title( $input['custom_login_slug'] );
		}
		if ( isset( $input['bf_max_attempts'] ) ) {
			$new_input['bf_max_attempts'] = absint( $input['bf_max_attempts'] );
		}
		if ( isset( $input['bf_lockout_duration'] ) ) {
			$new_input['bf_lockout_duration'] = absint( $input['bf_lockout_duration'] );
		}
		if ( isset( $input['captcha_type'] ) ) {
			$new_input['captcha_type'] = sanitize_key( $input['captcha_type'] );
		}
		if ( isset( $input['turnstile_site_key'] ) ) {
			$new_input['turnstile_site_key'] = sanitize_text_field( $input['turnstile_site_key'] );
		}
		if ( isset( $input['turnstile_secret_key'] ) ) {
			$new_input['turnstile_secret_key'] = sanitize_text_field( $input['turnstile_secret_key'] );
		}

		// Auto Updates
		if ( isset( $input['auto_update_plugins'] ) ) {
			$new_input['auto_update_plugins'] = in_array( $input['auto_update_plugins'], array( 'default', 'enable', 'disable' ), true ) ? $input['auto_update_plugins'] : 'default';
		}
		if ( isset( $input['auto_update_themes'] ) ) {
			$new_input['auto_update_themes'] = in_array( $input['auto_update_themes'], array( 'default', 'enable', 'disable' ), true ) ? $input['auto_update_themes'] : 'default';
		}
		if ( isset( $input['auto_update_core'] ) ) {
			$new_input['auto_update_core'] = in_array( $input['auto_update_core'], array( 'minor', 'major', 'disable' ), true ) ? $input['auto_update_core'] : 'minor';
		}

		// Checkboxes (hidden field sends 0 when unchecked)
		$checkbox_keys = array(
			'brute_force_protection',
			'login_notification',
			'hide_wp_version',
			'disable_xmlrpc',
			'disable_file_editor',
			'disable_rest_api',
			'security_headers',
			'login_honeypot',
			'login_success_notification',
			'prevent_user_enumeration',
			'admin_session_expiration_enabled',
			'csp_dynamic_scripts_compatibility',
			'disable_pingbacks',
			'disable_script_concat',
			'alert_admin_username',
			'2fa_disable_application_passwords',
			'password_block_common',
			'password_check_hibp',
			'rate_limiting_enabled',
			'virtual_patch_monitor',
			'vulnerability_feed_enabled',
			'woo_checkout_protection',
			'woo_monitor_mode',
			'woo_checkout_honeypot',
			'woo_checkout_turnstile',
			'woo_registration_protection',
			'woo_registration_honeypot',
			'woo_registration_disable_checkout_accounts',
			'woo_registration_disable_myaccount_form',
			'woo_registration_protect_wp_form',
			'woo_block_disposable_emails',
		);
		foreach ( $checkbox_keys as $key ) {
			if ( isset( $input[ $key ] ) ) {
				$new_input[ $key ] = $input[ $key ] ? 1 : 0;
			}
		}

		// .htaccess rules are an internal allowlist; no raw directives are accepted.
		if ( isset( $input['htaccess_rules'] ) && is_array( $input['htaccess_rules'] ) ) {
			$selected_rules = array_values( array_unique( array_filter( array_map( 'sanitize_key', array_filter( $input['htaccess_rules'], 'is_string' ) ) ) ) );
			$new_input['htaccess_rules'] = array_values( array_intersect( ADC_Security_Htaccess::get_rule_keys(), $selected_rules ) );
		}

		// Virtual patch rules are an internal allowlist; no raw patterns are accepted.
		if ( isset( $input['virtual_patch_rules'] ) && is_array( $input['virtual_patch_rules'] ) ) {
			$selected_patches = array_values( array_unique( array_filter( array_map( 'sanitize_key', array_filter( $input['virtual_patch_rules'], 'is_string' ) ) ) ) );
			$new_input['virtual_patch_rules'] = array_values( array_intersect( ADC_Security_Virtual_Patch::get_rule_keys(), $selected_patches ) );
		}

		if ( isset( $input['security_header_toggles'] ) && is_array( $input['security_header_toggles'] ) ) {
			$selected_headers = array_values( array_unique( array_filter( array_map( 'sanitize_key', array_filter( $input['security_header_toggles'], 'is_string' ) ) ) ) );
			$new_input['security_header_toggles'] = array_values( array_intersect( array_keys( ADC_Security_Hardening::get_security_header_definitions() ), $selected_headers ) );
		}

		// CSP header: sanitize as raw header value (no HTML, no newlines).
		if ( isset( $input['security_headers_csp'] ) ) {
			$new_input['security_headers_csp'] = sanitize_text_field( wp_unslash( $input['security_headers_csp'] ) );
		}

		// Admin session expiration days: 1..30, default 7
		if ( isset( $input['admin_session_expiration_days'] ) ) {
			$days = absint( $input['admin_session_expiration_days'] );
			if ( $days < 1 || $days > 30 ) {
				$days = 7;
			}
			$new_input['admin_session_expiration_days'] = $days;
		}

		// 2FA policy: required roles + grace period.
		if ( isset( $input['2fa_required_roles'] ) && is_array( $input['2fa_required_roles'] ) ) {
			$valid_roles = array_keys( wp_roles()->get_names() );
			$new_input['2fa_required_roles'] = array_values( array_intersect( $valid_roles, array_map( 'sanitize_key', $input['2fa_required_roles'] ) ) );
		} elseif ( isset( $input['2fa_grace_days'] ) ) {
			// Field group submitted (2fa tab) but all role checkboxes were unchecked.
			$new_input['2fa_required_roles'] = array();
		}
		if ( isset( $input['2fa_grace_days'] ) ) {
			$new_input['2fa_grace_days'] = min( 90, absint( $input['2fa_grace_days'] ) );
		}
		if ( isset( $input['password_min_length'] ) ) {
			$new_input['password_min_length'] = min( 128, absint( $input['password_min_length'] ) );
		}

		// WooCommerce abuse prevention: numeric thresholds (0 disables most rules).
		$woo_numbers = array(
			'woo_checkout_min_seconds'    => 120,
			'woo_checkout_rate_limit'     => 500,
			'woo_cart_write_limit'        => 1000,
			'woo_order_window_minutes'    => 1440,
			'woo_order_ip_limit'          => 200,
			'woo_order_email_limit'       => 500,
			'woo_order_phone_limit'       => 200,
			'woo_order_address_limit'     => 200,
			'woo_failed_order_limit'      => 100,
			'woo_registration_rate_limit' => 100,
		);
		foreach ( $woo_numbers as $key => $max ) {
			if ( isset( $input[ $key ] ) ) {
				$new_input[ $key ] = min( $max, absint( $input[ $key ] ) );
			}
		}

		// Checkout Origin/Referer enforcement mode.
		if ( isset( $input['woo_checkout_referrer_check'] ) ) {
			$allowed_modes = array( 'off', 'mismatch', 'required' );
			$new_input['woo_checkout_referrer_check'] = in_array( $input['woo_checkout_referrer_check'], $allowed_modes, true ) ? $input['woo_checkout_referrer_check'] : 'off';
		}

		// The order window must stay usable; anything below 1 minute falls back to 1.
		if ( isset( $new_input['woo_order_window_minutes'] ) && $new_input['woo_order_window_minutes'] < 1 ) {
			$new_input['woo_order_window_minutes'] = 1;
		}

		// Normalise the extra blocked email domains (built-in disposable list always applies).
		if ( isset( $input['woo_blocked_email_domains'] ) && is_string( $input['woo_blocked_email_domains'] ) ) {
			$new_input['woo_blocked_email_domains'] = implode( "\n", ADC_Security_Woo_Rules::parse_domain_list( wp_unslash( $input['woo_blocked_email_domains'] ) ) );
		}

		// IP Allowlist / Denylist: validate, normalise, deduplicate
		$ip_login = new ADC_Security_Login();
		foreach ( array( 'ip_allowlist', 'ip_denylist' ) as $list_key ) {
			if ( isset( $input[ $list_key ] ) ) {
				$raw = $input[ $list_key ];
				$new_input[ $list_key ] = $this->sanitize_ip_list( $raw, $ip_login );
			}
		}

		if ( isset( $input['trusted_proxy_header'] ) ) {
			$allowed_headers = array( '', 'CF-Connecting-IP', 'X-Real-IP', 'X-Forwarded-For' );
			$new_input['trusted_proxy_header'] = in_array( $input['trusted_proxy_header'], $allowed_headers, true ) ? $input['trusted_proxy_header'] : '';
		}
		if ( isset( $input['trusted_proxies'] ) ) {
			$new_input['trusted_proxies'] = $this->sanitize_ip_list( $input['trusted_proxies'], $ip_login );
		}

		// Flush rewriting rules if custom login slug changes.
		if ( isset( $old_options['custom_login_slug'] ) && isset( $new_input['custom_login_slug'] ) && $old_options['custom_login_slug'] !== $new_input['custom_login_slug'] ) {
			set_transient( 'adc_security_flush_rewrite_rules', true, 60 );
		}

		return $new_input;
	}

	/**
	 * Parse, validate, deduplicate and return a newline-separated IP list string.
	 *
	 * @param string            $raw      Raw textarea value.
	 * @param ADC_Security_Login $ip_login Login helper instance.
	 * @return string
	 */
	private function sanitize_ip_list( $raw, $ip_login ) {
		$lines = array_map( 'trim', explode( "\n", $raw ) );
		$valid = array();
		$seen  = array();

		foreach ( $lines as $line ) {
			$norm = $ip_login->normalize_ip_rule( $line );
			if ( false === $norm ) {
				continue;
			}
			if ( ! isset( $seen[ $norm ] ) ) {
				$seen[ $norm ] = true;
				$valid[]       = $norm;
			}
		}

		return implode( "\n", $valid );
	}

	/**
	 * Render the fixed .htaccess rule selection.
	 *
	 * @param array $args Field arguments.
	 */
	public function render_htaccess_rules_field( $args ) {
		$options  = get_option( self::OPTION_NAME, array() );
		$selected = isset( $options['htaccess_rules'] ) && is_array( $options['htaccess_rules'] ) ? $options['htaccess_rules'] : array();
		$selected = array_map( 'sanitize_key', array_filter( $selected, 'is_string' ) );
		?>
		<input type="hidden" name="<?php echo esc_attr( self::OPTION_NAME . '[htaccess_rules][]' ); ?>" value="">
		<?php foreach ( ADC_Security_Htaccess::get_rule_definitions() as $key => $definition ) : ?>
			<label class="adc-checkbox-row">
				<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[htaccess_rules][]' ); ?>" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $selected, true ) ); ?>>
				<strong><?php echo esc_html( $definition['label'] ); ?></strong>
				<br><span class="description adc-checkbox-description"><?php echo esc_html( $definition['description'] ); ?></span>
			</label>
		<?php endforeach; ?>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?> Rules are saved first; they are not active until you explicitly apply them below.</p>
		<?php
	}

	/**
	 * Section intro for the virtual patch rules.
	 */
	public function render_virtual_patch_section_intro() {
		echo '<p>Request-level guards for WordPress core vulnerabilities that are already exploited in the wild, so a site that cannot install the core update on the same day stays protected in the meantime. Every rule matches attack-shaped input only, and a legitimate page slug, post name or plugin call can never match.</p>';
	}

	/**
	 * Section intro for the known-vulnerability feed.
	 */
	public function render_vulnerability_feed_section_intro() {
		echo '<p>The daily component scan always checks plugin maintenance health locally. The optional cross-reference below adds known CVEs for the installed WordPress version and the active plugins, using the free and open WPVulnerability API (no API key, no account).</p>';
	}

	/**
	 * Render the fixed virtual patch rule selection.
	 *
	 * @param array $args Field arguments.
	 */
	public function render_virtual_patch_rules_field( $args ) {
		$options  = get_option( self::OPTION_NAME, array() );
		$selected = ADC_Security_Virtual_Patch::get_enabled_rules( is_array( $options ) ? $options : array() );
		?>
		<input type="hidden" name="<?php echo esc_attr( self::OPTION_NAME . '[virtual_patch_rules][]' ); ?>" value="">
		<?php foreach ( ADC_Security_Virtual_Patch::get_rule_definitions() as $key => $definition ) : ?>
			<label class="adc-checkbox-row">
				<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[virtual_patch_rules][]' ); ?>" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $selected, true ) ); ?>>
				<strong><?php echo esc_html( $definition['label'] ); ?></strong>
				<br><span class="description adc-checkbox-description"><?php echo esc_html( $definition['description'] ); ?></span>
			</label>
		<?php endforeach; ?>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
		<?php
	}

	/**
	 * Render the fixed security header allowlist.
	 *
	 * @param array $args Field arguments.
	 */
	public function render_security_header_toggles_field( $args ) {
		$options  = get_option( self::OPTION_NAME, array() );
		$selected = isset( $options['security_header_toggles'] ) && is_array( $options['security_header_toggles'] ) ? $options['security_header_toggles'] : array_values( array_diff( array_keys( ADC_Security_Hardening::get_security_header_definitions() ), array( 'csp' ) ) );
		$selected = array_map( 'sanitize_key', array_filter( $selected, 'is_string' ) );
		?>
		<input type="hidden" name="<?php echo esc_attr( self::OPTION_NAME . '[security_header_toggles][]' ); ?>" value="">
		<?php foreach ( ADC_Security_Hardening::get_security_header_definitions() as $key => $definition ) : ?>
			<label class="adc-checkbox-row">
				<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[security_header_toggles][]' ); ?>" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $selected, true ) ); ?>>
				<strong><?php echo esc_html( $definition['label'] ); ?></strong>
				<br><span class="description adc-checkbox-description"><?php echo esc_html( $definition['description'] ); ?></span>
			</label>
		<?php endforeach; ?>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
		<?php
	}

	/**
	 * Render explicit apply/revert controls outside the Settings API form.
	 */
	private function render_htaccess_actions() {
		$status = $this->htaccess->get_status();
		$result = isset( $_GET['htaccess_result'] ) ? sanitize_key( wp_unslash( $_GET['htaccess_result'] ) ) : '';
		$error  = isset( $_GET['htaccess_error'] ) ? sanitize_key( wp_unslash( $_GET['htaccess_error'] ) ) : '';
		?>
		<div class="adc-htaccess-controls adc-admin-panel">
			<h2>Apply Server Rules</h2>
			<?php if ( 'applied' === $result ) : ?>
				<div class="notice notice-success inline"><p>ADC Security fixed .htaccess rules were applied.</p></div>
			<?php elseif ( 'reverted' === $result ) : ?>
				<div class="notice notice-success inline"><p>ADC Security fixed .htaccess rules were reverted.</p></div>
			<?php elseif ( 'error' === $result ) : ?>
				<div class="notice notice-error inline"><p><?php echo esc_html( $this->get_htaccess_error_message( $error ) ); ?></p></div>
			<?php endif; ?>

			<p>Server: <strong><?php echo esc_html( $status['server'] ); ?></strong></p>
			<?php if ( isset( $status['error'] ) ) : ?>
				<div class="notice notice-warning inline"><p><?php echo esc_html( $status['error'] ); ?></p></div>
			<?php elseif ( ! $status['supported'] ) : ?>
				<div class="notice notice-warning inline"><p>Automatic changes are disabled on this server family. Use the fixed rules as a reference for the server administrator.</p></div>
				<?php if ( $status['managed'] ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="adc_security_revert_htaccess">
						<?php wp_nonce_field( 'adc_security_revert_htaccess', 'adc_security_htaccess_nonce' ); ?>
						<button type="submit" class="button button-secondary">Revert ADC Rules</button>
					</form>
				<?php endif; ?>
			<?php else : ?>
				<p>Status: <strong><?php echo $status['managed'] ? 'ADC Security rules are present.' : 'No ADC Security rule block is active.'; ?></strong></p>
				<?php if ( ! empty( $status['drift'] ) ) : ?>
					<div class="notice notice-warning inline"><p>The managed .htaccess file changed outside ADC Security. Apply or revert will preserve external changes.</p></div>
				<?php endif; ?>
				<p class="description">Save the selected rules above, then apply them explicitly. Revert removes only the ADC Security marker block and preserves other server rules.</p>
				<div>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-inline-form">
						<input type="hidden" name="action" value="adc_security_apply_htaccess">
						<?php wp_nonce_field( 'adc_security_apply_htaccess', 'adc_security_htaccess_nonce' ); ?>
						<button type="submit" class="button button-primary">Apply Selected Rules</button>
					</form>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-inline-form adc-inline-form-tight">
						<input type="hidden" name="action" value="adc_security_revert_htaccess">
						<?php wp_nonce_field( 'adc_security_revert_htaccess', 'adc_security_htaccess_nonce' ); ?>
						<button type="submit" class="button button-secondary" onclick="return confirm('Revert only the ADC Security .htaccess block?');">Revert ADC Rules</button>
					</form>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Map internal errors to safe admin-facing messages.
	 *
	 * @param string $error Error code.
	 * @return string
	 */
	private function get_htaccess_error_message( $error ) {
		$messages = array(
			'adc_htaccess_unsupported_server' => 'Automatic .htaccess changes are unavailable on this server.',
			'adc_htaccess_no_rules'           => 'Select at least one fixed rule before applying changes.',
			'adc_htaccess_invalid_rules'      => 'The rule selection was invalid.',
			'adc_htaccess_unknown_rule'       => 'An unknown rule was rejected.',
			'adc_htaccess_invalid_markers'    => 'The existing ADC Security marker block is malformed. No changes were made.',
			'adc_htaccess_symlink'             => 'The .htaccess file is a symlink and was not modified.',
			'adc_htaccess_not_writable'       => 'The WordPress home directory is not writable.',
			'adc_htaccess_too_large'          => 'The .htaccess file is larger than the safe processing limit.',
			'adc_htaccess_unreadable'         => 'The .htaccess file could not be read.',
			'adc_htaccess_write_failed'       => 'The temporary .htaccess file could not be written completely.',
			'adc_htaccess_rename_failed'      => 'The updated .htaccess file could not be installed.',
		);

		return isset( $messages[ $error ] ) ? $messages[ $error ] : 'The server rule operation was not completed.';
	}

	/**
	 * Render explicit security-key regenerate/restore controls.
	 */
	private function render_keys_actions() {
		$status = $this->keys->get_status();
		$result = isset( $_GET['keys_result'] ) ? sanitize_key( wp_unslash( $_GET['keys_result'] ) ) : '';
		$error  = isset( $_GET['keys_error'] ) ? sanitize_key( wp_unslash( $_GET['keys_error'] ) ) : '';
		?>
		<div class="adc-keys-controls adc-admin-panel">
			<h2>Security Keys</h2>
			<?php if ( 'regenerated' === $result ) : ?>
				<div class="notice notice-success inline"><p>ADC Security: new authentication keys were fetched from WordPress.org and applied. All logged-in sessions, including yours, were invalidated.</p></div>
			<?php elseif ( 'restored' === $result ) : ?>
				<div class="notice notice-success inline"><p>ADC Security: the previous authentication keys were restored.</p></div>
			<?php elseif ( 'error' === $result ) : ?>
				<div class="notice notice-error inline"><p><?php echo esc_html( $this->get_keys_error_message( $error ) ); ?></p></div>
			<?php endif; ?>

			<?php if ( isset( $status['error'] ) ) : ?>
				<div class="notice notice-warning inline"><p><?php echo esc_html( $status['error'] ); ?></p></div>
			<?php elseif ( ! $status['writable'] ) : ?>
				<div class="notice notice-warning inline"><p>wp-config.php is not writable by the web server, so keys cannot be regenerated automatically.</p></div>
			<?php else : ?>
				<p class="description">Fetches new AUTH_KEY/SALT values from the official WordPress.org secret-key service and replaces the existing definitions in wp-config.php. A backup of the current file is kept until the next regeneration. This immediately invalidates all logged-in sessions, including your own.</p>
				<div>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-inline-form">
						<input type="hidden" name="action" value="adc_security_regenerate_keys">
						<?php wp_nonce_field( 'adc_security_regenerate_keys', 'adc_security_keys_nonce' ); ?>
						<button type="submit" class="button button-primary" onclick="return confirm('Regenerate security keys now? This will log out every currently logged-in user, including you.');">Regenerate Security Keys</button>
					</form>
					<?php if ( $status['has_backup'] ) : ?>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-inline-form adc-inline-form-tight">
							<input type="hidden" name="action" value="adc_security_restore_keys">
							<?php wp_nonce_field( 'adc_security_restore_keys', 'adc_security_keys_nonce' ); ?>
							<button type="submit" class="button button-secondary" onclick="return confirm('Restore the previous security keys?');">Restore Previous Keys</button>
						</form>
						<p class="description">Last backup: <?php echo esc_html( $status['backed_up_at'] ); ?> UTC</p>
					<?php endif; ?>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Map internal security-key errors to safe admin-facing messages.
	 *
	 * @param string $error Error code.
	 * @return string
	 */
	private function get_keys_error_message( $error ) {
		$messages = array(
			'adc_keys_missing_config'        => 'wp-config.php could not be located.',
			'adc_keys_symlink'                => 'wp-config.php is a symlink and was not modified.',
			'adc_keys_invalid_path'          => 'wp-config.php could not be resolved.',
			'adc_keys_not_writable'          => 'wp-config.php is not writable.',
			'adc_keys_fetch_failed'          => 'The WordPress.org secret-key service could not be reached.',
			'adc_keys_incomplete_response'   => 'The secret-key service response was incomplete.',
			'adc_keys_definition_not_found'  => 'One or more key definitions could not be found in wp-config.php. No changes were made.',
			'adc_keys_no_change'             => 'No key definitions were changed.',
			'adc_keys_too_large'             => 'wp-config.php is larger than the safe processing limit.',
			'adc_keys_unreadable'            => 'wp-config.php could not be read.',
			'adc_keys_dir_not_writable'      => 'The wp-config.php directory is not writable.',
			'adc_keys_write_failed'          => 'The temporary wp-config.php file could not be written completely.',
			'adc_keys_rename_failed'         => 'The updated wp-config.php file could not be installed.',
			'adc_keys_no_backup'             => 'No matching security key backup is available.',
		);

		return isset( $messages[ $error ] ) ? $messages[ $error ] : 'The security key operation was not completed.';
	}

	/**
	 * Render text field.
	 * 
	 * @param array $args Field arguments.
	 */
	public function render_text_field( $args ) {
		$options = get_option( self::OPTION_NAME );
		$value   = isset( $options[ $args['label_for'] ] ) ? $options[ $args['label_for'] ] : '';
		?>
		<input type="text" name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" value="<?php echo esc_attr( $value ); ?>">
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
		<?php
	}

	/**
	 * Render checkbox field.
	 * 
	 * @param array $args Field arguments.
	 */
	public function render_checkbox_field( $args ) {
		$options = get_option( self::OPTION_NAME );
		$checked = isset( $options[ $args['label_for'] ] ) ? checked( $options[ $args['label_for'] ], 1, false ) : '';
		?>
        <input type="hidden" name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" value="0">
		<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" value="1" <?php echo $checked; ?>>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
		<?php
	}

    /**
     * Render number field.
     * 
     * @param array $args Field arguments.
     */
    public function render_number_field( $args ) {
        $options = get_option( self::OPTION_NAME );
        $value   = isset( $options[ $args['label_for'] ] ) ? $options[ $args['label_for'] ] : '';
        $min     = isset( $args['min'] ) ? 'min="' . (int) $args['min'] . '"' : '';
        $max     = isset( $args['max'] ) ? 'max="' . (int) $args['max'] . '"' : '';
        ?>
        <input type="number" name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" value="<?php echo esc_attr( $value ); ?>" <?php echo $min; ?> <?php echo $max; ?>>
        <p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
        <?php
    }

    /**
     * Render textarea field.
     *
     * @param array $args Field arguments.
     */
    public function render_textarea_field( $args ) {
        $options = get_option( self::OPTION_NAME );
        $value   = isset( $options[ $args['label_for'] ] ) ? $options[ $args['label_for'] ] : '';
        ?>
        <textarea name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" rows="6" cols="50" class="large-text code"><?php echo esc_textarea( $value ); ?></textarea>
        <p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
        <?php
    }

    /**
     * Render select field.
     * 
     * @param array $args Field arguments.
     */
    public function render_select_field( $args ) {
        $options = get_option( self::OPTION_NAME );
        $value   = isset( $options[ $args['label_for'] ] ) ? $options[ $args['label_for'] ] : '';
        ?>
        <select name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>">
            <?php foreach ( $args['options'] as $key => $label ) : ?>
                <option value="<?php echo esc_attr( $key ); ?>" <?php selected( $value, $key ); ?>><?php echo esc_html( $label ); ?></option>
            <?php endforeach; ?>
        </select>
        <p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
        <?php
    }

	/**
	 * Render the Activity tab: filterable events list + CSV export.
	 */
	public function render_activity_tab() {
		if ( ! class_exists( 'ADC_Security_Events_Table' ) ) {
			echo '<p>' . esc_html__( 'The activity log is unavailable.', 'adc-security' ) . '</p>';
			return;
		}

		$table = new ADC_Security_Events_Table();
		$table->prepare_items();
		?>
		<div class="adc-activity-content adc-admin-panel">
			<h2><?php esc_html_e( 'Activity Log', 'adc-security' ); ?></h2>
			<p class="description"><?php esc_html_e( 'Logins, lockouts, user and settings changes, and other security-relevant events.', 'adc-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-mb-10">
				<input type="hidden" name="action" value="adc_security_export_events">
				<?php wp_nonce_field( 'adc_security_export_events', 'adc_security_events_export_nonce' ); ?>
				<button type="submit" class="button button-secondary"><?php esc_html_e( 'Export CSV', 'adc-security' ); ?></button>
			</form>
			<form method="get">
				<input type="hidden" name="page" value="adc-security">
				<input type="hidden" name="tab" value="activity">
				<?php $table->display(); ?>
			</form>
		</div>
		<?php
	}

    /**
     * Render Locked IPs Table
     */
	/**
	 * Render the blocked-IP table. Rendered outside the options.php form
	 * (see the login tab branch above) so its own nonced admin-post forms
	 * never get nested inside, and never share, the settings form's nonce.
	 */
	public function render_locked_ips_table() {
		if ( isset( $_GET['adc_notice'] ) && 'unblocked' === $_GET['adc_notice'] ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'IP address unblocked.', 'adc-security' ) . '</p></div>';
		}

		$locked_ips = get_option( 'adc_locked_ips', array() );

		// Filter expired entries for display only; do not persist during a render.
		$locked_ips = array_filter(
			$locked_ips,
			static function ( $expiry ) {
				return $expiry > time();
			}
		);

		?>
		<div class="adc-locked-ips-controls adc-admin-panel">
			<h2><?php esc_html_e( 'Blocked IP Addresses', 'adc-security' ); ?></h2>
			<?php if ( empty( $locked_ips ) ) : ?>
				<p><?php esc_html_e( 'No blocked IP addresses.', 'adc-security' ); ?></p>
			<?php else : ?>
				<table class="widefat fixed striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'IP Address', 'adc-security' ); ?></th>
							<th><?php esc_html_e( 'Expires In', 'adc-security' ); ?></th>
							<th><?php esc_html_e( 'Action', 'adc-security' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $locked_ips as $ip => $expiry ) : ?>
							<tr>
								<td><?php echo esc_html( $ip ); ?></td>
								<td><?php echo esc_html( human_time_diff( time(), $expiry ) ); ?></td>
								<td>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" class="adc-inline">
										<input type="hidden" name="action" value="adc_security_unblock_ip">
										<input type="hidden" name="adc_unblock_ip" value="<?php echo esc_attr( $ip ); ?>">
										<?php wp_nonce_field( 'adc_security_unblock_ip', 'adc_unblock_nonce' ); ?>
										<button type="submit" class="button button-small button-secondary"><?php esc_html_e( 'Unblock', 'adc-security' ); ?></button>
									</form>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
		</div>
		<?php
	}
}
