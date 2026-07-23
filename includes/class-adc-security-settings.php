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
	 * Constructor.
	 */
	public function __construct( $htaccess = null ) {
		$this->htaccess = $htaccess instanceof ADC_Security_Htaccess ? $htaccess : new ADC_Security_Htaccess();
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'handle_debug_export' ) );
        add_action( 'admin_init', array( $this, 'handle_clear_logs' ) );
		add_action( 'admin_post_adc_security_apply_htaccess', array( $this, 'handle_apply_htaccess' ) );
		add_action( 'admin_post_adc_security_revert_htaccess', array( $this, 'handle_revert_htaccess' ) );
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
            'locked_ips_list',
            'Blocked IP Addresses',
            array( $this, 'render_locked_ips_table' ),
            'adc_security_login',
            'adc_security_login_section',
            array(
                'label_for' => 'locked_ips_list',
                'description' => 'List of currently locked out IP addresses.',
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
        
        add_action( 'admin_print_scripts-' . $hook, array( $this, 'enqueue_admin_scripts' ) );
        add_action( 'admin_head', array( $this, 'add_menu_icon_styles' ) );
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
        $blocked_ips = get_option( 'adc_security_blocked_ips', array() );

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
	 * Render settings page.
	 */
	public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Save Options manually if form submitted (because we might be using custom tab logic)
        // Actually, normal options.php triggers save, so we just need to display.
        // However, for successful save redirect, we need to preserve the tab.
        // We can use a hidden field '_wp_http_referer' manipulation or just let WP handle it.
        // WP redirects back to options-general.php?page=adc-security&settings-updated=true
        // We need to append the tab if possible, but WP core hardcodes the redirect in options.php.
        // A common workaround is a JS localized script or just selecting the tab based on a transient or similar.
        // For simplicity, we rely on GET 'tab'. If it's lost on save, it defaults to overview.
        
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
                <a href="?page=adc-security&tab=overview" class="nav-tab <?php echo 'overview' === $active_tab ? 'nav-tab-active' : ''; ?>">Overview</a>
                <a href="?page=adc-security&tab=login" class="nav-tab <?php echo 'login' === $active_tab ? 'nav-tab-active' : ''; ?>">Login Security</a>
                <a href="?page=adc-security&tab=captcha" class="nav-tab <?php echo 'captcha' === $active_tab ? 'nav-tab-active' : ''; ?>">Captcha</a>
                <a href="?page=adc-security&tab=hardening" class="nav-tab <?php echo 'hardening' === $active_tab ? 'nav-tab-active' : ''; ?>">Hardening</a>
                <a href="?page=adc-security&tab=support" class="nav-tab <?php echo 'support' === $active_tab ? 'nav-tab-active' : ''; ?>">System & Support</a>
                <a href="?page=adc-security&tab=changelog" class="nav-tab <?php echo 'changelog' === $active_tab ? 'nav-tab-active' : ''; ?>">Changelog</a>
            </nav>

            <?php if ( 'overview' === $active_tab ) : ?>
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

                    <hr style="margin: 30px 0; border: 0; border-top: 1px solid #ddd;">

                    <div class="adc-contact-cta" style="background: #f0f6fc; padding: 20px; border-radius: 8px; border: 1px solid #d0d7de;">
                        <h3 style="margin-top: 0;">Do you want a custom plugin made?</h3>
                        <p>We can help you build custom solutions tailored to your specific needs.</p>
                        <a href="https://adcelerum.ro/servicii-marketing/contact-agentia-de-publicitate/" target="_blank" class="button button-primary button-large">Contact Us</a>
                    </div>
                </div>
            <?php elseif ( 'support' === $active_tab ) : ?>
                <div class="adc-support-content" style="background: #fff; padding: 20px; margin-top: 20px; border: 1px solid #ccd0d4;">
                    <h2>System Status & Support</h2>
                    <p>Use the information below for troubleshooting or when contacting support.</p>
                    
                    <table class="widefat striped" style="margin-bottom: 20px; max-width: 600px;">
                        <tr><td><strong>WordPress Version</strong></td><td><?php echo esc_html( get_bloginfo( 'version' ) ); ?></td></tr>
                        <tr><td><strong>PHP Version</strong></td><td><?php echo esc_html( phpversion() ); ?></td></tr>
                        <tr><td><strong>Plugin Version</strong></td><td><?php echo esc_html( ADC_SECURITY_VERSION ); ?></td></tr>
                        <tr><td><strong>Active Theme</strong></td><td><?php echo esc_html( wp_get_theme()->get( 'Name' ) ); ?></td></tr>
                        <tr><td><strong>Web Server</strong></td><td><?php echo isset( $_SERVER['SERVER_SOFTWARE'] ) ? esc_html( $_SERVER['SERVER_SOFTWARE'] ) : 'Unknown'; ?></td></tr>
                        <tr><td><strong>HTTPS</strong></td><td><?php echo is_ssl() ? 'Yes' : 'No'; ?></td></tr>
                    </table>

                    <div class="adc-debug-export" style="background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 4px; display: flex; gap: 20px;">
                        <div>
                            <h3 style="margin-top:0;">Export Debug Report</h3>
                            <p>Generate a text file containing your current site settings, blocked IPs, and error logs.</p>
                            <form method="post" action="">
                                <?php wp_nonce_field( 'adc_security_export_debug', 'adc_security_export_nonce' ); ?>
                                <input type="hidden" name="adc_security_action" value="export_debug">
                                <button type="submit" class="button button-secondary">Download .txt Report</button>
                            </form>
                        </div>
                        <div style="border-left: 1px solid #ddd; padding-left: 20px;">
                            <h3 style="margin-top:0;">Maintenance</h3>
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
                <div class="adc-changelog-content" style="background: #fff; padding: 20px; margin-top: 20px; border: 1px solid #ccc;">
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
                    }
                    
                     submit_button();
                     ?>
                 </form>
				<?php if ( 'hardening' === $active_tab ) : ?>
					<?php $this->render_htaccess_actions(); ?>
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

		// IP Allowlist / Denylist: validate, normalise, deduplicate
		$ip_login = new ADC_Security_Login();
		foreach ( array( 'ip_allowlist', 'ip_denylist' ) as $list_key ) {
			if ( isset( $input[ $list_key ] ) ) {
				$raw = $input[ $list_key ];
				$new_input[ $list_key ] = $this->sanitize_ip_list( $raw, $ip_login );
			}
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
			<label style="display:block; margin:0 0 10px 0;">
				<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[htaccess_rules][]' ); ?>" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $selected, true ) ); ?>>
				<strong><?php echo esc_html( $definition['label'] ); ?></strong>
				<br><span class="description" style="margin-left:24px;"><?php echo esc_html( $definition['description'] ); ?></span>
			</label>
		<?php endforeach; ?>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?> Rules are saved first; they are not active until you explicitly apply them below.</p>
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
			<label style="display:block; margin:0 0 10px 0;">
				<input type="checkbox" name="<?php echo esc_attr( self::OPTION_NAME . '[security_header_toggles][]' ); ?>" value="<?php echo esc_attr( $key ); ?>" <?php checked( in_array( $key, $selected, true ) ); ?>>
				<strong><?php echo esc_html( $definition['label'] ); ?></strong>
				<br><span class="description" style="margin-left:24px;"><?php echo esc_html( $definition['description'] ); ?></span>
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
		<div class="adc-htaccess-controls" style="background:#fff; border:1px solid #ccd0d4; margin-top:20px; padding:20px; max-width:900px;">
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
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block; margin-right:8px;">
						<input type="hidden" name="action" value="adc_security_apply_htaccess">
						<?php wp_nonce_field( 'adc_security_apply_htaccess', 'adc_security_htaccess_nonce' ); ?>
						<button type="submit" class="button button-primary">Apply Selected Rules</button>
					</form>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;">
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
     * Render Locked IPs Table
     */
    public function render_locked_ips_table() {
        // Handle Unblock Action
        if ( isset( $_POST['adc_unblock_ip'] ) && check_admin_referer( 'adc_unblock_ip_nonce' ) ) {
            $ip_to_unblock = sanitize_text_field( $_POST['adc_unblock_ip'] );
            // Get login class instance to call unblock (dirty way, better via dependency injection or static, but works for singleton pattern if used)
            // Accessing via global or simpler: re-implement unblock here or instantiate.
            // Since Core holds instances, we can't easily access it without global.
            // Let's replicate logic or use a helper. 
            // Better: Load only the needed method logic here since transients are global.
            
            $transient_name = 'adc_bf_' . md5( $ip_to_unblock );
            delete_transient( $transient_name );
            
            $locked_ips = get_option( 'adc_locked_ips', array() );
            if ( isset( $locked_ips[ $ip_to_unblock ] ) ) {
                unset( $locked_ips[ $ip_to_unblock ] );
                update_option( 'adc_locked_ips', $locked_ips );
            }
            
            echo '<div class="updated"><p>IP ' . esc_html( $ip_to_unblock ) . ' unblocked.</p></div>';
        }

        $locked_ips = get_option( 'adc_locked_ips', array() );
        
        // Cleanup expired
        $updated = false;
        foreach ( $locked_ips as $ip => $expiry ) {
            if ( time() > $expiry ) {
                unset( $locked_ips[ $ip ] );
                $updated = true;
            }
        }
        if ( $updated ) {
            update_option( 'adc_locked_ips', $locked_ips );
        }

        if ( empty( $locked_ips ) ) {
            echo '<p>No blocked IP addresses.</p>';
            return;
        }

        echo '<table class="widefat fixed striped">';
        echo '<thead><tr><th>IP Address</th><th>Expires In</th><th>Action</th></tr></thead>';
        echo '<tbody>';
        
        foreach ( $locked_ips as $ip => $expiry ) {
            $time_left = $expiry - time();
            $time_str = $time_left > 0 ? human_time_diff( time(), $expiry ) : 'Expired';
            
            echo '<tr>';
            echo '<td>' . esc_html( $ip ) . '</td>';
            echo '<td>' . esc_html( $time_str ) . '</td>';
            echo '<td>';
            echo '<form method="post" style="display:inline;">';
            echo '<input type="hidden" name="adc_unblock_ip" value="' . esc_attr( $ip ) . '">';
            wp_nonce_field( 'adc_unblock_ip_nonce' );
            echo '<button type="submit" class="button button-small button-secondary">Unblock</button>';
            echo '</form>';
            echo '</td>';
            echo '</tr>';
        }
        
        echo '</tbody></table>';
    }
}
