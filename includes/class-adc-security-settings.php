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
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'handle_debug_export' ) );
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

        add_settings_field(
			'security_headers',
			'Enable Security Headers',
			array( $this, 'render_checkbox_field' ),
			'adc_security_hardening',
			'adc_security_hardening_section',
			array(
				'label_for' => 'security_headers',
				'description' => 'Adds the following HTTP security headers to protect your site:<br>
                <ul>
                    <li><strong>X-Content-Type-Options:</strong> nosniff (Prevents MIME-type sniffing)</li>
                    <li><strong>X-Frame-Options:</strong> SAMEORIGIN (Prevents clickjacking)</li>
                    <li><strong>X-XSS-Protection:</strong> 1; mode=block (Enables XSS filtering)</li>
                    <li><strong>Referrer-Policy:</strong> strict-origin-when-cross-origin (Controls referrer info)</li>
                    <li><strong>Content-Security-Policy:</strong> Safe defaults (Protects against XSS)</li>
                    <li><strong>Permissions-Policy:</strong> Disables sensitive features (Camera, Mic, etc.)</li>
                    <li><strong>Strict-Transport-Security:</strong> max-age=31536000; includeSubDomains (Enforces HTTPS)</li>
                </ul>',
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
            'Plugin Updates',
            array( $this, 'render_select_field' ),
            'adc_security_hardening',
            'adc_security_updates_section',
            array(
                'label_for' => 'auto_update_plugins',
                'description' => 'Control automatic updates for all plugins.',
                'options' => array(
                    'default' => 'Default (Manual)',
                    'enable'  => 'Enable All',
                    'disable' => 'Disable All',
                ),
            )
        );

        add_settings_field(
            'auto_update_themes',
            'Theme Updates',
            array( $this, 'render_select_field' ),
            'adc_security_hardening',
            'adc_security_updates_section',
            array(
                'label_for' => 'auto_update_themes',
                'description' => 'Control automatic updates for all themes.',
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
            foreach ( $blocked_ips as $ip => $data ) {
                $report .= "IP: $ip - Blocked until: " . date( 'Y-m-d H:i:s', $data['timestamp'] + $data['duration'] * 60 ) . "\r\n";
            }
        }

        header( 'Content-Type: text/plain' );
        header( 'Content-Disposition: attachment; filename="adc-security-debug-report.txt"' );
        echo $report;
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
                        <li><strong>Lightweight & Fast:</strong> Optimized code with no bloat, ensuring zero impact on your site's speed.</li>
                        <li><strong>Secure & Robust:</strong> Built with security best practices to provide reliable, professional-grade protection.</li>
                        <li><strong>Custom Login URL:</strong> Hide your admin area from automated bot attacks and scanners.</li>
                        <li><strong>Brute Force Shield:</strong> Automatically detect and block malicious login attempts.</li>
                        <li><strong>Advanced Hardening:</strong> One-click implementation of Security Headers (HSTS, CSP) and core protection.</li>
                        <li><strong>Privacy-Friendly Captcha:</strong> Effortless integration with Math Captcha and Cloudflare Turnstile.</li>
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
                        <tr><td><strong>WordPress Version</strong></td><td><?php echo get_bloginfo( 'version' ); ?></td></tr>
                        <tr><td><strong>PHP Version</strong></td><td><?php echo phpversion(); ?></td></tr>
                        <tr><td><strong>Plugin Version</strong></td><td><?php echo ADC_SECURITY_VERSION; ?></td></tr>
                        <tr><td><strong>Active Theme</strong></td><td><?php echo wp_get_theme()->get( 'Name' ); ?></td></tr>
                        <tr><td><strong>Web Server</strong></td><td><?php echo isset( $_SERVER['SERVER_SOFTWARE'] ) ? esc_html( $_SERVER['SERVER_SOFTWARE'] ) : 'Unknown'; ?></td></tr>
                        <tr><td><strong>HTTPS</strong></td><td><?php echo is_ssl() ? 'Yes' : 'No'; ?></td></tr>
                    </table>

                    <div class="adc-debug-export" style="background: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 4px;">
                        <h3 style="margin-top:0;">Export Debug Report</h3>
                        <p>Generate a text file containing your current site settings and system info for analysis.</p>
                        <form method="post" action="">
                            <?php wp_nonce_field( 'adc_security_export_debug', 'adc_security_export_nonce' ); ?>
                            <input type="hidden" name="adc_security_action" value="export_debug">
                            <button type="submit" class="button button-secondary">Download .txt Report</button>
                        </form>
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
        // Retrieve existing options to merge with, as generic settings API might overwrite with partial data if we are not careful.
        // But wait, key point: 'register_setting' passes the NEW input for the whole option group.
        // If the form on 'login' tab only has login fields, $input will ONLY contain login fields.
        // The other fields (captcha, hardening) will be MISSING from $input.
        // If we return $input as is, we lose the other settings.
        // We MUST merge with existing database values.

		$old_options = get_option( self::OPTION_NAME, array() );
        
        // Start with old options, overwrite with new input provided
        $new_input = $old_options;
        
        // Loop through known fields and update if present in input, or unset/false if checkbox missing?
        // Checkboxes are tricky. If unchecked, they are not sent in POST.
        // If we are on 'Login' tab, 'brute_force_protection' checkbox might be missing if unchecked. 
        // But 'hide_wp_version' (Hardening tab) is also missing.
        // We need to know WHICH tab we are saving to know what "missing" means (unchecked vs not on screen).
        
        // We can detect which fields *should* be present based on the submitted sections, 
        // OR we can just check if specific known fields are set in $_POST/input.
        // A cleaner way in WP: use hidden fields to indicate which context/tab we are in?
        // Or just leniently update only keys that exist in $input, but handle checkboxes explicitly?
        
        // Problem: Unchecked checkbox sends NOTHING.
        // Soluation: Add a hidden field 'adc_tab_context' in the form.
        
        $tab = isset( $_POST['_wp_http_referer'] ) ? $_POST['_wp_http_referer'] : '';
        // Parse tab from referrer? Too brittle.
        
        // Let's assume we handle standard fields.
        
        // Helper to update checkbox logic
        // Only update these if we are on the relevant tab.
        // We can check if *any* field from a section is present to guess the tab?
        // Or just look at $_POST keys.
        
        // Let's rely on merging logic:
        // Update simple scalar values if set.
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
            $new_input['auto_update_plugins'] = sanitize_key( $input['auto_update_plugins'] );
        }
        if ( isset( $input['auto_update_themes'] ) ) {
            $new_input['auto_update_themes'] = sanitize_key( $input['auto_update_themes'] );
        }
        if ( isset( $input['auto_update_core'] ) ) {
            $new_input['auto_update_core'] = sanitize_key( $input['auto_update_core'] );
        }

        // Checkboxes:
        // We must know if the user *saw* the checkbox to know if missing means "off".
        // Instead of strict tab detection, let's use the valid list approach and update if corresponding trigger is found?
        // Or just update all known checkboxes present in input to 1.
        // BUT how to set to 0?
        // Standard trick: <input type="hidden" name="adc_security_options[brute_force_protection]" value="0"> 
        // before the checkbox. WP Settings API doesn't do this automatically for `render_checkbox_field`.
        // I should update `render_checkbox_field` to include the hidden 0 value fallback.
        
        // Let's update `render_checkbox_field` first in a separate step?
        // For now, let's just assume if we receive ANY input for a tab, we process its checkboxes.
        // Let's try to detect context from $_POST directly or just iterate keys.
        
        // Actually, if I change `render_checkbox_field` to print a hidden input with value 0 before, 
        // then `$input` WILL contain 0 if unchecked. 
        // That allows safe merging.
        
        // I will assume I'll make that change in `render_checkbox_field`.
        // So here I just iterate $input.
        
        foreach ( $input as $key => $val ) {
            // For checkboxes that send '0' or '1'
             $new_input[ $key ] = $val;
        }

		// Flush rewriting rules if custom login slug changes.
		if ( isset( $old_options['custom_login_slug'] ) && isset( $new_input['custom_login_slug'] ) && $old_options['custom_login_slug'] !== $new_input['custom_login_slug'] ) {
            set_transient( 'adc_security_flush_rewrite_rules', true, 60 );
		}

		return $new_input;
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
        $min = isset( $args['min'] ) ? 'min="' . $args['min'] . '"' : '';
        ?>
        <input type="number" name="<?php echo esc_attr( self::OPTION_NAME . '[' . $args['label_for'] . ']' ); ?>" value="<?php echo esc_attr( $value ); ?>" <?php echo $min; ?>>
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
