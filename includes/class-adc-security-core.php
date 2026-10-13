<?php
/**
 * ADC Security Core Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Core {

	/**
	 * Single instance of the class.
	 *
	 * @var ADC_Security_Core
	 */
	protected static $_instance = null;

	/**
	 * Settings instance.
	 * 
	 * @var ADC_Security_Settings
	 */
	public $settings;
    
	/**
	 * Logger instance.
	 * 
	 * @var ADC_Security_Logger
	 */
	public $logger;

	/**
	 * Login instance.
	 * 
	 * @var ADC_Security_Login
	 */
	public $login;

	/**
	 * Hardening instance.
	 * 
	 * @var ADC_Security_Hardening
	 */
	public $hardening;

	/**
	 * Fixed-rule .htaccess manager instance.
	 *
	 * @var ADC_Security_Htaccess
	 */
	public $htaccess;

	/**
	 * CSP policy module instance.
	 *
	 * @var ADC_Security_Csp_Policy
	 */
	public $csp;

	/**
	 * CSP violation report collector and blocked-source aggregator.
	 *
	 * @var ADC_Security_Csp_Reports
	 */
	public $csp_reports;

	/**
	 * Captcha instance.
	 *
	 * @var ADC_Security_Captcha
	 */
	public $captcha;

	/**
	 * Audit-log event recorder instance.
	 *
	 * @var ADC_Security_Events
	 */
	public $events;

	/**
	 * Rate limiter instance.
	 *
	 * @var ADC_Security_Rate_Limit
	 */
	public $rate_limit;

	/**
	 * Virtual patch (request-level CVE guard) instance.
	 *
	 * @var ADC_Security_Virtual_Patch
	 */
	public $virtual_patch;

	/**
	 * Firewall rules instance (replaces the virtual patch hooks from 1.13.0).
	 *
	 * @var ADC_Security_Firewall_Rules
	 */
	public $firewall_rules;

	/**
	 * File integrity scanner instance.
	 *
	 * @var ADC_Security_Integrity
	 */
	public $integrity;

	/**
	 * Plugin/theme health scanner instance.
	 *
	 * @var ADC_Security_Vulnerabilities
	 */
	public $vulnerabilities;

	/**
	 * WooCommerce abuse-prevention instance.
	 *
	 * @var ADC_Security_Woocommerce
	 */
	public $woocommerce;

	/**
	 * Users screen columns instance.
	 *
	 * @var ADC_Security_Users_Columns
	 */
	public $users_columns;

	/**
	 * Main ADC Security Instance.
	 *
	 * Ensures only one instance of ADC Security is loaded or can be loaded.
	 *
	 * @return ADC_Security_Core - Main instance.
	 */
	public static function instance() {
		if ( is_null( self::$_instance ) ) {
			self::$_instance = new self();
		}
		return self::$_instance;
	}

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->includes();
		$this->init_hooks();
        $this->check_version();
		$this->instantiate();
	}

    /**
     * Check for version updates and run cleanup/migration if needed.
     */
    private function check_version() {
        ADC_Security_Install::maybe_install();

        $installed_version = get_option( 'adc_security_version' );

        if ( version_compare( $installed_version, ADC_SECURITY_VERSION, '<' ) ) {
            $this->migrate_defaults();

            update_option( 'adc_security_version', ADC_SECURITY_VERSION );
        }
    }

    /**
     * Fill missing option keys with safe defaults on upgrade.
     *
     * Only inserts keys that do not yet exist so manual overrides are preserved.
     */
    private function migrate_defaults() {
        $options = get_option( 'adc_security_options', array() );

        $defaults = array(
            'login_success_notification'       => 1,
            'ip_allowlist'                     => '',
            'ip_denylist'                      => '',
            'prevent_user_enumeration'         => 0,
            'admin_session_expiration_enabled' => 0,
			'admin_session_expiration_days'    => 7,
			'htaccess_rules'                    => array(),
			'csp_dynamic_scripts_compatibility' => 0,
			'security_header_toggles'            => array_values( array_diff( array_keys( ADC_Security_Hardening::get_security_header_definitions() ), array( 'csp' ) ) ),
			'disable_pingbacks'                  => 0,
			'disable_script_concat'              => 0,
			'alert_admin_username'               => 1,
			'rate_limiting_enabled'              => 1,
			'woo_checkout_protection'            => 1,
			'woo_monitor_mode'                   => 1,
			'woo_checkout_honeypot'              => 1,
			'woo_checkout_min_seconds'           => 3,
			'woo_checkout_referrer_check'        => 'off',
			'woo_checkout_rate_limit'            => 30,
			'woo_cart_write_limit'               => 60,
			'woo_checkout_turnstile'             => 0,
			'woo_order_window_minutes'           => 60,
			'woo_order_ip_limit'                 => 10,
			'woo_order_email_limit'              => 20,
			'woo_order_phone_limit'              => 5,
			'woo_order_address_limit'            => 5,
			'woo_failed_order_limit'             => 5,
			'woo_registration_protection'        => 1,
			'woo_registration_honeypot'          => 1,
			'woo_registration_rate_limit'        => 10,
			'woo_registration_disable_checkout_accounts' => 0,
			'woo_registration_disable_myaccount_form'    => 0,
			'woo_registration_protect_wp_form'   => 1,
			'woo_block_disposable_emails'        => 1,
			'woo_blocked_email_domains'          => '',
			// Deprecated since 1.13.0: migrated once into the adc_security_firewall option (see ADC_Security_Firewall_Rules::maybe_migrate()). Kept, not deleted.
			'virtual_patch_rules'                => array(),
			'virtual_patch_monitor'              => 0,
			'vulnerability_feed_enabled'         => 0,
			'csp_mode'                           => 'off',
			'csp_report_only'                    => 0,
			'csp_presets'                        => array(),
			'csp_extra_sources'                  => array(),
			'csp_removed_defaults'               => array(),
			'referrer_policy_value'              => 'strict-origin-when-cross-origin',
			'permissions_policy_mode'            => 'standard',
			'permissions_policy_custom'          => '',
			'hsts_max_age'                       => 31536000,
			'hsts_include_subdomains'            => 1,
			'hsts_preload'                       => 0,
        );

        $changed = false;
        foreach ( $defaults as $key => $value ) {
            if ( ! array_key_exists( $key, $options ) ) {
                $options[ $key ] = $value;
                $changed = true;
            }
        }

		// CSP is opt-in from 1.7.2 onward. Preserve all other header choices while
		// removing the default CSP that 1.7.0/1.7.1 added automatically.
		if (
			version_compare( ADC_SECURITY_VERSION, '1.7.2', '>=' ) &&
			version_compare( (string) get_option( 'adc_security_version', '0.0.0' ), '1.7.2', '<' ) &&
			isset( $options['security_header_toggles'] ) && is_array( $options['security_header_toggles'] ) &&
			in_array( 'csp', $options['security_header_toggles'], true )
		) {
			$options['security_header_toggles'] = array_values( array_diff( $options['security_header_toggles'], array( 'csp' ) ) );
			$changed = true;
		}

		// 1.12.1: older key backups stored the whole wp-config.php (DB credentials
		// included) in wp_options. Reduce them to the key lines only.
		if ( version_compare( (string) get_option( 'adc_security_version', '0.0.0' ), '1.12.1', '<' ) && class_exists( 'ADC_Security_Keys' ) ) {
			ADC_Security_Keys::scrub_legacy_backup();
		}

		// 1.12.0 replaced the CSP checkbox with a mode. Derive it from the old state:
		// a site that had CSP ticked keeps it (custom if it had text, otherwise standard);
		// every other site stays off, even if old custom text exists. Only runs once,
		// on the upgrade from a version older than 1.12.0.
		if ( version_compare( (string) get_option( 'adc_security_version', '0.0.0' ), '1.12.0', '<' ) ) {
			$had_csp = isset( $options['security_header_toggles'] ) && is_array( $options['security_header_toggles'] ) && in_array( 'csp', $options['security_header_toggles'], true );
			$custom  = isset( $options['security_headers_csp'] ) && is_string( $options['security_headers_csp'] ) ? trim( $options['security_headers_csp'] ) : '';

			if ( ! $had_csp ) {
				$mode = 'off';
			} else {
				$mode = '' !== $custom ? 'custom' : 'standard';
			}

			if ( ! isset( $options['csp_mode'] ) || $options['csp_mode'] !== $mode ) {
				$options['csp_mode'] = $mode;
				$changed = true;
			}
		}

		// 1.13.2: service presets are expanded once into csp_extra_sources, so the
		// stored list is the single source of truth. The generated policy is unchanged.
		if ( version_compare( (string) get_option( 'adc_security_version', '0.0.0' ), '1.13.2', '<' ) && class_exists( 'ADC_Security_Csp_Scanner' ) && ! empty( $options['csp_presets'] ) && is_array( $options['csp_presets'] ) ) {
			$extra_sources = isset( $options['csp_extra_sources'] ) && is_array( $options['csp_extra_sources'] ) ? $options['csp_extra_sources'] : array();
			$options['csp_extra_sources'] = ADC_Security_Csp_Scanner::expand_presets( $options['csp_presets'], $extra_sources );
			$options['csp_presets']       = array();
			$changed = true;
		}

        if ( $changed ) {
            update_option( 'adc_security_options', $options, false );
        }
    }

	/**
	 * Include required files.
	 */
	private function includes() {
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-ip.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-htaccess.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-keys.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-csp.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-csp-reports.php';
		if ( file_exists( ADC_SECURITY_DIR . 'includes/class-adc-security-csp-scanner.php' ) ) {
			require_once ADC_SECURITY_DIR . 'includes/class-adc-security-csp-scanner.php';
		}
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-settings.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-login.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-hardening.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-captcha.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-updater.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-logger.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-score.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-cron-health.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-install.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-events.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-stats.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-totp.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-2fa.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-rate-limit.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-virtual-patch.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-matchers.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-registry.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-engine.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-rules.php';
		if ( file_exists( ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-admin.php' ) ) {
			require_once ADC_SECURITY_DIR . 'includes/class-adc-security-firewall-admin.php';
		}
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-integrity.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-vulnerabilities.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-woo-rules.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-woocommerce.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-users-columns.php';

		if ( is_admin() ) {
			require_once ADC_SECURITY_DIR . 'includes/class-adc-security-dashboard.php';
			require_once ADC_SECURITY_DIR . 'includes/class-adc-security-events-table.php';
		}
	}

	/**
	 * Instantiate classes.
	 */
	private function instantiate() {
		$this->logger    = new ADC_Security_Logger();
		$this->htaccess  = new ADC_Security_Htaccess();
		$this->csp       = new ADC_Security_Csp_Policy();
		$this->csp_reports = new ADC_Security_Csp_Reports();
		$this->csp_reports->register();
		$this->settings  = new ADC_Security_Settings( $this->htaccess );
		$this->login     = new ADC_Security_Login();
		$this->rate_limit = new ADC_Security_Rate_Limit( $this->login );
		$this->virtual_patch = new ADC_Security_Virtual_Patch(); // Deprecated; registers no hooks.
		$this->firewall_rules = new ADC_Security_Firewall_Rules();
		$this->firewall_rules->register();
		if ( class_exists( 'ADC_Security_Firewall_Admin' ) ) {
			ADC_Security_Firewall_Admin::init();
		}
		$this->integrity      = new ADC_Security_Integrity();
		$this->vulnerabilities = new ADC_Security_Vulnerabilities();
		$this->hardening = new ADC_Security_Hardening( $this->csp );
		$this->captcha   = new ADC_Security_Captcha();
		$this->events    = new ADC_Security_Events();
		$this->woocommerce   = new ADC_Security_Woocommerce( $this->login, $this->captcha );
		$this->users_columns = new ADC_Security_Users_Columns();
		ADC_Security_2fa::instance();

        // Init Updater
        new ADC_Security_Updater();
	}

	/**
	 * Hook into actions and filters.
	 */
	private function init_hooks() {
		// Add settings link to plugins page.
		add_filter( 'plugin_action_links_' . plugin_basename( ADC_SECURITY_FILE ), array( $this, 'add_settings_link' ) );
	}

	/**
	 * Add settings link to plugins page.
	 * 
	 * @param array $links Plugin action links.
	 * @return array Modified links.
	 */
	public function add_settings_link( $links ) {
		$settings_link = '<a href="' . admin_url( 'admin.php?page=adc-security' ) . '">Settings</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}
}
