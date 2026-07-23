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
	 * Captcha instance.
	 * 
	 * @var ADC_Security_Captcha
	 */
	public $captcha;

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

        if ( $changed ) {
            update_option( 'adc_security_options', $options, false );
        }
    }

	/**
	 * Include required files.
	 */
	private function includes() {
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-htaccess.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-csp.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-settings.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-login.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-hardening.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-captcha.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-updater.php';
		require_once ADC_SECURITY_DIR . 'includes/class-adc-security-logger.php';
	}

	/**
	 * Instantiate classes.
	 */
	private function instantiate() {
		$this->logger    = new ADC_Security_Logger();
		$this->htaccess  = new ADC_Security_Htaccess();
		$this->csp       = new ADC_Security_Csp_Policy();
		$this->settings  = new ADC_Security_Settings( $this->htaccess );
		$this->login     = new ADC_Security_Login();
		$this->hardening = new ADC_Security_Hardening( $this->csp );
		$this->captcha   = new ADC_Security_Captcha();
        
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
		$settings_link = '<a href="' . admin_url( 'options-general.php?page=adc-security' ) . '">Settings</a>';
		array_unshift( $links, $settings_link );
		return $links;
	}
}
