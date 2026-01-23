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
            // Run upgrade routines here if needed in future
            
            // Update version in DB
            update_option( 'adc_security_version', ADC_SECURITY_VERSION );
        }
    }

	/**
	 * Include required files.
	 */
	private function includes() {
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
		$this->settings  = new ADC_Security_Settings();
		$this->login     = new ADC_Security_Login();
		$this->hardening = new ADC_Security_Hardening();
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
