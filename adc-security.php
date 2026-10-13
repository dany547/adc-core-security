<?php
/**
 * Plugin Name: ADC Core Security
 * Plugin URI:  https://adcelerum.ro
 * Description: Simple WordPress security plugin to prevent brute force, restrict access, and harden security.
 * Version:     1.12.1
 * Author:      Dan Mutu - adcelerum.ro
 * Author URI:  https://adcelerum.ro
 * License:     GPL-2.0+
 * Text Domain: adc-security
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Another copy of this plugin (for example an old folder such as
// adc-core-security-1.3.7 left next to adc-security) is already loaded: stop here
// instead of redeclaring constants and functions, which would be a fatal error.
if ( defined( 'ADC_SECURITY_VERSION' ) || function_exists( 'adc_security' ) ) {
	add_action(
		'admin_notices',
		static function () {
			if ( ! current_user_can( 'activate_plugins' ) ) {
				return;
			}
			printf(
				'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s <code>%3$s</code></p></div>',
				esc_html__( 'ADC Core Security is installed twice.', 'adc-security' ),
				esc_html__( 'Deactivate and delete the duplicate copy in', 'adc-security' ),
				esc_html( basename( __DIR__ ) )
			);
		}
	);
	return;
}

// Define Plugin Constants.
define( 'ADC_SECURITY_VERSION', '1.12.1' );
define( 'ADC_SECURITY_DIR', plugin_dir_path( __FILE__ ) );
define( 'ADC_SECURITY_URL', plugin_dir_url( __FILE__ ) );
define( 'ADC_SECURITY_FILE', __FILE__ );

// GitHub Releases API URL for automatic updates.
define( 'ADC_SECURITY_GITHUB_REPO', 'dany547/adc-core-security' );
define( 'ADC_SECURITY_UPDATE_URL', 'https://api.github.com/repos/' . ADC_SECURITY_GITHUB_REPO . '/releases/latest' );

/**
 * Main Core Class
 */
require_once ADC_SECURITY_DIR . 'includes/class-adc-security-core.php';

/**
 * Main instance of ADC Security.
 *
 * Returns the main instance of ADC Security to prevent the need to use globals.
 *
 * @since  1.0.0
 * @return ADC_Security_Core
 */
function adc_security() {
	return ADC_Security_Core::instance();
}

// Global for backwards compatibility.
$GLOBALS['adc_security'] = adc_security();
