<?php
/**
 * Plugin Name: ADC Core Security
 * Plugin URI:  https://adcelerum.ro
 * Description: Simple WordPress security plugin to prevent brute force, restrict access, and harden security.
 * Version:     1.7.4
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

// Define Plugin Constants.
define( 'ADC_SECURITY_VERSION', '1.7.4' );
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
