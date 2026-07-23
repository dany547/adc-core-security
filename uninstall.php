<?php
/**
 * Fired when the plugin is uninstalled.
 *
 * @package ADCSecurity
 */

// Abort if called directly.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// Remove plugin options.
delete_option( 'adc_security_options' );
delete_option( 'adc_security_version' );
delete_option( 'adc_security_error_log' );
delete_option( 'adc_locked_ips' );
delete_option( 'adc_security_htaccess_backup' );
delete_option( 'adc_security_htaccess_state' );

// Remove brute-force transients.
$transients = array(
	'adc_security_flush_rewrite_rules',
);
foreach ( $transients as $transient ) {
	delete_transient( $transient );
}
