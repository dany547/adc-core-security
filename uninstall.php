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
delete_option( 'adc_security_keys_backup' );
delete_option( 'adc_security_db_version' );

// Remove named transients and the events-retention cron.
$transients = array(
	'adc_security_flush_rewrite_rules',
	'adc_security_login_stats',
);
foreach ( $transients as $transient ) {
	delete_transient( $transient );
}

wp_clear_scheduled_hook( 'adc_security_prune_events' );

// Remove per-IP brute-force and per-token captcha transients (their names are
// dynamic hashes/tokens, so they cannot be targeted with delete_transient()).
global $wpdb;
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_adc\_bf\_%' OR option_name LIKE '\_transient\_timeout\_adc\_bf\_%' OR option_name LIKE '\_transient\_adc\_math\_captcha\_%' OR option_name LIKE '\_transient\_timeout\_adc\_math\_captcha\_%'"
);

// Drop the audit-log events table.
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}adc_security_events" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName, WordPress.DB.PreparedSQL.NotPrepared

// Remove per-user 2FA data.
$two_fa_meta_keys = array(
	'adc_security_totp_secret',
	'adc_security_totp_pending_secret',
	'adc_security_totp_enabled',
	'adc_security_totp_recovery_codes',
	'adc_security_2fa_required_since',
);
foreach ( $two_fa_meta_keys as $meta_key ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", $meta_key ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
}

// Remove the last-login timestamps written by the Users screen columns.
// Order IP meta (_adc_security_order_ip) is intentionally kept: it belongs to
// the order record and is useful for post-incident fraud review.
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->usermeta} WHERE meta_key = %s", '_adc_last_login' ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName

// Remove pending-login / lockout / one-time-display transients created during 2FA.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_adc\_2fa\_%' OR option_name LIKE '\_transient\_timeout\_adc\_2fa\_%'"
);

// Remove rate-limiter token-bucket transients (dynamic per-IP names).
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_adc\_rl\_%' OR option_name LIKE '\_transient\_timeout\_adc\_rl\_%'"
);

// Remove WooCommerce checkout-attempt, order-velocity and registration counters.
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_adc\_woo\_%' OR option_name LIKE '\_transient\_timeout\_adc\_woo\_%'"
);

// Remove file integrity / plugin health scan state and clear their crons.
delete_option( 'adc_security_integrity_state' );
delete_option( 'adc_security_integrity_result' );
delete_option( 'adc_security_vuln_result' );
delete_option( 'adc_security_cron_last_run' );
wp_clear_scheduled_hook( 'adc_security_integrity_scan' );
wp_clear_scheduled_hook( 'adc_security_integrity_tick' );
wp_clear_scheduled_hook( 'adc_security_vuln_scan' );

// Remove cached plugin/theme checksum lookups (dynamic per-slug+version names).
$wpdb->query(
	"DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_adc\_cksum\_%' OR option_name LIKE '\_transient\_timeout\_adc\_cksum\_%'"
);
