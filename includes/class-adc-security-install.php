<?php
/**
 * ADC Security Install Class
 *
 * Creates/upgrades the plugin's custom database table(s). Called from
 * ADC_Security_Core::check_version() so it runs both on fresh installs and
 * on upgrades of sites that already had the plugin active (the plugin has
 * no register_activation_hook()).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Install {

	/**
	 * Option storing the currently installed schema version.
	 */
	const DB_VERSION_OPTION = 'adc_security_db_version';

	/**
	 * Bump this whenever the schema below changes.
	 */
	const DB_VERSION = '1.0';

	/**
	 * Create or upgrade the events table if needed.
	 */
	public static function maybe_install() {
		if ( get_option( self::DB_VERSION_OPTION ) === self::DB_VERSION ) {
			return;
		}

		self::create_events_table();

		update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
	}

	/**
	 * Full table name for the events log.
	 *
	 * @return string
	 */
	public static function events_table() {
		global $wpdb;
		return $wpdb->prefix . 'adc_security_events';
	}

	/**
	 * Create the events table via dbDelta (safe to call repeatedly).
	 */
	private static function create_events_table() {
		global $wpdb;

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$table_name      = self::events_table();
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table_name} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			event_time DATETIME NOT NULL,
			event_type VARCHAR(32) NOT NULL,
			severity TINYINT NOT NULL DEFAULT 0,
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			username VARCHAR(60) NOT NULL DEFAULT '',
			ip VARCHAR(45) NOT NULL DEFAULT '',
			object VARCHAR(191) NOT NULL DEFAULT '',
			context LONGTEXT NULL,
			PRIMARY KEY  (id),
			KEY event_time (event_time),
			KEY event_type (event_type),
			KEY user_id (user_id),
			KEY ip (ip)
		) {$charset_collate};";

		dbDelta( $sql );
	}
}
