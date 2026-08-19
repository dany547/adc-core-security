<?php
/**
 * ADC Security Events Class
 *
 * Records security-relevant events into the {$wpdb->prefix}adc_security_events
 * table and prunes old rows on a daily cron. This is the write side of the
 * audit log; ADC_Security_Stats reads it back for the dashboard, and
 * ADC_Security_Events_Table renders it for the Activity tab.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Events {

	const SEVERITY_INFO     = 0;
	const SEVERITY_NOTICE   = 1;
	const SEVERITY_WARNING  = 2;
	const SEVERITY_CRITICAL = 3;

	/**
	 * Cron hook used to prune old events.
	 */
	const CRON_HOOK = 'adc_security_prune_events';

	/**
	 * Default retention window, in days.
	 */
	const DEFAULT_RETENTION_DAYS = 90;

	/**
	 * Row cap enforced alongside the age-based retention.
	 */
	const MAX_ROWS = 20000;

	public function __construct() {
		add_action( 'wp_login_failed', array( $this, 'on_login_failed' ), 20, 1 );
		add_action( 'wp_login', array( $this, 'on_login_success' ), 20, 2 );
		add_action( 'adc_security_lockout', array( $this, 'on_lockout' ), 10, 3 );
		add_action( 'adc_security_ip_denied', array( $this, 'on_ip_denied' ), 10, 1 );

		add_action( 'user_register', array( $this, 'on_user_created' ), 10, 1 );
		add_action( 'delete_user', array( $this, 'on_user_deleted' ), 10, 1 );
		add_action( 'set_user_role', array( $this, 'on_role_changed' ), 10, 3 );

		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 1 );
		add_action( 'deactivated_plugin', array( $this, 'on_plugin_deactivated' ), 10, 1 );
		add_action( 'switch_theme', array( $this, 'on_theme_switched' ), 10, 1 );
		add_action( 'update_option_' . ADC_Security_Settings::OPTION_NAME, array( $this, 'on_settings_changed' ), 10, 2 );
		add_action( '_core_updated_successfully', array( $this, 'on_core_updated' ), 10, 1 );

		add_action( self::CRON_HOOK, array( $this, 'prune' ) );
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time(), 'daily', self::CRON_HOOK );
		}
	}

	// -------------------------------------------------------------------------
	// Hook callbacks
	// -------------------------------------------------------------------------

	public function on_login_failed( $username ) {
		self::log(
			'login_failed',
			self::SEVERITY_NOTICE,
			array(
				'username' => $username,
				'ip'       => $this->get_client_ip(),
			)
		);
	}

	public function on_login_success( $user_login, $user = null ) {
		self::log(
			'login_success',
			self::SEVERITY_INFO,
			array(
				'username' => $user_login,
				'user_id'  => $user instanceof WP_User ? $user->ID : 0,
				'ip'       => $this->get_client_ip(),
			)
		);
	}

	public function on_lockout( $ip, $username, $expiration ) {
		self::log(
			'lockout',
			self::SEVERITY_WARNING,
			array(
				'username' => $username,
				'ip'       => $ip,
				'context'  => array( 'expiration' => (int) $expiration ),
			)
		);
	}

	public function on_ip_denied( $ip ) {
		self::log(
			'ip_denied',
			self::SEVERITY_WARNING,
			array( 'ip' => $ip )
		);
	}

	public function on_user_created( $user_id ) {
		$user = get_userdata( $user_id );
		self::log(
			'user_created',
			self::SEVERITY_NOTICE,
			array(
				'user_id'  => $user_id,
				'username' => $user ? $user->user_login : '',
			)
		);
	}

	public function on_user_deleted( $user_id ) {
		$user = get_userdata( $user_id );
		self::log(
			'user_deleted',
			self::SEVERITY_NOTICE,
			array(
				'user_id'  => $user_id,
				'username' => $user ? $user->user_login : '',
			)
		);
	}

	public function on_role_changed( $user_id, $role, $old_roles ) {
		self::log(
			'role_changed',
			self::SEVERITY_NOTICE,
			array(
				'user_id' => $user_id,
				'context' => array(
					'new_role'  => $role,
					'old_roles' => $old_roles,
				),
			)
		);
	}

	public function on_plugin_activated( $plugin ) {
		self::log( 'plugin_activated', self::SEVERITY_NOTICE, array( 'object' => $plugin ) );
	}

	public function on_plugin_deactivated( $plugin ) {
		self::log( 'plugin_deactivated', self::SEVERITY_NOTICE, array( 'object' => $plugin ) );
	}

	public function on_theme_switched( $new_name ) {
		self::log( 'theme_switched', self::SEVERITY_NOTICE, array( 'object' => $new_name ) );
	}

	public function on_settings_changed( $old_value, $new_value ) {
		self::log( 'settings_changed', self::SEVERITY_INFO, array() );
	}

	public function on_core_updated( $wp_version ) {
		self::log( 'core_updated', self::SEVERITY_NOTICE, array( 'object' => $wp_version ) );
	}

	// -------------------------------------------------------------------------
	// Writing / pruning
	// -------------------------------------------------------------------------

	/**
	 * Insert one event row.
	 *
	 * @param string $type    Event type slug, e.g. 'login_failed'.
	 * @param int    $severity One of the SEVERITY_* constants.
	 * @param array  $args    Optional: user_id, username, ip, object, context (array, JSON-encoded).
	 */
	public static function log( $type, $severity, array $args = array() ) {
		global $wpdb;

		$context = isset( $args['context'] ) && is_array( $args['context'] ) ? wp_json_encode( $args['context'] ) : null;

		$wpdb->insert(
			ADC_Security_Install::events_table(),
			array(
				'event_time' => current_time( 'mysql' ),
				'event_type' => sanitize_key( $type ),
				'severity'   => (int) $severity,
				'user_id'    => isset( $args['user_id'] ) ? (int) $args['user_id'] : 0,
				'username'   => isset( $args['username'] ) ? mb_substr( sanitize_text_field( (string) $args['username'] ), 0, 60 ) : '',
				'ip'         => isset( $args['ip'] ) ? mb_substr( sanitize_text_field( (string) $args['ip'] ), 0, 45 ) : '',
				'object'     => isset( $args['object'] ) ? mb_substr( sanitize_text_field( (string) $args['object'] ), 0, 191 ) : '',
				'context'    => $context,
			),
			array( '%s', '%s', '%d', '%d', '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Delete events older than the retention window and enforce the row cap.
	 * Also clears expired entries from the adc_locked_ips display list.
	 */
	public function prune() {
		if ( class_exists( 'ADC_Security_Cron_Health' ) ) {
			ADC_Security_Cron_Health::record( self::CRON_HOOK );
		}

		global $wpdb;

		$table          = ADC_Security_Install::events_table();
		$retention_days = (int) apply_filters( 'adc_security_events_retention_days', self::DEFAULT_RETENTION_DAYS );
		$cutoff         = gmdate( 'Y-m-d H:i:s', time() - ( max( 1, $retention_days ) * DAY_IN_SECONDS ) );

		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE event_time < %s", $cutoff ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName

		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
		if ( $total > self::MAX_ROWS ) {
			$overflow = $total - self::MAX_ROWS;
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} ORDER BY id ASC LIMIT %d", $overflow ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
		}

		$locked_ips = get_option( 'adc_locked_ips', array() );
		$filtered   = array_filter(
			$locked_ips,
			static function ( $expiry ) {
				return $expiry > time();
			}
		);
		if ( count( $filtered ) !== count( $locked_ips ) ) {
			update_option( 'adc_locked_ips', $filtered );
		}
	}

	/**
	 * Best-effort client IP lookup for hooks that don't receive it directly.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		return ADC_Security_Ip::get_client_ip();
	}
}
