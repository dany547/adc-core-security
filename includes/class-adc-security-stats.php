<?php
/**
 * ADC Security Stats Class
 *
 * Aggregate read queries over the events table, cached in a transient so
 * the dashboard doesn't re-scan the table on every admin page load.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Stats {

	const CACHE_KEY     = 'adc_security_login_stats';
	const WOO_CACHE_KEY      = 'adc_security_woo_stats';
	const FIREWALL_CACHE_KEY = 'adc_security_firewall_stats_';
	const CACHE_TTL          = 5 * MINUTE_IN_SECONDS;

	/**
	 * Login/lockout statistics for the dashboard's Login & Lockout card.
	 *
	 * @param bool $force_refresh Bypass the cached copy.
	 * @return array{
	 *     attempts_24h:int,attempts_7d:int,attempts_30d:int,
	 *     top_ips:array,top_usernames:array,sparkline:array
	 * }
	 */
	public static function get_login_stats( $force_refresh = false ) {
		if ( ! $force_refresh ) {
			$cached = get_transient( self::CACHE_KEY );
			if ( false !== $cached ) {
				return $cached;
			}
		}

		$table = ADC_Security_Install::events_table();

		$stats = array(
			'attempts_24h'  => self::count_since( $table, 'login_failed', 1 ),
			'attempts_7d'   => self::count_since( $table, 'login_failed', 7 ),
			'attempts_30d'  => self::count_since( $table, 'login_failed', 30 ),
			'top_ips'       => self::top_column( $table, 'login_failed', 'ip', 5 ),
			'top_usernames' => self::top_column( $table, 'login_failed', 'username', 5 ),
			'sparkline'     => self::daily_counts( $table, 'login_failed', 30 ),
		);

		set_transient( self::CACHE_KEY, $stats, self::CACHE_TTL );

		return $stats;
	}

	/**
	 * WooCommerce abuse-prevention counts for the dashboard card.
	 *
	 * @param bool $force_refresh Bypass the cached copy.
	 * @return array{blocked_7d:int,flagged_7d:int,blocked_30d:int,flagged_30d:int}
	 */
	public static function get_woo_stats( $force_refresh = false ) {
		if ( ! $force_refresh ) {
			$cached = get_transient( self::WOO_CACHE_KEY );
			if ( false !== $cached ) {
				return $cached;
			}
		}

		$table = ADC_Security_Install::events_table();

		$blocked = array( 'woo_checkout_blocked', 'woo_registration_blocked', 'woo_lost_password_blocked' );
		$flagged = array( 'woo_checkout_flagged', 'woo_registration_flagged', 'woo_lost_password_flagged' );

		$stats = array(
			'blocked_7d'  => array_sum( self::count_types_since( $blocked, time() - ( 7 * DAY_IN_SECONDS ) ) ),
			'flagged_7d'  => array_sum( self::count_types_since( $flagged, time() - ( 7 * DAY_IN_SECONDS ) ) ),
			'blocked_30d' => array_sum( self::count_types_since( $blocked, time() - ( 30 * DAY_IN_SECONDS ) ) ),
			'flagged_30d' => array_sum( self::count_types_since( $flagged, time() - ( 30 * DAY_IN_SECONDS ) ) ),
		);

		set_transient( self::WOO_CACHE_KEY, $stats, self::CACHE_TTL );

		return $stats;
	}

	/**
	 * Firewall and protection counts for the Firewall tab's "Last N days" panel.
	 *
	 * @param int $days Window length in days.
	 * @return array{rule_blocks:int,rate_limited:int,lockout:int,ip_denied:int}
	 */
	public static function get_firewall_stats( $days = 7 ) {
		$days = max( 1, (int) $days );
		$key  = self::FIREWALL_CACHE_KEY . $days;

		$cached = get_transient( $key );
		if ( false !== $cached ) {
			return $cached;
		}

		$since  = time() - ( $days * DAY_IN_SECONDS );
		$counts = self::count_types_since( array( 'rate_limited', 'lockout', 'ip_denied' ), $since );

		$stats = array(
			'rule_blocks'  => self::count_events( ADC_Security_Firewall_Rules::EVENT_TYPE, $since, ADC_Security_Events::SEVERITY_CRITICAL ),
			'rate_limited' => $counts['rate_limited'],
			'lockout'      => $counts['lockout'],
			'ip_denied'    => $counts['ip_denied'],
		);

		set_transient( $key, $stats, self::CACHE_TTL );

		return $stats;
	}

	/**
	 * Count rows of $event_type in the last $days days.
	 */
	private static function count_since( $table, $event_type, $days ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE event_type = %s AND event_time >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				$event_type,
				$since
			)
		);
	}

	/**
	 * Most frequent non-empty values of $column for $event_type, last 30 days.
	 */
	private static function top_column( $table, $event_type, $column, $limit ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', time() - ( 30 * DAY_IN_SECONDS ) );

		if ( ! in_array( $column, array( 'ip', 'username' ), true ) ) {
			return array();
		}

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$column} AS value, COUNT(*) AS total FROM {$table} " // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				. "WHERE event_type = %s AND event_time >= %s AND {$column} != '' " // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				. "GROUP BY {$column} ORDER BY total DESC LIMIT %d", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				$event_type,
				$since,
				$limit
			),
			ARRAY_A
		);

		return $rows ? $rows : array();
	}

	/**
	 * Per-day counts of $event_type for the last $days days, oldest first.
	 * Always returns exactly $days entries (0-filled for days with no events).
	 */
	private static function daily_counts( $table, $event_type, $days ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d 00:00:00', time() - ( ( $days - 1 ) * DAY_IN_SECONDS ) );

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(event_time) AS day, COUNT(*) AS total FROM {$table} " // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				. 'WHERE event_type = %s AND event_time >= %s GROUP BY DATE(event_time)',
				$event_type,
				$since
			),
			ARRAY_A
		);

		$by_day = array();
		foreach ( (array) $rows as $row ) {
			$by_day[ $row['day'] ] = (int) $row['total'];
		}

		$series = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$day            = gmdate( 'Y-m-d', time() - ( $i * DAY_IN_SECONDS ) );
			$series[ $day ] = isset( $by_day[ $day ] ) ? $by_day[ $day ] : 0;
		}

		return $series;
	}

	/**
	 * Invalidate the cached stats, e.g. after a manual events purge.
	 */
	public static function flush_cache() {
		delete_transient( self::CACHE_KEY );
		delete_transient( self::WOO_CACHE_KEY );
		delete_transient( self::FIREWALL_CACHE_KEY . 7 );
	}

	/**
	 * Count events per type since a Unix timestamp. Every requested type is
	 * present in the result, with 0 when it has no rows.
	 *
	 * @param array $types Event type slugs.
	 * @param int   $since Unix timestamp; rows at or after it are counted.
	 * @return array<string,int> event_type => count.
	 */
	public static function count_types_since( array $types, $since ) {
		$types  = array_values( array_unique( array_filter( array_map( 'strval', $types ) ) ) );
		$counts = array_fill_keys( $types, 0 );
		if ( empty( $types ) ) {
			return $counts;
		}

		global $wpdb;

		$table        = ADC_Security_Install::events_table();
		$placeholders = implode( ',', array_fill( 0, count( $types ), '%s' ) );
		$params       = array_merge( $types, array( gmdate( 'Y-m-d H:i:s', (int) $since ) ) );

		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT event_type, COUNT(*) AS total FROM {$table} WHERE event_type IN ($placeholders) AND event_time >= %s GROUP BY event_type", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
				...$params
			),
			ARRAY_A
		);

		foreach ( (array) $rows as $row ) {
			if ( isset( $counts[ $row['event_type'] ] ) ) {
				$counts[ $row['event_type'] ] = (int) $row['total'];
			}
		}

		return $counts;
	}

	/**
	 * Count rows of one event type with an exact severity since a Unix timestamp.
	 *
	 * @param string $event_type Event type slug.
	 * @param int    $since      Unix timestamp.
	 * @param int    $severity   Exact severity to count.
	 * @return int
	 */
	private static function count_events( $event_type, $since, $severity ) {
		global $wpdb;

		$table = ADC_Security_Install::events_table();

		return (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$table} WHERE event_type = %s AND severity = %d AND event_time >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
				$event_type,
				(int) $severity,
				gmdate( 'Y-m-d H:i:s', (int) $since )
			)
		);
	}
}
