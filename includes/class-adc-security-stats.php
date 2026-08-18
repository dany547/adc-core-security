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

	const CACHE_KEY = 'adc_security_login_stats';
	const CACHE_TTL = 5 * MINUTE_IN_SECONDS;

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
	}
}
