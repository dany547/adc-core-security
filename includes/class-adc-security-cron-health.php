<?php
/**
 * ADC Security Cron Health Class
 *
 * WP-Cron only fires on a visited request, and is notoriously unreliable on
 * low-traffic or misconfigured (DISABLE_WP_CRON, server-side cron pointed
 * at the wrong URL, etc.) sites. Every background feature this plugin added
 * — audit-log retention, file integrity scanning, plugin health scanning —
 * depends on it. This class gives the dashboard a way to say "these scans
 * look stuck", rather than silently never running.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Cron_Health {

	const OPTION = 'adc_security_cron_last_run';

	/**
	 * Hooks to monitor, mapped to their expected interval in seconds. Used
	 * to decide when a hook is "overdue" (its next run, per wp_next_scheduled,
	 * has already passed by more than one full interval).
	 *
	 * @var array
	 */
	const MONITORED = array(
		'adc_security_prune_events'   => DAY_IN_SECONDS,
		'adc_security_integrity_scan' => WEEK_IN_SECONDS,
		'adc_security_vuln_scan'      => DAY_IN_SECONDS,
	);

	/**
	 * Record that $hook actually fired, right now. Call this at the top of
	 * the hook's own callback, not from here.
	 *
	 * @param string $hook One of the MONITORED keys.
	 */
	public static function record( $hook ) {
		$log          = get_option( self::OPTION, array() );
		$log[ $hook ] = time();
		update_option( self::OPTION, $log, false );
	}

	/**
	 * @return array Map of hook => {next_scheduled, last_run, overdue}.
	 */
	public static function get_status() {
		$log    = get_option( self::OPTION, array() );
		$status = array();

		foreach ( self::MONITORED as $hook => $interval ) {
			$next_scheduled = wp_next_scheduled( $hook );
			$last_run       = isset( $log[ $hook ] ) ? (int) $log[ $hook ] : 0;

			$overdue = false;
			if ( false === $next_scheduled ) {
				$overdue = true; // Not scheduled at all.
			} elseif ( $next_scheduled < time() - $interval ) {
				$overdue = true; // Missed at least one full cycle.
			}

			$status[ $hook ] = array(
				'next_scheduled' => $next_scheduled,
				'last_run'       => $last_run,
				'overdue'        => $overdue,
			);
		}

		return $status;
	}

	/**
	 * @return bool Whether any monitored cron hook looks stuck.
	 */
	public static function any_overdue() {
		foreach ( self::get_status() as $hook_status ) {
			if ( $hook_status['overdue'] ) {
				return true;
			}
		}
		return false;
	}
}
