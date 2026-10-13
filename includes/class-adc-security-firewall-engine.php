<?php
/**
 * ADC Security Firewall Engine
 *
 * Decides what to do with a request that a firewall matcher flagged: allow,
 * log only (monitor) or block. Also holds the safe-mode threshold check and
 * the fingerprint used to group repeated hits in the Activity log.
 *
 * Pure PHP: no WordPress calls, so it is unit tested with plain php
 * (tests/test-firewall-engine.php).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Firewall_Engine {

	const ACTION_ALLOW   = 'allow';
	const ACTION_MONITOR = 'monitor';
	const ACTION_BLOCK   = 'block';

	/**
	 * Bytes of a matched value that feed the fingerprint.
	 */
	const FINGERPRINT_BYTES = 512;

	/**
	 * Decide the action for a flagged request.
	 *
	 * Expected $req keys: rule_id, wp_version, logged_in, can_edit, is_cli,
	 * is_cron, ip_allowlisted, kill_switch, matched. Missing keys default to
	 * the least restrictive value. Any error fails open (allow).
	 *
	 * @param array $req  Request facts.
	 * @param array $opts The adc_security_firewall option array.
	 * @return array{action:string,reason:string}
	 */
	public static function decide( array $req, array $opts ) {
		try {
			return self::evaluate( $req, $opts );
		} catch ( Throwable $e ) {
			return self::result( self::ACTION_ALLOW, 'Firewall error: request allowed (fail-open).' );
		}
	}

	/**
	 * Whether repeated blocks in a short window should switch the site to safe mode.
	 *
	 * @param array $block_timestamps Unix timestamps of recent blocks.
	 * @param int   $now              Current Unix timestamp.
	 * @param int   $limit            Blocks needed to trigger safe mode.
	 * @param int   $window           Window length in seconds.
	 * @return bool
	 */
	public static function should_enter_safe_mode( array $block_timestamps, $now, $limit = 5, $window = 60 ) {
		$recent = 0;

		foreach ( $block_timestamps as $timestamp ) {
			if ( ! is_int( $timestamp ) ) {
				continue;
			}

			if ( $timestamp >= $now - $window && $timestamp <= $now ) {
				++$recent;
			}
		}

		return $recent >= $limit;
	}

	/**
	 * Short, stable identifier for a matched value, safe to store and group on.
	 *
	 * @param string $rule_id Rule id.
	 * @param string $value   Matched value; only its first 512 bytes are used.
	 * @return string 16 lowercase hex characters.
	 */
	public static function fingerprint( $rule_id, $value ) {
		$value = substr( (string) $value, 0, self::FINGERPRINT_BYTES );

		return substr( hash( 'sha256', (string) $rule_id . "\0" . $value ), 0, 16 );
	}

	// -------------------------------------------------------------------------
	// Internals
	// -------------------------------------------------------------------------

	/**
	 * @param array $req  Request facts.
	 * @param array $opts Firewall options.
	 * @return array{action:string,reason:string}
	 */
	private static function evaluate( array $req, array $opts ) {
		if ( ! empty( $req['kill_switch'] ) ) {
			return self::result( self::ACTION_ALLOW, 'The kill switch is active.' );
		}

		if ( ! empty( $req['is_cli'] ) ) {
			return self::result( self::ACTION_ALLOW, 'WP-CLI request.' );
		}

		if ( ! empty( $req['is_cron'] ) ) {
			return self::result( self::ACTION_ALLOW, 'Cron request.' );
		}

		if ( ! empty( $req['ip_allowlisted'] ) ) {
			return self::result( self::ACTION_ALLOW, 'The client IP is on the allowlist.' );
		}

		if ( empty( $req['matched'] ) ) {
			return self::result( self::ACTION_ALLOW, 'No firewall rule matched.' );
		}

		$rule_id    = (string) ( isset( $req['rule_id'] ) ? $req['rule_id'] : '' );
		$wp_version = (string) ( isset( $req['wp_version'] ) ? $req['wp_version'] : '' );
		$logged_in  = ! empty( $req['logged_in'] );
		$can_edit   = ! empty( $req['can_edit'] );

		$status = ADC_Security_Firewall_Registry::status( $rule_id, $wp_version, $opts );

		if ( in_array( $status['state'], array( ADC_Security_Firewall_Registry::STATE_NOT_NEEDED, ADC_Security_Firewall_Registry::STATE_DISABLED ), true ) ) {
			return self::result( self::ACTION_ALLOW, $status['reason'] );
		}

		$rules = ADC_Security_Firewall_Registry::all();
		$rule  = $rules[ $rule_id ];

		if ( ! empty( $rule['requires_unauth'] ) && $logged_in ) {
			return self::result( self::ACTION_ALLOW, 'This rule only applies to anonymous requests.' );
		}

		if ( $logged_in && $can_edit ) {
			return self::result( self::ACTION_MONITOR, 'Editors are never blocked; the match is logged only.' );
		}

		if ( ADC_Security_Firewall_Registry::STATE_MONITOR === $status['state'] ) {
			return self::result( self::ACTION_MONITOR, $status['reason'] );
		}

		return self::result( self::ACTION_BLOCK, $status['reason'] );
	}

	/**
	 * @param string $action Action constant.
	 * @param string $reason Human-readable reason.
	 * @return array{action:string,reason:string}
	 */
	private static function result( $action, $reason ) {
		return array(
			'action' => $action,
			'reason' => $reason,
		);
	}
}
