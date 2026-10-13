<?php
/**
 * ADC Security Firewall Registry
 *
 * Static data for the ADC Firewall Rules module: one entry per WordPress core
 * vulnerability the module can virtually patch, with the affected version
 * ranges and the fixed release on each branch. Also decides, for a given
 * WordPress version and saved option set, whether a rule is needed and in
 * which state it runs.
 *
 * Pure PHP: no WordPress calls, so it is unit tested with plain php
 * (tests/test-firewall-registry.php).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Firewall_Registry {

	const STATE_ACTIVE     = 'active';
	const STATE_MONITOR    = 'monitor';
	const STATE_DISABLED   = 'disabled';
	const STATE_NOT_NEEDED = 'not_needed';

	const CLASS_FIXED        = 'fixed';
	const CLASS_NOT_AFFECTED = 'not_affected';
	const CLASS_AFFECTED     = 'affected';
	const CLASS_UNKNOWN      = 'unknown';

	const SOURCE_NEWS     = 'https://wordpress.org/news/';
	const SOURCE_ADVISORY = 'https://github.com/advisories/GHSA-7hp8-65ch-5whp';

	/**
	 * Rule definitions keyed by rule id. The ids match the rule keys already
	 * stored in the virtual patch options, so existing settings carry over.
	 *
	 * @return array<string,array>
	 */
	public static function all() {
		return array(
			'block_rest_batch_unauth'     => array(
				'id'              => 'block_rest_batch_unauth',
				'cve'             => 'CVE-2026-63030',
				'title'           => 'Unauthenticated REST batch route',
				'summary'         => 'The REST API batch route (/batch/v1) can be abused without logging in, the first half of a pre-authentication remote code execution chain.',
				'severity'        => 'critical',
				'scope'           => 'rest',
				'requires_unauth' => true,
				'affected'        => array( '6.9.0-6.9.4', '7.0.0-7.0.1' ),
				'fixed'           => array(
					'6.9' => '6.9.5',
					'7.0' => '7.0.2',
				),
				'matcher'         => 'is_batch_route',
				'sources'         => array( self::SOURCE_NEWS, self::SOURCE_ADVISORY ),
			),
			'reject_author_query_injection' => array(
				'id'              => 'reject_author_query_injection',
				'cve'             => 'CVE-2026-60137',
				'title'           => 'author__not_in SQL injection',
				'summary'         => 'WP_Query author__in / author__not_in arguments are not sanitised, allowing SQL injection. It is reachable through REST author_exclude and batch sub-requests.',
				'severity'        => 'high',
				'scope'           => 'any',
				'requires_unauth' => false,
				'affected'        => array( '6.8.0-6.8.5', '6.9.0-6.9.4', '7.0.0-7.0.1' ),
				'fixed'           => array(
					'6.8' => '6.8.6',
					'6.9' => '6.9.5',
					'7.0' => '7.0.2',
				),
				'matcher'         => 'contains_author_injection_arg',
				'sources'         => array( self::SOURCE_NEWS, self::SOURCE_ADVISORY ),
			),
			'block_page_template_traversal' => array(
				'id'              => 'block_page_template_traversal',
				'cve'             => 'CVE-2026-87902',
				'title'           => 'Page template path traversal (LFI)',
				'summary'         => 'The pagename query variable is not validated before page-template resolution, so encoded path traversal can include local files, leading to remote code execution.',
				'severity'        => 'critical',
				'scope'           => 'frontend',
				'requires_unauth' => true,
				'affected'        => array( '4.7.0-7.1.1' ),
				'fixed'           => array(
					'7.1' => '7.1.2',
					'7.0' => '7.0.6',
					'6.9' => '6.9.9',
					'6.8' => '6.8.10',
					'6.7' => '6.7.9',
					'6.6' => '6.6.9',
					'6.5' => '6.5.12',
					'6.4' => '6.4.12',
					'6.3' => '6.3.12',
					'6.2' => '6.2.13',
					'6.1' => '6.1.14',
					'6.0' => '6.0.16',
					'5.9' => '5.9.18',
					'5.8' => '5.8.17',
					'5.7' => '5.7.19',
					'5.6' => '5.6.21',
					'5.5' => '5.5.22',
					'5.4' => '5.4.23',
					'5.3' => '5.3.25',
					'5.2' => '5.2.28',
					'5.1' => '5.1.26',
					'5.0' => '5.0.29',
					'4.9' => '4.9.33',
					'4.8' => '4.8.32',
					'4.7' => '4.7.37',
				),
				'matcher'         => 'contains_traversal',
				'sources'         => array( self::SOURCE_NEWS ),
			),
		);
	}

	/**
	 * @return string[] Rule ids in registry order.
	 */
	public static function get_rule_ids() {
		return array_keys( self::all() );
	}

	/**
	 * Decide the state of one rule for a WordPress version and saved options.
	 *
	 * Order: not_needed (version fixed or not affected) wins, then disabled
	 * (firewall off, or rule off/missing), then monitor, otherwise active.
	 *
	 * @param string $rule_id     Rule id from all().
	 * @param string $wp_version  Installed WordPress version.
	 * @param array  $opts        The adc_security_firewall option array.
	 * @return array{state:string,reason:string}
	 */
	public static function status( $rule_id, $wp_version, array $opts ) {
		$rules = self::all();

		if ( ! is_string( $rule_id ) || ! isset( $rules[ $rule_id ] ) ) {
			return array(
				'state'  => self::STATE_DISABLED,
				'reason' => 'Unknown firewall rule.',
			);
		}

		$rule    = $rules[ $rule_id ];
		$version = self::version_label( $wp_version );
		list( $class, $fixed_in ) = self::classify( $rule, $wp_version );

		if ( self::CLASS_FIXED === $class ) {
			return array(
				'state'  => self::STATE_NOT_NEEDED,
				'reason' => sprintf( 'WordPress %1$s already includes the fix for %2$s (fixed in %3$s).', $version, $rule['cve'], $fixed_in ),
			);
		}

		if ( self::CLASS_NOT_AFFECTED === $class ) {
			return array(
				'state'  => self::STATE_NOT_NEEDED,
				'reason' => sprintf( 'Not affected: WordPress %1$s is outside the affected range for %2$s (%3$s).', $version, $rule['cve'], implode( ', ', $rule['affected'] ) ),
			);
		}

		if ( self::CLASS_UNKNOWN === $class ) {
			$prefix = sprintf( 'The WordPress version could not be determined, so %s is treated as affected. ', $rule['cve'] );
		} else {
			$prefix = sprintf( 'WordPress %1$s is affected by %2$s. ', $version, $rule['cve'] );
		}

		if ( empty( $opts['enabled'] ) ) {
			return array(
				'state'  => self::STATE_DISABLED,
				'reason' => $prefix . 'The firewall is turned off.',
			);
		}

		$setting = null;

		if ( isset( $opts['rules'] ) && is_array( $opts['rules'] ) && array_key_exists( $rule_id, $opts['rules'] ) ) {
			$setting = $opts['rules'][ $rule_id ];
		}

		if ( null === $setting || 'off' === $setting ) {
			return array(
				'state'  => self::STATE_DISABLED,
				'reason' => $prefix . 'This rule is switched off.',
			);
		}

		$mode = isset( $opts['mode'] ) ? $opts['mode'] : '';

		if ( 'monitor' === $mode || 'monitor' === $setting ) {
			return array(
				'state'  => self::STATE_MONITOR,
				'reason' => $prefix . 'Monitor mode: matching requests are logged but not blocked.',
			);
		}

		return array(
			'state'  => self::STATE_ACTIVE,
			'reason' => $prefix . 'Matching requests are blocked.',
		);
	}

	/**
	 * Whether a WordPress version needs no protection from a rule.
	 *
	 * True when the version already includes the fix on its branch, or when
	 * the version is outside the affected range. Unknown or unparseable
	 * versions return false (treated as affected).
	 *
	 * @param string $rule_id    Rule id from all().
	 * @param string $wp_version Installed WordPress version.
	 * @return bool
	 */
	public static function is_fixed( $rule_id, $wp_version ) {
		$rules = self::all();

		if ( ! is_string( $rule_id ) || ! isset( $rules[ $rule_id ] ) ) {
			return false;
		}

		list( $class ) = self::classify( $rules[ $rule_id ], $wp_version );

		return self::CLASS_FIXED === $class || self::CLASS_NOT_AFFECTED === $class;
	}

	// -------------------------------------------------------------------------
	// Version helpers
	// -------------------------------------------------------------------------

	/**
	 * Classify a version against a rule.
	 *
	 * @param array  $rule       Rule definition.
	 * @param string $wp_version Installed WordPress version.
	 * @return array{0:string,1:string|null} Class constant and the fixed version when fixed.
	 */
	private static function classify( array $rule, $wp_version ) {
		$version = self::parse_version( $wp_version );

		if ( null === $version ) {
			return array( self::CLASS_UNKNOWN, null );
		}

		$ranges = array();

		foreach ( $rule['affected'] as $range ) {
			$bounds = explode( '-', $range, 2 );

			if ( 2 !== count( $bounds ) ) {
				continue;
			}

			$min = self::parse_version( $bounds[0] );
			$max = self::parse_version( $bounds[1] );

			if ( null !== $min && null !== $max ) {
				$ranges[] = array( $min, $max );
			}
		}

		if ( empty( $ranges ) ) {
			return array( self::CLASS_NOT_AFFECTED, null );
		}

		$oldest = $ranges[0][0];
		$newest = $ranges[0][1];

		foreach ( $ranges as $range ) {
			if ( self::compare( $range[0], $oldest ) < 0 ) {
				$oldest = $range[0];
			}

			if ( self::compare( $range[1], $newest ) > 0 ) {
				$newest = $range[1];
			}
		}

		$branch = $version[0] . '.' . $version[1];

		if ( isset( $rule['fixed'][ $branch ] ) ) {
			$fixed_in = $rule['fixed'][ $branch ];
			$fixed    = self::parse_version( $fixed_in );

			if ( null !== $fixed && self::compare( $version, $fixed ) >= 0 ) {
				return array( self::CLASS_FIXED, $fixed_in );
			}
		}

		if ( self::compare( $version, $oldest ) < 0 ) {
			return array( self::CLASS_NOT_AFFECTED, null );
		}

		if ( ! isset( $rule['fixed'][ $branch ] ) && self::compare( $version, $newest ) > 0 ) {
			return array( self::CLASS_NOT_AFFECTED, null );
		}

		return array( self::CLASS_AFFECTED, null );
	}

	/**
	 * Parse a version string into four integer parts.
	 *
	 * Pre-release and build suffixes are dropped ("7.2-beta1" becomes 7.2.0.0),
	 * and up to four numeric parts are kept.
	 *
	 * @param mixed $version Version string.
	 * @return int[]|null Four parts, or null when the value has no leading number.
	 */
	private static function parse_version( $version ) {
		if ( ! is_string( $version ) && ! is_int( $version ) && ! is_float( $version ) ) {
			return null;
		}

		$version = trim( (string) $version );

		if ( ! preg_match( '/^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?/', $version, $matches ) ) {
			return null;
		}

		$parts = array();

		for ( $i = 1; $i <= 4; $i++ ) {
			$parts[] = isset( $matches[ $i ] ) && '' !== $matches[ $i ] ? (int) $matches[ $i ] : 0;
		}

		return $parts;
	}

	/**
	 * @param int[] $a Parsed version.
	 * @param int[] $b Parsed version.
	 * @return int -1, 0 or 1.
	 */
	private static function compare( array $a, array $b ) {
		for ( $i = 0; $i < 4; $i++ ) {
			if ( $a[ $i ] !== $b[ $i ] ) {
				return $a[ $i ] < $b[ $i ] ? -1 : 1;
			}
		}

		return 0;
	}

	/**
	 * @param mixed $wp_version Version as given.
	 * @return string Version for display, or "unknown" when empty.
	 */
	private static function version_label( $wp_version ) {
		$label = is_scalar( $wp_version ) ? trim( (string) $wp_version ) : '';

		return '' === $label ? 'unknown' : $label;
	}
}
