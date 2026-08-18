<?php
/**
 * ADC Security Score Class
 *
 * Pure scoring engine: given the plugin's current option/status values it
 * returns a 0-100 score, a letter grade, and the list of individual checks
 * that were evaluated. Has no WordPress option reads of its own so it can
 * be unit tested with plain arrays (see tests/test-security-score.php).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Score {

	/**
	 * Compute the security score from plugin state.
	 *
	 * @param array $options        The saved `adc_security_options` array.
	 * @param array $htaccess_status Result of ADC_Security_Htaccess::get_status().
	 * @param array $keys_status     Result of ADC_Security_Keys::get_status().
	 * @param array $extra           Optional overrides for facts this class cannot
	 *                                derive on its own, e.g.:
	 *                                - 'https'                bool
	 *                                - 'default_admin_user'   bool
	 *                                - 'disallow_file_edit'   bool
	 *                                - 'admins_without_2fa'   int, number of administrators without 2FA enabled
	 *                                - 'integrity_issues'     int, count of file integrity findings (null/absent = not yet scanned, doesn't count against the score)
	 *                                - 'vulnerability_issues' int, count of flagged plugins (null/absent = not yet scanned)
	 *
	 * @return array{score:int,grade:string,checks:array}
	 */
	public static function calculate( array $options, array $htaccess_status = array(), array $keys_status = array(), array $extra = array() ) {
		$header_toggles = isset( $options['security_header_toggles'] ) && is_array( $options['security_header_toggles'] )
			? $options['security_header_toggles']
			: array();

		$https              = array_key_exists( 'https', $extra ) ? (bool) $extra['https'] : is_ssl();
		$default_admin_user = array_key_exists( 'default_admin_user', $extra ) ? (bool) $extra['default_admin_user'] : false;
		$disallow_file_edit = array_key_exists( 'disallow_file_edit', $extra ) ? (bool) $extra['disallow_file_edit'] : ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		$admins_without_2fa = array_key_exists( 'admins_without_2fa', $extra ) ? (int) $extra['admins_without_2fa'] : 0;
		$integrity_issues   = array_key_exists( 'integrity_issues', $extra ) ? $extra['integrity_issues'] : null;
		$vulnerability_issues = array_key_exists( 'vulnerability_issues', $extra ) ? $extra['vulnerability_issues'] : null;

		$checks = array(
			array(
				'id'     => 'custom_login_slug',
				'label'  => 'Custom login URL',
				'passed' => ! empty( $options['custom_login_slug'] ),
				'weight' => 8,
				'tab'    => 'login',
			),
			array(
				'id'     => 'brute_force_protection',
				'label'  => 'Brute-force protection enabled',
				'passed' => ! empty( $options['brute_force_protection'] ),
				'weight' => 10,
				'tab'    => 'login',
			),
			array(
				'id'     => 'disable_xmlrpc',
				'label'  => 'XML-RPC disabled',
				'passed' => ! empty( $options['disable_xmlrpc'] ),
				'weight' => 8,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'disable_file_editor',
				'label'  => 'File editor disabled',
				'passed' => ! empty( $options['disable_file_editor'] ) || $disallow_file_edit,
				'weight' => 8,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'prevent_user_enumeration',
				'label'  => 'User enumeration blocked',
				'passed' => ! empty( $options['prevent_user_enumeration'] ),
				'weight' => 6,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'security_headers',
				'label'  => 'Security headers enabled',
				'passed' => ! empty( $options['security_headers'] ) && ! empty( $header_toggles ),
				'weight' => 10,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'hsts',
				'label'  => 'HTTP Strict Transport Security (HSTS)',
				'passed' => ! empty( $options['security_headers'] ) && in_array( 'hsts', $header_toggles, true ),
				'weight' => 6,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'captcha',
				'label'  => 'Login captcha enabled',
				'passed' => ! empty( $options['captcha_type'] ) && 'none' !== $options['captcha_type'],
				'weight' => 8,
				'tab'    => 'captcha',
			),
			array(
				'id'     => 'htaccess_rules',
				'label'  => 'Server hardening rules applied',
				'passed' => ! empty( $htaccess_status['managed'] ),
				'weight' => 8,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'keys_rotated',
				'label'  => 'Security keys rotated at least once',
				'passed' => ! empty( $keys_status['has_backup'] ),
				'weight' => 5,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'https',
				'label'  => 'HTTPS active',
				'passed' => $https,
				'weight' => 8,
				'tab'    => '',
			),
			array(
				'id'     => 'no_default_admin',
				'label'  => 'No administrator uses the "admin" username',
				'passed' => ! $default_admin_user,
				'weight' => 8,
				'tab'    => '',
			),
			array(
				'id'     => 'disable_pingbacks',
				'label'  => 'XML-RPC pingbacks disabled',
				'passed' => ! empty( $options['disable_pingbacks'] ),
				'weight' => 4,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'admin_session_expiration',
				'label'  => 'Admin session expiration enforced',
				'passed' => ! empty( $options['admin_session_expiration_enabled'] ),
				'weight' => 4,
				'tab'    => 'hardening',
			),
			array(
				'id'     => 'admins_2fa',
				'label'  => 'All administrators have 2FA enabled',
				'passed' => 0 === $admins_without_2fa,
				'weight' => 10,
				'tab'    => '2fa',
			),
		);

		if ( null !== $integrity_issues ) {
			$checks[] = array(
				'id'     => 'integrity_clean',
				'label'  => 'File integrity scan clean',
				'passed' => 0 === (int) $integrity_issues,
				'weight' => 8,
				'tab'    => 'support',
			);
		}

		if ( null !== $vulnerability_issues ) {
			$checks[] = array(
				'id'     => 'no_abandoned_plugins',
				'label'  => 'No abandoned/unmaintained plugins detected',
				'passed' => 0 === (int) $vulnerability_issues,
				'weight' => 6,
				'tab'    => 'support',
			);
		}

		$earned = 0;
		$total  = 0;
		foreach ( $checks as $check ) {
			$total += $check['weight'];
			if ( $check['passed'] ) {
				$earned += $check['weight'];
			}
		}

		$score = $total > 0 ? (int) round( 100 * $earned / $total ) : 0;

		return array(
			'score'  => $score,
			'grade'  => self::grade_for_score( $score ),
			'checks' => $checks,
		);
	}

	/**
	 * Map a 0-100 score to a letter grade.
	 *
	 * @param int $score Score between 0 and 100.
	 * @return string
	 */
	public static function grade_for_score( $score ) {
		if ( $score >= 90 ) {
			return 'A';
		}
		if ( $score >= 75 ) {
			return 'B';
		}
		if ( $score >= 60 ) {
			return 'C';
		}
		if ( $score >= 40 ) {
			return 'D';
		}
		return 'F';
	}
}
