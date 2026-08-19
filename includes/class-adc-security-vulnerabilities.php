<?php
/**
 * ADC Security Vulnerabilities Class
 *
 * Zero-configuration plugin/theme health scan: flags installed plugins that
 * have been closed/removed from the WordPress.org directory, or that
 * haven't shipped an update in over two years — both strong signals of
 * unmaintained code that's more likely to carry an unpatched vulnerability.
 * No API key and no external service required.
 *
 * The 'adc_security_vulnerability_findings' filter is provided as an
 * extension point for a paid CVE feed (WPScan, Patchstack, ...) to plug
 * additional findings into the same result set; no such provider ships here.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Vulnerabilities {

	const CRON_HOOK      = 'adc_security_vuln_scan';
	const RESULT_OPTION  = 'adc_security_vuln_result';
	const ABANDONED_YEARS = 2;

	public function __construct() {
		add_action( self::CRON_HOOK, array( $this, 'run_scan' ) );

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	/**
	 * Run the scan and store results. Safe to call directly (e.g. "Scan Now").
	 */
	public function run_scan() {
		if ( class_exists( 'ADC_Security_Cron_Health' ) ) {
			ADC_Security_Cron_Health::record( self::CRON_HOOK );
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( ! function_exists( 'plugins_api' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		}

		$findings      = array();
		$active_plugins = get_option( 'active_plugins', array() );
		$all_plugins    = get_plugins();

		foreach ( $active_plugins as $plugin_file ) {
			if ( ! isset( $all_plugins[ $plugin_file ] ) ) {
				continue;
			}

			$finding = $this->check_plugin( $plugin_file, $all_plugins[ $plugin_file ] );
			if ( $finding ) {
				$findings[] = $finding;
			}
		}

		/**
		 * Let an optional external provider add its own findings, e.g.
		 * matched CVEs from a paid feed. Each entry should look like the
		 * ones this class produces: array( 'plugin', 'issue', 'detail' ).
		 *
		 * @param array $findings       Findings so far.
		 * @param array $active_plugins Active plugin files.
		 */
		$findings = apply_filters( 'adc_security_vulnerability_findings', $findings, $active_plugins );

		update_option(
			self::RESULT_OPTION,
			array(
				'scanned_at' => time(),
				'findings'   => $findings,
			),
			false
		);
	}

	/**
	 * @param string $plugin_file Relative plugin file, e.g. "foo/foo.php".
	 * @param array  $plugin_data Plugin header data from get_plugins().
	 * @return array|null Finding, or null if nothing to report.
	 */
	private function check_plugin( $plugin_file, array $plugin_data ) {
		$slug = strtok( $plugin_file, '/' );

		$response = plugins_api(
			'plugin_information',
			array(
				'slug'   => $slug,
				'fields' => array( 'last_updated' => true ),
			)
		);

		if ( is_wp_error( $response ) || ! isset( $response->last_updated ) ) {
			return null; // Not on WordPress.org (premium/custom plugin) — nothing we can check for free.
		}

		$last_updated = strtotime( $response->last_updated );
		if ( ! $last_updated ) {
			return null;
		}

		$age_years = ( time() - $last_updated ) / YEAR_IN_SECONDS;
		if ( $age_years < self::ABANDONED_YEARS ) {
			return null;
		}

		return array(
			'plugin' => isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug,
			'issue'  => 'abandoned',
			'detail' => sprintf(
				/* translators: %s: human-readable time since last update, e.g. "2 years" */
				__( 'No update on WordPress.org in over %s.', 'adc-security' ),
				human_time_diff( $last_updated )
			),
		);
	}

	/**
	 * @return array{scanned_at:int,findings:array}
	 */
	public static function get_last_result() {
		return get_option(
			self::RESULT_OPTION,
			array(
				'scanned_at' => 0,
				'findings'   => array(),
			)
		);
	}
}
