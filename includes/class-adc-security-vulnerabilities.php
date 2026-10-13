<?php
/**
 * ADC Security Vulnerabilities Class
 *
 * Zero-configuration component health scan with two independent signals:
 *
 * 1. Plugin maintenance health (always on): flags installed plugins that have
 *    been closed/removed from the WordPress.org directory, or that haven't
 *    shipped an update in over two years — strong signals of unmaintained code
 *    that's more likely to carry an unpatched vulnerability. Uses only the
 *    WordPress.org plugins API, so nothing leaves the site.
 * 2. Known-vulnerability cross-reference (opt-in): matches the installed
 *    WordPress core version and every active WordPress.org plugin against the
 *    public WPVulnerability database API (https://www.wpvulnerability.net),
 *    which is free and needs no API key. Only the core version and the plugin
 *    slugs are sent — never site URLs, users or content.
 *
 * The feed is a cross-reference, not a proof of cleanliness: an empty result
 * does not mean a component is safe (coverage is only as complete as the
 * upstream database), so it never replaces installing updates.
 *
 * The result set is intentionally plain data (array of findings, each with
 * 'component', 'issue' and 'detail') so it can be rendered, counted by the
 * security score, or extended by another provider. The
 * 'adc_security_vulnerability_findings' filter remains the extension point for
 * a paid feed (WPScan, Patchstack, ...) on top of the free data.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Vulnerabilities {

	const CRON_HOOK       = 'adc_security_vuln_scan';
	const RESULT_OPTION   = 'adc_security_vuln_result';
	const ABANDONED_YEARS = 2;

	/**
	 * Base URL of the free WPVulnerability API.
	 */
	const FEED_BASE = 'https://www.wpvulnerability.net';

	/**
	 * How long a component response is cached before it is fetched again.
	 */
	const FEED_CACHE_TTL = 12 * HOUR_IN_SECONDS;

	/**
	 * How long a component's findings stay in the result set without being
	 * re-checked (relevant because plugin lookups are rotated across runs).
	 */
	const FEED_MAX_AGE_DAYS = 7;

	/**
	 * Component lookups performed per scan run. Plugin lookups rotate, so one
	 * cron run never fires an unbounded number of HTTP requests; core is always
	 * checked because it is a single request with the highest signal.
	 */
	const FEED_LOOKUPS_PER_SCAN = 25;

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

		$active_plugins = get_option( 'active_plugins', array() );
		$all_plugins    = get_plugins();

		$findings = $this->collect_abandoned_findings( $active_plugins, $all_plugins );

		$previous = get_option( self::RESULT_OPTION, array() );
		$feed     = $this->refresh_feed( $active_plugins, $all_plugins, is_array( $previous ) ? $previous : array() );

		if ( ! empty( $feed['findings'] ) ) {
			$findings = array_merge( $findings, $feed['findings'] );
		}

		/**
		 * Let an optional external provider add its own findings, e.g.
		 * matched CVEs from a paid feed. Each entry should look like the
		 * ones this class produces: array( 'component', 'issue', 'detail' ).
		 *
		 * @param array $findings       Findings so far.
		 * @param array $active_plugins Active plugin files.
		 */
		$findings = apply_filters( 'adc_security_vulnerability_findings', $findings, $active_plugins );

		update_option(
			self::RESULT_OPTION,
			array(
				'scanned_at'      => time(),
				'findings'        => $findings,
				'feed_checked_at' => $feed['feed_checked_at'],
				'feed_offset'     => $feed['feed_offset'],
				'feed_cache'      => $feed['feed_cache'],
			),
			false
		);
	}

	// -------------------------------------------------------------------------
	// Signal 1: plugin maintenance health
	// -------------------------------------------------------------------------

	/**
	 * @param array $active_plugins Active plugin files.
	 * @param array $all_plugins    Plugin headers from get_plugins().
	 * @return array Findings.
	 */
	private function collect_abandoned_findings( array $active_plugins, array $all_plugins ) {
		$findings = array();

		foreach ( $active_plugins as $plugin_file ) {
			if ( ! isset( $all_plugins[ $plugin_file ] ) ) {
				continue;
			}

			$finding = $this->check_plugin( $plugin_file, $all_plugins[ $plugin_file ] );
			if ( $finding ) {
				$findings[] = $finding;
			}
		}

		return $findings;
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
			'component' => isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug,
			'plugin'    => isset( $plugin_data['Name'] ) ? $plugin_data['Name'] : $slug,
			'issue'     => 'abandoned',
			'detail'    => sprintf(
				/* translators: %s: human-readable time since last update, e.g. "2 years" */
				__( 'No update on WordPress.org in over %s.', 'adc-security' ),
				human_time_diff( $last_updated )
			),
		);
	}

	// -------------------------------------------------------------------------
	// Signal 2: known-vulnerability cross-reference (opt-in)
	// -------------------------------------------------------------------------

	/**
	 * @return bool Whether the external vulnerability feed is enabled.
	 */
	public function is_feed_enabled() {
		$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		return ! empty( $options['vulnerability_feed_enabled'] );
	}

	/**
	 * Refresh the feed cache: core every run, plugins in a rotating batch.
	 *
	 * @param array $active_plugins Active plugin files.
	 * @param array $all_plugins    Plugin headers from get_plugins().
	 * @param array $previous       Previous stored result.
	 * @return array{feed_cache:array,feed_offset:int,feed_checked_at:int,findings:array}
	 *
	 * The returned keys match the option keys this method reads from
	 * $previous, so its own output can be fed straight back in on the next run.
	 */
	private function refresh_feed( array $active_plugins, array $all_plugins, array $previous ) {
		if ( ! $this->is_feed_enabled() ) {
			return array(
				'feed_cache'      => array(),
				'feed_offset'     => 0,
				'feed_checked_at' => 0,
				'findings'        => array(),
			);
		}

		$cache      = isset( $previous['feed_cache'] ) && is_array( $previous['feed_cache'] ) ? $previous['feed_cache'] : array();
		$offset     = isset( $previous['feed_offset'] ) ? max( 0, (int) $previous['feed_offset'] ) : 0;
		$checked_at = isset( $previous['feed_checked_at'] ) ? (int) $previous['feed_checked_at'] : 0;

		// Build the component queue: core plus every active WordPress.org plugin.
		$core_version = (string) get_bloginfo( 'version' );
		$queue        = array();

		foreach ( $active_plugins as $plugin_file ) {
			if ( ! isset( $all_plugins[ $plugin_file ] ) ) {
				continue;
			}

			$slug = strtok( (string) $plugin_file, '/' );
			if ( ! $slug || 'adc-security' === $slug ) {
				continue;
			}

			$queue[ $slug ] = array(
				'name'    => isset( $all_plugins[ $plugin_file ]['Name'] ) ? $all_plugins[ $plugin_file ]['Name'] : $slug,
				'version' => isset( $all_plugins[ $plugin_file ]['Version'] ) ? (string) $all_plugins[ $plugin_file ]['Version'] : '',
			);
		}

		ksort( $queue );
		$slugs = array_keys( $queue );

		$cache[ 'core:' . $core_version ] = array(
			'checked_at' => time(),
			'findings'   => $this->scan_core_for_cves( $core_version ),
		);

		if ( $slugs ) {
			$count = count( $slugs );
			$limit = (int) apply_filters( 'adc_security_vulnerability_feed_lookups_per_scan', self::FEED_LOOKUPS_PER_SCAN );
			$limit = max( 1, min( $limit, $count ) );

			if ( $offset >= $count ) {
				$offset = 0;
			}

			for ( $i = 0; $i < $limit; $i++ ) {
				$slug = $slugs[ ( $offset + $i ) % $count ];

				$cache[ 'plugin:' . $slug ] = array(
					'checked_at' => time(),
					'findings'   => $this->scan_plugin_for_cves( $slug, $queue[ $slug ]['name'], $queue[ $slug ]['version'] ),
				);
			}

			$offset     = ( $offset + $limit ) % $count;
			$checked_at = time();
		}

		// Keep only installed components, and only fresh entries.
		$installed    = array( 'core:' . $core_version );
		$stale_before = time() - ( self::FEED_MAX_AGE_DAYS * DAY_IN_SECONDS );

		foreach ( $slugs as $slug ) {
			$installed[] = 'plugin:' . $slug;
		}

		foreach ( array_keys( $cache ) as $key ) {
			$fresh = isset( $cache[ $key ]['checked_at'] ) && (int) $cache[ $key ]['checked_at'] >= $stale_before;

			if ( ! $fresh || ! in_array( $key, $installed, true ) ) {
				unset( $cache[ $key ] );
			}
		}

		$findings = array();
		foreach ( $cache as $entry ) {
			if ( ! empty( $entry['findings'] ) ) {
				$findings = array_merge( $findings, $entry['findings'] );
			}
		}

		return array(
			'feed_cache'      => $cache,
			'feed_offset'     => $offset,
			'feed_checked_at' => $checked_at,
			'findings'        => $findings,
		);
	}

	/**
	 * @param string $version Installed WordPress version.
	 * @return array Findings.
	 */
	private function scan_core_for_cves( $version ) {
		if ( '' === $version ) {
			return array();
		}

		// The core endpoint is already scoped to the requested version.
		$payload = $this->fetch_component( 'core/' . rawurlencode( $version ) );

		return $this->build_findings( 'WordPress ' . $version, $payload, $version );
	}

	/**
	 * @param string $slug    Plugin slug.
	 * @param string $name    Plugin display name.
	 * @param string $version Installed plugin version.
	 * @return array Findings.
	 */
	private function scan_plugin_for_cves( $slug, $name, $version = '' ) {
		$payload = $this->fetch_component( 'plugin/' . rawurlencode( $slug ) );

		return $this->build_findings( $name ? $name : $slug, $payload, $version );
	}

	/**
	 * Turn a feed payload into findings for one installed version.
	 *
	 * @param string $label   Component label shown in the result.
	 * @param array  $payload Decoded API response.
	 * @param string $version Installed version.
	 * @return array Findings.
	 */
	private function build_findings( $label, array $payload, $version ) {
		$findings = array();

		foreach ( self::match_vulnerabilities( $payload, (string) $version ) as $match ) {
			$findings[] = array(
				'component' => $label,
				'plugin'    => $label,
				'issue'     => 'vulnerable',
				'detail'    => self::describe_match( $match ),
				'cve'       => $match['cve'],
				'severity'  => $match['severity'],
			);
		}

		return $findings;
	}

	/**
	 * Fetch and cache one component from the public feed. Fails closed to an
	 * empty result: a feed outage must never break the scan.
	 *
	 * @param string $path Path below the API base, e.g. "plugin/woocommerce".
	 * @return array Decoded response, or an empty array on any failure.
	 */
	private function fetch_component( $path ) {
		$key    = 'adc_vuln_' . md5( $path );
		$cached = get_transient( $key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$response = wp_remote_get(
			self::FEED_BASE . '/' . $path . '/',
			array(
				'timeout'    => 15,
				'sslverify'  => true,
				'user-agent' => 'ADC-Security-Plugin/' . ( defined( 'ADC_SECURITY_VERSION' ) ? ADC_SECURITY_VERSION : '0' ),
				'headers'    => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			set_transient( $key, array(), HOUR_IN_SECONDS );

			return array();
		}

		$payload = json_decode( wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $payload ) || ! isset( $payload['error'] ) || 0 !== (int) $payload['error'] ) {
			$payload = array();
		}

		set_transient( $key, $payload, self::FEED_CACHE_TTL );

		return $payload;
	}

	// -------------------------------------------------------------------------
	// Pure matchers (unit tested without WordPress)
	// -------------------------------------------------------------------------

	/**
	 * Whether one feed entry applies to the installed version.
	 *
	 * The API expresses affected ranges with PHP version_compare() operators
	 * ("lt", "le", "eq", "ne", "gt", "ge"). An entry without bounds applies to
	 * every version — which is how the core endpoint reports, since it is
	 * already scoped to the version that was requested.
	 *
	 * @param array  $vulnerability Feed entry.
	 * @param string $version       Installed version.
	 * @return bool
	 */
	public static function matches_version( array $vulnerability, $version ) {
		$operators = isset( $vulnerability['operator'] ) && is_array( $vulnerability['operator'] ) ? $vulnerability['operator'] : array();

		$min = isset( $operators['min_version'] ) && is_string( $operators['min_version'] ) && '' !== $operators['min_version'] ? $operators['min_version'] : null;
		$max = isset( $operators['max_version'] ) && is_string( $operators['max_version'] ) && '' !== $operators['max_version'] ? $operators['max_version'] : null;

		if ( null === $min && null === $max ) {
			return true;
		}

		if ( '' === (string) $version ) {
			return false; // Unknown installed version: never claim a match.
		}

		$map = array(
			'lt' => '<',
			'le' => '<=',
			'eq' => '=',
			'ne' => '!=',
			'gt' => '>',
			'ge' => '>=',
		);

		if ( null !== $min ) {
			$raw    = isset( $operators['min_operator'] ) ? strtolower( (string) $operators['min_operator'] ) : 'ge';
			$symbol = isset( $map[ $raw ] ) ? $map[ $raw ] : '>=';

			if ( ! version_compare( (string) $version, $min, $symbol ) ) {
				return false;
			}
		}

		if ( null !== $max ) {
			$raw    = isset( $operators['max_operator'] ) ? strtolower( (string) $operators['max_operator'] ) : 'lt';
			$symbol = isset( $map[ $raw ] ) ? $map[ $raw ] : '<';

			if ( ! version_compare( (string) $version, $max, $symbol ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * Extract every feed entry that applies to the installed version.
	 *
	 * @param array  $payload Decoded API response.
	 * @param string $version Installed version.
	 * @return array<int,array{cve:string[],title:string,score:string,severity:string,unfixed:bool}>
	 */
	public static function match_vulnerabilities( array $payload, $version ) {
		if ( isset( $payload['error'] ) && 0 !== (int) $payload['error'] ) {
			return array();
		}

		$data = isset( $payload['data'] ) && is_array( $payload['data'] ) ? $payload['data'] : array();
		$list = isset( $data['vulnerability'] ) && is_array( $data['vulnerability'] ) ? $data['vulnerability'] : array();

		$matches = array();

		foreach ( $list as $vulnerability ) {
			if ( ! is_array( $vulnerability ) || ! self::matches_version( $vulnerability, $version ) ) {
				continue;
			}

			$matches[] = self::summarize( $vulnerability );
		}

		return $matches;
	}

	/**
	 * Reduce one feed entry to the fields the finding needs.
	 *
	 * @param array $vulnerability Feed entry.
	 * @return array{cve:string[],title:string,score:string,severity:string,unfixed:bool}
	 */
	private static function summarize( array $vulnerability ) {
		$cve = array();

		if ( isset( $vulnerability['source'] ) && is_array( $vulnerability['source'] ) ) {
			foreach ( $vulnerability['source'] as $source ) {
				$id = isset( $source['id'] ) && is_string( $source['id'] ) ? trim( $source['id'] ) : '';

				if ( '' !== $id && preg_match( '/^CVE-\d{4}-\d{4,}$/i', $id ) ) {
					$cve[] = strtoupper( $id );
				}
			}
		}

		$score    = '';
		$severity = '';
		$impact   = isset( $vulnerability['impact'] ) && is_array( $vulnerability['impact'] ) ? $vulnerability['impact'] : array();

		foreach ( array( 'cvss3', 'cvss4', 'cvss' ) as $key ) {
			if ( isset( $impact[ $key ]['score'] ) && '' !== (string) $impact[ $key ]['score'] ) {
				$score    = (string) $impact[ $key ]['score'];
				$severity = isset( $impact[ $key ]['severity'] ) ? (string) $impact[ $key ]['severity'] : '';
				break;
			}
		}

		return array(
			'cve'      => array_values( array_unique( $cve ) ),
			'title'    => isset( $vulnerability['name'] ) ? (string) $vulnerability['name'] : '',
			'score'    => $score,
			'severity' => $severity,
			'unfixed'  => ! empty( $vulnerability['operator']['unfixed'] ),
		);
	}

	/**
	 * Build the human-readable finding detail from a summary.
	 *
	 * @param array $match Summary from summarize().
	 * @return string
	 */
	private static function describe_match( array $match ) {
		$ids = ! empty( $match['cve'] ) ? implode( ', ', $match['cve'] ) : $match['title'];

		if ( '' === $ids ) {
			$ids = __( 'Known vulnerability', 'adc-security' );
		}

		if ( $match['unfixed'] ) {
			$suffix = __( 'no fixed version published yet', 'adc-security' );
		} else {
			$suffix = __( 'fixed in a newer release', 'adc-security' );
		}

		if ( '' !== $match['score'] ) {
			/* translators: 1: CVE identifiers, 2: CVSS score, 3: remediation note. */
			return sprintf( __( '%1$s (CVSS %2$s) — %3$s.', 'adc-security' ), $ids, $match['score'], $suffix );
		}

		/* translators: 1: CVE identifiers, 2: remediation note. */
		return sprintf( __( '%1$s — %2$s.', 'adc-security' ), $ids, $suffix );
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
