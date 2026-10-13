<?php
/**
 * ADC Security CSP Reports Class
 *
 * Collects Content-Security-Policy violation reports so a non-technical admin
 * can see what the CSP is blocking, and which source would need to be allowed.
 *
 * Reports are accepted on a REST endpoint (POST /adc-security/v1/csp-report),
 * normalized, and folded into a single non-autoloaded option keyed by
 * "directive|host" with a count and last-seen time. Storage is deliberately
 * not the events table: a flood of CSP reports would crowd out real audit
 * entries under the shared row cap, and the events table cannot aggregate
 * cheaply by directive and host.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Csp_Reports {

	/**
	 * REST namespace and route.
	 */
	const REST_NAMESPACE = 'adc-security/v1';
	const REST_ROUTE     = '/csp-report';

	/**
	 * Option holding the aggregated counters. Never autoloaded.
	 */
	const OPTION_NAME = 'adc_security_csp_reports';

	/**
	 * Hard cap on distinct directive+host rows kept.
	 */
	const MAX_ENTRIES = 200;

	/**
	 * Entries not seen for this many days are dropped on write and on read.
	 */
	const RETENTION_DAYS = 30;

	/**
	 * Hard cap on the raw request body, in bytes. Larger bodies are rejected.
	 */
	const MAX_BODY_BYTES = 8192;

	/**
	 * Maximum reports processed from one batched (Reporting API) request.
	 */
	const MAX_REPORTS_PER_REQUEST = 10;

	/**
	 * Per-IP token bucket for report submissions.
	 */
	const RATE_CAPACITY    = 30;
	const RATE_REFILL_SECS = 2;

	/**
	 * Accepted request media types. Browsers send application/csp-report
	 * (legacy) or application/reports+json (Reporting API).
	 */
	const ALLOWED_TYPES = array(
		'application/csp-report',
		'application/reports+json',
		'application/json',
	);

	/**
	 * Field length caps applied at store time.
	 */
	const MAX_DIRECTIVE_LENGTH = 40;
	const MAX_HOST_LENGTH      = 253;
	const MAX_SOURCE_LENGTH    = 200;
	const MAX_RAW_URI_LENGTH   = 2048;

	/**
	 * Hook the REST route registration.
	 */
	public function register(): void {
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
	}

	/**
	 * Register the report route. Called from rest_api_init.
	 */
	public function register_routes(): void {
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE,
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_report' ),
				// Browsers send CSP reports anonymously: no cookies, no REST nonce,
				// and no way to attach a capability. Access control is therefore
				// the body cap, the media type allowlist, the per-IP rate limit and
				// the same-site document check in handle_report().
				'permission_callback' => '__return_true',
				'args'                => array(),
			)
		);
	}

	/**
	 * Absolute URL of the report endpoint, for the Content-Security-Policy report-uri / report-to directive.
	 *
	 * @return string
	 */
	public static function report_uri(): string {
		return rest_url( 'adc-security/v1/csp-report' );
	}

	/**
	 * REST callback. Always answers quietly: 204 for accepted or intentionally
	 * ignored reports, 400 for unusable input. Never logs or emits notices.
	 *
	 * @param WP_REST_Request $request Incoming request.
	 * @return WP_REST_Response
	 */
	public function handle_report( WP_REST_Request $request ): WP_REST_Response {
		$media_type = self::media_type( $request->get_header( 'content-type' ) );
		if ( ! in_array( $media_type, self::ALLOWED_TYPES, true ) ) {
			return new WP_REST_Response( null, 400 );
		}

		$body = $request->get_body();
		if ( ! is_string( $body ) || '' === $body || strlen( $body ) > self::MAX_BODY_BYTES ) {
			return new WP_REST_Response( null, 400 );
		}

		if ( ! $this->within_rate_limit() ) {
			// Drop silently. A 429 would only tell a flooder that the endpoint exists.
			return new WP_REST_Response( null, 204 );
		}

		$decoded = json_decode( $body, true );
		if ( ! is_array( $decoded ) ) {
			return new WP_REST_Response( null, 400 );
		}

		// Reporting API batches are lists; legacy reports are a single object.
		$reports = isset( $decoded[0] ) ? $decoded : array( $decoded );
		$reports = array_slice( $reports, 0, self::MAX_REPORTS_PER_REQUEST );

		$site_host = self::site_host();
		$entries   = array();

		foreach ( $reports as $raw ) {
			if ( ! is_array( $raw ) ) {
				continue;
			}

			// Only record violations on this site's own pages. Reports for other
			// hosts are either spoofed or come from an embedding page we do not own.
			$document_host = self::host_of( self::document_uri( $raw ) );
			if ( '' === $site_host || $document_host !== $site_host ) {
				continue;
			}

			$normalized = self::normalize_report( $raw );
			if ( null !== $normalized ) {
				$entries[] = $normalized;
			}
		}

		if ( ! empty( $entries ) ) {
			$this->store( $entries );
		}

		return new WP_REST_Response( null, 204 );
	}

	/**
	 * Aggregated view for the admin UI, most frequent first.
	 *
	 * @param int $limit Maximum rows to return (1-200).
	 * @return array<int,array{directive:string,host:string,count:int,last_seen:string,suggested_source:string}>
	 */
	public function get_blocked_summary( int $limit = 50 ): array {
		$limit  = max( 1, min( self::MAX_ENTRIES, $limit ) );
		$cutoff = time() - ( self::RETENTION_DAYS * DAY_IN_SECONDS );
		$store  = self::read_store();

		$rows = array();
		foreach ( $store as $row ) {
			if ( $row['last_seen_ts'] < $cutoff ) {
				continue;
			}
			$rows[] = $row;
		}

		usort(
			$rows,
			static function ( $a, $b ) {
				if ( $a['count'] !== $b['count'] ) {
					return $b['count'] - $a['count'];
				}
				return $b['last_seen_ts'] - $a['last_seen_ts'];
			}
		);

		$summary = array();
		foreach ( array_slice( $rows, 0, $limit ) as $row ) {
			$summary[] = array(
				'directive'        => $row['directive'],
				'host'             => $row['host'],
				'count'            => $row['count'],
				'last_seen'        => gmdate( 'Y-m-d H:i:s', $row['last_seen_ts'] ),
				'suggested_source' => $row['suggested_source'],
			);
		}

		return $summary;
	}

	/**
	 * Remove all aggregated CSP report data.
	 */
	public function clear(): void {
		delete_option( self::OPTION_NAME );
	}

	/**
	 * Turn one raw report (either format, or a Reporting API envelope) into a
	 * sanitized directive/host/source triple. Pure: no WordPress calls are
	 * needed, except sanitize_text_field() when it is available.
	 *
	 * Returns null for reports that are not actionable: missing or malformed
	 * directive, empty blocked URI, 'inline' / 'eval', browser-extension
	 * schemes, and anything that fails strict validation.
	 *
	 * @param array $raw Decoded report.
	 * @return array{directive:string,host:string,suggested_source:string}|null
	 */
	public static function normalize_report( array $raw ): ?array {
		$body = self::unwrap( $raw );
		if ( empty( $body ) ) {
			return null;
		}

		// Directive: prefer the effective directive, fall back to the first token of the violated one.
		$directive = trim( self::clean( self::first_of( $body, array( 'effective-directive', 'effectiveDirective' ) ), self::MAX_RAW_URI_LENGTH ) );
		if ( '' === $directive ) {
			$violated  = self::clean( self::first_of( $body, array( 'violated-directive', 'violatedDirective' ) ), self::MAX_RAW_URI_LENGTH );
			$tokens    = preg_split( '/\s+/', $violated, -1, PREG_SPLIT_NO_EMPTY );
			$directive = $tokens ? $tokens[0] : '';
		}
		// Reject rather than truncate: a directive name is never longer than the cap.
		$directive = strtolower( $directive );
		if ( strlen( $directive ) > self::MAX_DIRECTIVE_LENGTH || ! preg_match( '/^[a-z][a-z-]{0,39}$/', $directive ) ) {
			return null;
		}

		$blocked = strtolower( trim( self::clean( self::first_of( $body, array( 'blocked-uri', 'blockedURL' ) ), self::MAX_RAW_URI_LENGTH ) ) );
		if ( '' === $blocked || 'inline' === $blocked || 'eval' === $blocked ) {
			return null;
		}

		foreach ( array( 'chrome-extension:', 'moz-extension:', 'safari-extension:' ) as $extension_prefix ) {
			if ( 0 === strpos( $blocked, $extension_prefix ) ) {
				return null;
			}
		}

		$parts = parse_url( $blocked ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		if ( false === $parts || empty( $parts['scheme'] ) || ! preg_match( '/^[a-z][a-z0-9+.-]{0,20}$/', $parts['scheme'] ) ) {
			return null;
		}

		$scheme = $parts['scheme'];
		if ( ! empty( $parts['host'] ) ) {
			$host   = strtolower( $parts['host'] );
			$source = $scheme . '://' . $host;
			if ( isset( $parts['port'] ) ) {
				$source .= ':' . (int) $parts['port'];
			}
		} else {
			// data:, blob:, filesystem: and similar carry no host; the scheme is the source.
			$host   = $scheme;
			$source = $scheme . ':';
		}

		if ( ! preg_match( '/^[a-z0-9.\[\]:-]{1,' . self::MAX_HOST_LENGTH . '}$/', $host ) ) {
			return null;
		}
		if ( ! preg_match( '/^[a-z0-9.+\-:\/\[\]]{1,' . self::MAX_SOURCE_LENGTH . '}$/', $source ) ) {
			return null;
		}

		return array(
			'directive'        => $directive,
			'host'             => $host,
			'suggested_source' => $source,
		);
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	/**
	 * Return the inner report body for the legacy, Reporting API and flat shapes.
	 *
	 * @param array $raw Decoded report.
	 * @return array Inner body, or empty array if the report is of another type.
	 */
	private static function unwrap( array $raw ): array {
		if ( isset( $raw['csp-report'] ) && is_array( $raw['csp-report'] ) ) {
			return $raw['csp-report'];
		}

		if ( isset( $raw['type'], $raw['body'] ) ) {
			if ( 'csp-violation' !== $raw['type'] || ! is_array( $raw['body'] ) ) {
				return array();
			}
			return $raw['body'];
		}

		return $raw;
	}

	/**
	 * Document URI from either report format, unsanitized.
	 *
	 * @param array $raw Decoded report.
	 * @return string
	 */
	private static function document_uri( array $raw ): string {
		$body = self::unwrap( $raw );
		return self::first_of( $body, array( 'document-uri', 'documentURL' ) );
	}

	/**
	 * First non-empty string value among the given keys, capped in length.
	 *
	 * @param array    $body Inner report body.
	 * @param string[] $keys Keys to try in order.
	 * @return string
	 */
	private static function first_of( array $body, array $keys ): string {
		foreach ( $keys as $key ) {
			if ( isset( $body[ $key ] ) && is_string( $body[ $key ] ) && '' !== $body[ $key ] ) {
				return substr( $body[ $key ], 0, self::MAX_RAW_URI_LENGTH );
			}
		}
		return '';
	}

	/**
	 * Lowercased host of a URL, or '' when it has none.
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function host_of( string $url ): string {
		if ( '' === $url ) {
			return '';
		}
		$parts = parse_url( $url ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url
		return ( false !== $parts && ! empty( $parts['host'] ) ) ? strtolower( $parts['host'] ) : '';
	}

	/**
	 * Lowercased host of this site.
	 *
	 * @return string
	 */
	private static function site_host(): string {
		return self::host_of( home_url() );
	}

	/**
	 * Media type from a Content-Type header, without parameters.
	 *
	 * @param mixed $header Header value.
	 * @return string
	 */
	private static function media_type( $header ): string {
		if ( ! is_string( $header ) ) {
			return '';
		}
		$parts = explode( ';', $header, 2 );
		return strtolower( trim( $parts[0] ) );
	}

	/**
	 * Sanitize a free-text value and cap its length. Strips tags and control
	 * characters. Output is escaped by the consumer.
	 *
	 * @param mixed $value Raw value.
	 * @param int   $max   Maximum length in bytes.
	 * @return string
	 */
	private static function clean( $value, int $max ): string {
		if ( ! is_string( $value ) ) {
			return '';
		}

		if ( function_exists( 'sanitize_text_field' ) ) {
			$value = sanitize_text_field( $value );
		} else {
			$value = trim( strip_tags( preg_replace( '/[\x00-\x1F\x7F]/', '', $value ) ) );
		}

		return substr( $value, 0, $max );
	}

	/**
	 * Fold entries into the stored counters, apply retention and the row cap.
	 *
	 * @param array[] $entries Normalized entries from normalize_report().
	 */
	private function store( array $entries ): void {
		$now    = time();
		$cutoff = $now - ( self::RETENTION_DAYS * DAY_IN_SECONDS );
		$store  = self::read_store();

		// Retention on write: drop anything older than the window.
		foreach ( $store as $key => $row ) {
			if ( $row['last_seen_ts'] < $cutoff ) {
				unset( $store[ $key ] );
			}
		}

		foreach ( $entries as $entry ) {
			$key = $entry['directive'] . '|' . $entry['host'];

			if ( isset( $store[ $key ] ) ) {
				$store[ $key ]['count']        += 1;
				$store[ $key ]['last_seen_ts']  = $now;
			} else {
				$store[ $key ] = array(
					'directive'        => $entry['directive'],
					'host'             => $entry['host'],
					'suggested_source' => $entry['suggested_source'],
					'count'            => 1,
					'last_seen_ts'     => $now,
				);
			}
		}

		// Row cap: evict the least recently seen rows first.
		if ( count( $store ) > self::MAX_ENTRIES ) {
			uasort(
				$store,
				static function ( $a, $b ) {
					return $b['last_seen_ts'] - $a['last_seen_ts'];
				}
			);
			$store = array_slice( $store, 0, self::MAX_ENTRIES, true );
		}

		update_option( self::OPTION_NAME, $store, false );
	}

	/**
	 * Read the stored counters, discarding malformed rows.
	 *
	 * @return array<string,array>
	 */
	private static function read_store(): array {
		$store = get_option( self::OPTION_NAME, array() );
		if ( ! is_array( $store ) ) {
			return array();
		}

		$clean = array();
		foreach ( $store as $key => $row ) {
			if (
				is_array( $row ) &&
				isset( $row['directive'], $row['host'], $row['suggested_source'], $row['count'], $row['last_seen_ts'] ) &&
				is_string( $row['directive'] ) && is_string( $row['host'] ) && is_string( $row['suggested_source'] ) &&
				is_int( $row['count'] ) && is_int( $row['last_seen_ts'] )
			) {
				$clean[ $key ] = $row;
			}
		}
		return $clean;
	}

	/**
	 * Per-IP token bucket. Uses the shared refill calculation from
	 * ADC_Security_Rate_Limit so the arithmetic matches the other buckets.
	 *
	 * @return bool True if this report may be processed.
	 */
	private function within_rate_limit(): bool {
		$ip  = ADC_Security_Ip::get_client_ip();
		$key = 'adc_rl_csp_report_' . md5( '' !== $ip ? $ip : 'unknown' );

		$now    = microtime( true );
		$bucket = get_transient( $key );
		if ( ! is_array( $bucket ) || ! isset( $bucket['tokens'], $bucket['updated'] ) ) {
			$bucket = array(
				'tokens'  => self::RATE_CAPACITY,
				'updated' => $now,
			);
		}

		$bucket['tokens']  = ADC_Security_Rate_Limit::refill(
			$bucket['tokens'],
			max( 0, $now - $bucket['updated'] ),
			self::RATE_CAPACITY,
			self::RATE_REFILL_SECS
		);
		$bucket['updated'] = $now;

		$allowed = $bucket['tokens'] >= 1;
		if ( $allowed ) {
			$bucket['tokens'] -= 1;
		}

		set_transient( $key, $bucket, self::RATE_CAPACITY * self::RATE_REFILL_SECS );

		return $allowed;
	}
}
