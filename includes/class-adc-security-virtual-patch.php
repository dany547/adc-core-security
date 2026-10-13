<?php
/**
 * ADC Security Virtual Patch Class
 *
 * Request-level ("virtual patch") guards for WordPress core vulnerabilities
 * that are exploited in the wild, so a site keeps its protection window
 * between the day a CVE is published and the day the core update is actually
 * installed. Sites that deliberately delay core updates (or that cannot
 * update because of a host/plugin incompatibility) are exactly the audience
 * for this module.
 *
 * Every rule is opt-in, pattern-based — so it also catches encoding variants
 * of the same bug instead of one hardcoded exploit string — and can run in
 * monitor mode, which records the hit in the Activity log without blocking,
 * the same rollout model the WooCommerce rules already use.
 *
 * Rules shipped here:
 * - block_page_template_traversal  CVE-2026-87902 (unauthenticated LFI/RCE via
 *   double-encoded path traversal in the pagename query var).
 * - block_rest_batch_unauth        CVE-2026-63030 (unauthenticated REST batch
 *   route confusion, the first half of the "wp2shell" RCE chain).
 * - reject_author_query_injection  CVE-2026-60137 (WP_Query author__not_in SQL
 *   injection, the second half of the same chain).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Virtual_Patch {

	const RULE_PAGE_TEMPLATE_TRAVERSAL = 'block_page_template_traversal';
	const RULE_REST_BATCH_UNAUTH       = 'block_rest_batch_unauth';
	const RULE_AUTHOR_QUERY_INJECTION  = 'reject_author_query_injection';

	/**
	 * Decode passes performed while probing for encoded path traversal.
	 *
	 * The exploit for CVE-2026-87902 is double-encoded, and PHP has already
	 * decoded the request body once by the time the plugin sees it.
	 */
	const MAX_DECODE_PASSES = 4;

	/**
	 * Maximum recursion depth when walking nested request arrays.
	 */
	const MAX_ARG_DEPTH = 5;

	/**
	 * Core REST route abused by CVE-2026-63030.
	 */
	const REST_BATCH_ROUTE = '/batch/v1';

	/**
	 * Event type recorded in the Activity log.
	 */
	const EVENT_TYPE = 'virtual_patch';

	/**
	 * @var array Saved plugin options.
	 */
	private $options;

	/**
	 * Constructor. Only the hooks for the enabled rules are registered.
	 */
	public function __construct() {
		$this->options = get_option( ADC_Security_Settings::OPTION_NAME, array() );

		$rules = self::get_enabled_rules( $this->options );

		if ( in_array( self::RULE_PAGE_TEMPLATE_TRAVERSAL, $rules, true ) ) {
			add_action( 'init', array( $this, 'guard_page_template_traversal' ), 0 );
		}

		if ( in_array( self::RULE_AUTHOR_QUERY_INJECTION, $rules, true ) ) {
			add_action( 'init', array( $this, 'guard_author_query_injection' ), 0 );
		}

		if ( in_array( self::RULE_REST_BATCH_UNAUTH, $rules, true ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'guard_rest_batch' ), 1, 3 );
		}
	}

	// -------------------------------------------------------------------------
	// Rule definitions
	// -------------------------------------------------------------------------

	/**
	 * Return the fixed rules this module can enforce.
	 *
	 * The labels are deliberately plain strings, like the .htaccess rule
	 * definitions, so this class stays free of translation calls and can be
	 * unit tested outside WordPress.
	 *
	 * @return array<string,array<string,string>>
	 */
	public static function get_rule_definitions() {
		return array(
			self::RULE_PAGE_TEMPLATE_TRAVERSAL => array(
				'label'       => 'Block page-template path traversal',
				'description' => 'Rejects front-end requests whose pagename contains path traversal, in any encoding depth (CVE-2026-87902: unauthenticated local file inclusion / remote code execution in page-template resolution, WordPress 4.7 - 7.1.1).',
			),
			self::RULE_REST_BATCH_UNAUTH       => array(
				'label'       => 'Block unauthenticated REST batch requests',
				'description' => 'Rejects unauthenticated POSTs to /wp-json/batch/v1 (CVE-2026-63030: REST API batch route confusion, first half of the "wp2shell" pre-authentication RCE chain, WordPress 6.9.0 - 6.9.4 and 7.0.0 - 7.0.1).',
			),
			self::RULE_AUTHOR_QUERY_INJECTION  => array(
				'label'       => 'Reject author__not_in request arguments',
				'description' => 'Rejects front-end requests that pass author__not_in / author__in over HTTP (CVE-2026-60137: WP_Query SQL injection, second half of the same "wp2shell" RCE chain). Plugins that build these arguments internally are not affected.',
			),
		);
	}

	/**
	 * @return string[] Rule keys accepted by the module.
	 */
	public static function get_rule_keys() {
		return array_keys( self::get_rule_definitions() );
	}

	/**
	 * Extract the enabled rule keys from the saved options.
	 *
	 * @param array $options Saved plugin options.
	 * @return string[] Enabled rule keys.
	 */
	public static function get_enabled_rules( array $options ) {
		$rules = isset( $options['virtual_patch_rules'] ) && is_array( $options['virtual_patch_rules'] )
			? $options['virtual_patch_rules']
			: array();

		$rules = array_map( 'sanitize_key', array_filter( $rules, 'is_string' ) );

		return array_values( array_intersect( self::get_rule_keys(), $rules ) );
	}

	/**
	 * @return bool Whether hits are logged without being blocked.
	 */
	private function is_monitor_mode() {
		return ! empty( $this->options['virtual_patch_monitor'] );
	}

	// -------------------------------------------------------------------------
	// Guards
	// -------------------------------------------------------------------------

	/**
	 * Reject traversal payloads aimed at the page-template resolver.
	 *
	 * Hooked on init so it runs before WP::parse_request(), the main query and
	 * template loading. Admin requests are skipped: the vulnerable code path is
	 * front-end template resolution, and wp-admin never renders a page
	 * template.
	 */
	public function guard_page_template_traversal() {
		if ( is_admin() ) {
			return;
		}

		foreach ( array( $_GET, $_POST ) as $source ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Request screening, not a form handler.
			if ( ! isset( $source['pagename'] ) || ! is_string( $source['pagename'] ) ) {
				continue;
			}

			if ( self::contains_traversal( wp_unslash( $source['pagename'] ) ) ) {
				$this->deny( 'CVE-2026-87902', 'pagename', 'page-template path traversal' );
				return;
			}
		}
	}

	/**
	 * Reject author query-argument injection passed over HTTP.
	 *
	 * Hooked on init, before WP::parse_request() turns $_GET into query vars.
	 */
	public function guard_author_query_injection() {
		if ( is_admin() ) {
			return;
		}

		foreach ( array( $_GET, $_POST ) as $source ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Request screening, not a form handler.
			if ( self::contains_author_injection_arg( $source ) ) {
				$this->deny( 'CVE-2026-60137', 'author__not_in', 'WP_Query author argument injection' );
				return;
			}
		}
	}

	/**
	 * Reject unauthenticated REST batch requests.
	 *
	 * @param mixed           $result  Short-circuit result from earlier filters.
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request Current REST request.
	 * @return mixed WP_Error when blocked, otherwise the value passed in.
	 */
	public function guard_rest_batch( $result, $server, $request ) {
		if ( null !== $result ) {
			return $result; // Another filter already decided; do not override it.
		}

		if ( is_user_logged_in() ) {
			return $result; // The CVE chain is unauthenticated; logged-in batching stays available.
		}

		$route = $request instanceof WP_REST_Request ? (string) $request->get_route() : '';

		if ( 0 !== strpos( $route, self::REST_BATCH_ROUTE ) ) {
			return $result;
		}

		$blocked = $this->deny( 'CVE-2026-63030', self::REST_BATCH_ROUTE, 'unauthenticated REST batch request', false );

		if ( ! $blocked ) {
			return $result;
		}

		return new WP_Error(
			'adc_virtual_patch_rest_batch_blocked',
			esc_html__( 'This request was blocked by the ADC Security virtual patch rules.', 'adc-security' ),
			array( 'status' => 403 )
		);
	}

	// -------------------------------------------------------------------------
	// Decision + logging
	// -------------------------------------------------------------------------

	/**
	 * Log a matched rule and, unless monitor mode is on, fail the request.
	 *
	 * @param string $cve    CVE reference the rule covers.
	 * @param string $target Request field or route that matched.
	 * @param string $detail Human-readable reason.
	 * @param bool   $exit   Whether an enforced match ends the request here.
	 * @return bool True when the caller should block the request.
	 */
	private function deny( $cve, $target, $detail, $exit = true ) {
		$enforced = ! $this->is_monitor_mode();

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				self::EVENT_TYPE,
				$enforced ? ADC_Security_Events::SEVERITY_CRITICAL : ADC_Security_Events::SEVERITY_WARNING,
				array(
					'ip'      => class_exists( 'ADC_Security_Ip' ) ? ADC_Security_Ip::get_client_ip() : '',
					'object'  => $cve . ' ' . $target,
					'context' => array(
						'cve'     => $cve,
						'target'  => $target,
						'detail'  => $detail,
						'monitor' => ! $enforced,
					),
				)
			);
		}

		if ( ! $enforced ) {
			return false;
		}

		if ( $exit ) {
			status_header( 403 );
			nocache_headers();
			wp_die(
				esc_html__( 'This request was blocked by the ADC Security virtual patch rules.', 'adc-security' ),
				403,
				array( 'response' => 403 )
			);
		}

		return true;
	}

	// -------------------------------------------------------------------------
	// Pure matchers (unit tested without WordPress)
	// -------------------------------------------------------------------------

	/**
	 * Detect path traversal in a request value, at any encoding depth.
	 *
	 * Traversal always needs a ".." component, so that is the invariant this
	 * checks for instead of one specific exploit string. The value is decoded
	 * repeatedly because CVE-2026-87902 relies on sanitization running before
	 * a late urldecode() — and a legitimate page slug or post name cannot
	 * contain a percent sign, a backslash or two consecutive dots.
	 *
	 * @param mixed $value Raw request value.
	 * @return bool
	 */
	public static function contains_traversal( $value ) {
		if ( ! is_string( $value ) || '' === $value ) {
			return false;
		}

		if ( false !== strpos( $value, "\0" ) ) {
			return true;
		}

		$probe = $value;

		for ( $i = 0; $i < self::MAX_DECODE_PASSES; $i++ ) {
			$decoded = rawurldecode( $probe );

			if ( $decoded === $probe ) {
				break;
			}

			$probe = $decoded;
		}

		return false !== strpos( $probe, '..' );
	}

	/**
	 * Whether one request argument is an author__in / author__not_in injection.
	 *
	 * @param string|int $key   Argument name.
	 * @param mixed      $value Argument value.
	 * @return bool
	 */
	public static function is_author_injection_arg( $key, $value ) {
		if ( ! preg_match( '/^author__(not_)?in$/', (string) $key ) ) {
			return false;
		}

		if ( is_array( $value ) ) {
			return ! empty( $value );
		}

		return '' !== (string) $value;
	}

	/**
	 * Recursively look for an author__in / author__not_in injection inside a
	 * request array (PHP builds nested arrays from bracket notation).
	 *
	 * @param mixed $args  Request array.
	 * @param int   $depth Current recursion depth.
	 * @return bool
	 */
	public static function contains_author_injection_arg( $args, $depth = 0 ) {
		if ( ! is_array( $args ) || $depth > self::MAX_ARG_DEPTH ) {
			return false;
		}

		foreach ( $args as $key => $value ) {
			if ( self::is_author_injection_arg( $key, $value ) ) {
				return true;
			}

			if ( is_array( $value ) && self::contains_author_injection_arg( $value, $depth + 1 ) ) {
				return true;
			}
		}

		return false;
	}
}
