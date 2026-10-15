<?php
/**
 * ADC Security Firewall Rules
 *
 * WordPress side of the request firewall: reads the rule registry, screens
 * requests with the pure matchers, asks the engine what to do, and enforces
 * or logs the result. It replaces the hooks of ADC_Security_Virtual_Patch.
 *
 * Design rules:
 * - Zero overhead when nothing is active: hooks are only added for rules whose
 *   state is active or monitor.
 * - Fail open: any exception in a guard lets the request through and logs at
 *   most one error per hour.
 * - Every enforced or monitored match goes to the Activity log (event type
 *   'virtual_patch') with rule_id, mode, fingerprint and cve.
 * - A rule that blocks legitimate-looking traffic (logged-in cookie or
 *   same-origin Referer) several times in a minute drops to monitor mode for a
 *   day (safe mode).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Firewall_Rules {

	const OPTION_NAME = 'adc_security_firewall';

	/**
	 * Marker option for the one-time migration from adc_security_options.
	 */
	const DB_OPTION  = 'adc_security_firewall_db';
	const DB_VERSION = 1;

	const EVENT_TYPE = 'virtual_patch';

	const RULE_PAGE_TEMPLATE = 'block_page_template_traversal';
	const RULE_BATCH         = 'block_rest_batch_unauth';
	const RULE_AUTHOR        = 'reject_author_query_injection';
	const RULE_PROBE         = 'block_vulnerability_probes';
	const RULE_SEARCH        = 'limit_anonymous_search';

	const PROBE_THRESHOLD      = 8;
	const PROBE_WINDOW         = 300;
	const PROBE_RETRY_AFTER    = 900;
	const PROBE_MAX_STAMPS     = 20;
	const PROBE_HITS_TRANSIENT = 'adc_fw_probe_hits_';
	const PROBE_TRIP_TRANSIENT = 'adc_fw_probe_trip_';
	const SEARCH_CAPACITY      = 20;
	const SEARCH_REFILL_SECS   = 3;
	const LOG_THROTTLE_SECS    = 60;
	const LOG_THROTTLE_KEY     = 'adc_fw_log_';

	const ALLOWLIST_MAX         = 50;
	const SAFE_MODE_LIMIT       = 5;
	const SAFE_MODE_WINDOW      = 60;
	const SAFE_MODE_MAX_STAMPS  = 20;
	const SAFE_MODE_DURATION    = DAY_IN_SECONDS;
	const MONITOR_STALE_DAYS    = 14;
	const STREAK_TRANSIENT      = 'adc_fw_streak_';
	const ERROR_TRANSIENT       = 'adc_fw_error_logged';
	const BLOCK_COUNT_DAYS      = 7;
	const BLOCK_COUNT_MAX_ROWS  = 5000;

	/**
	 * Active rules for this request: rule_id => state (active|monitor).
	 *
	 * @var array<string,string>
	 */
	private $active = array();

	/**
	 * WordPress version, read once per request.
	 *
	 * @var string
	 */
	private $wp_version = '';

	/**
	 * Per-request cache of the firewall option.
	 *
	 * @var array|null
	 */
	private $options_cache = null;

	/**
	 * Whether the client IP can be trusted, read once per request (null = not read yet).
	 *
	 * @var bool|null
	 */
	private $ip_reliable = null;

	// -------------------------------------------------------------------------
	// Options
	// -------------------------------------------------------------------------

	/**
	 * Stored firewall options merged over the defaults.
	 *
	 * @return array
	 */
	public static function get_options() {
		$stored = get_option( self::OPTION_NAME, array() );

		if ( ! is_array( $stored ) ) {
			$stored = array();
		}

		$options = array_merge( self::get_defaults(), $stored );

		$options['enabled'] = empty( $options['enabled'] ) ? 0 : 1;
		$options['mode']    = 'enforce' === $options['mode'] ? 'enforce' : 'monitor';

		foreach ( array( 'rules', 'allowlist_patterns', 'safe_mode', 'monitor_since' ) as $key ) {
			if ( ! is_array( $options[ $key ] ) ) {
				$options[ $key ] = array();
			}
		}

		return $options;
	}

	/**
	 * @return array Default option values (firewall off, monitor mode).
	 */
	private static function get_defaults() {
		return array(
			'enabled'            => 0,
			'mode'               => 'monitor',
			'rules'              => array(),
			'allowlist_patterns' => array(),
			'safe_mode'          => array(),
			'monitor_since'      => array(),
		);
	}

	/**
	 * Options for the current request, read once.
	 *
	 * @return array
	 */
	private function current_options() {
		if ( null === $this->options_cache ) {
			$this->options_cache = self::get_options();
		}

		return $this->options_cache;
	}

	// -------------------------------------------------------------------------
	// Registration
	// -------------------------------------------------------------------------

	/**
	 * Decide which guards to attach for this request.
	 */
	public function register() {
		$this->maybe_migrate();

		add_filter( 'site_status_tests', array( $this, 'add_site_health_test' ) );

		if ( self::kill_switch() ) {
			return;
		}

		$options          = self::get_options();
		$this->wp_version = (string) get_bloginfo( 'version' );

		$status_options = $this->decision_options( $options );

		$states = array();
		foreach ( ADC_Security_Firewall_Registry::get_rule_ids() as $rule_id ) {
			$status             = ADC_Security_Firewall_Registry::status( $rule_id, $this->wp_version, $status_options );
			$states[ $rule_id ] = $status['state'];
		}

		$this->track_monitor_since( $options, $states );

		foreach ( $states as $rule_id => $state ) {
			if ( ! in_array( $state, array( ADC_Security_Firewall_Registry::STATE_NOT_NEEDED, ADC_Security_Firewall_Registry::STATE_DISABLED ), true ) ) {
				$this->active[ $rule_id ] = $state;
			}
		}

		if ( empty( $this->active ) ) {
			return;
		}

		if ( isset( $this->active[ self::RULE_PAGE_TEMPLATE ] ) ) {
			add_action( 'init', array( $this, 'guard_page_template_traversal' ), 0 );
		}

		if ( isset( $this->active[ self::RULE_AUTHOR ] ) ) {
			add_action( 'init', array( $this, 'guard_author_query_injection' ), 0 );
		}

		if ( isset( $this->active[ self::RULE_BATCH ] ) || isset( $this->active[ self::RULE_AUTHOR ] ) ) {
			add_filter( 'rest_pre_dispatch', array( $this, 'guard_rest' ), 1, 3 );
		}

		if ( isset( $this->active[ self::RULE_PROBE ] ) ) {
			add_action( 'template_redirect', array( $this, 'guard_probe_paths' ), 0 );
		}

		if ( isset( $this->active[ self::RULE_SEARCH ] ) ) {
			add_action( 'pre_get_posts', array( $this, 'guard_anonymous_search' ) );
		}
	}

	/**
	 * Whether the client IP can be trusted. Asks ADC_Security_Ip when it offers
	 * the check; assumes true otherwise.
	 *
	 * @return bool
	 */
	private function ip_reliable() {
		if ( null === $this->ip_reliable ) {
			$this->ip_reliable = self::read_ip_reliable();
		}

		return $this->ip_reliable;
	}

	/**
	 * @return bool
	 */
	private static function read_ip_reliable() {
		if ( method_exists( 'ADC_Security_Ip', 'is_client_ip_reliable' ) ) {
			return (bool) ADC_Security_Ip::is_client_ip_reliable();
		}

		return true;
	}

	/**
	 * Options for registry status and engine decisions: the stored options plus
	 * the request's IP trust state. Never saved back to the database.
	 *
	 * @param array|null $options Options to start from (defaults to the current request's options).
	 * @return array
	 */
	private function decision_options( $options = null ) {
		$options = null === $options ? $this->current_options() : $options;

		$options['ip_unreliable'] = ! $this->ip_reliable();

		return $options;
	}

	/**
	 * Record when each rule started running in monitor mode (for Site Health).
	 *
	 * Writes only when a rule changes state, so this costs nothing on normal requests.
	 *
	 * @param array $options Stored options.
	 * @param array $states  rule_id => state for this request.
	 */
	private function track_monitor_since( array $options, array $states ) {
		$since   = $options['monitor_since'];
		$changed = false;
		$now     = time();

		foreach ( $states as $rule_id => $state ) {
			$monitoring = ADC_Security_Firewall_Registry::STATE_MONITOR === $state && ! empty( $options['enabled'] );

			if ( $monitoring && ! isset( $since[ $rule_id ] ) ) {
				$since[ $rule_id ] = $now;
				$changed           = true;
			} elseif ( ! $monitoring && isset( $since[ $rule_id ] ) ) {
				unset( $since[ $rule_id ] );
				$changed = true;
			}
		}

		if ( $changed ) {
			$options['monitor_since'] = $since;
			update_option( self::OPTION_NAME, $options, false );
			$this->options_cache = $options;
		}
	}

	/**
	 * One-time migration from the virtual patch settings in adc_security_options.
	 *
	 * Old keys are left in place (deprecated), so a downgrade keeps working.
	 */
	public function maybe_migrate() {
		if ( (int) get_option( self::DB_OPTION, 0 ) >= self::DB_VERSION ) {
			return;
		}

		$legacy = get_option( 'adc_security_options', array() );
		$legacy = is_array( $legacy ) ? $legacy : array();

		$legacy_rules = array();
		if ( isset( $legacy['virtual_patch_rules'] ) && is_array( $legacy['virtual_patch_rules'] ) ) {
			$legacy_rules = array_map( 'sanitize_key', array_filter( $legacy['virtual_patch_rules'], 'is_string' ) );
		}
		$legacy_rules = array_values( array_intersect( ADC_Security_Firewall_Registry::get_rule_ids(), $legacy_rules ) );

		if ( ! empty( $legacy_rules ) ) {
			$options = self::get_options();
			$monitor = ! empty( $legacy['virtual_patch_monitor'] );

			foreach ( $legacy_rules as $rule_id ) {
				if ( ! isset( $options['rules'][ $rule_id ] ) ) {
					$options['rules'][ $rule_id ] = $monitor ? 'monitor' : 'on';
				}
			}

			$options['enabled'] = 1;
			update_option( self::OPTION_NAME, $options, false );
		}

		update_option( self::DB_OPTION, self::DB_VERSION, 'yes' );
	}

	// -------------------------------------------------------------------------
	// Skip rules
	// -------------------------------------------------------------------------

	/**
	 * Whether the kill-switch constant is set.
	 *
	 * @return bool
	 */
	private static function kill_switch() {
		return defined( 'ADC_SECURITY_DISABLE_FIREWALL' ) && ADC_SECURITY_DISABLE_FIREWALL;
	}

	/**
	 * @return bool
	 */
	private static function is_cli() {
		return defined( 'WP_CLI' ) && WP_CLI;
	}

	/**
	 * Whether this request is exempt from every rule.
	 *
	 * Exempt: kill switch, WP-CLI, cron, an allowlisted client IP, or a
	 * fingerprint present in the allowlist patterns.
	 *
	 * @param string $fingerprint Fingerprint of the matched value, if any.
	 * @return bool
	 */
	public function should_skip( $fingerprint = '' ) {
		if ( self::kill_switch() || self::is_cli() || wp_doing_cron() ) {
			return true;
		}

		if ( '' !== $fingerprint ) {
			$options = $this->current_options();

			if ( in_array( strtolower( (string) $fingerprint ), $options['allowlist_patterns'], true ) ) {
				return true;
			}
		}

		return $this->ip_allowlisted( ADC_Security_Ip::get_client_ip() );
	}

	/**
	 * Whether an IP matches the plugin-wide IP allowlist (adc_security_options.ip_allowlist).
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function ip_allowlisted( $ip ) {
		if ( '' === $ip ) {
			return false;
		}

		return ADC_Security_Ip::is_allowlisted( $ip );
	}

	// -------------------------------------------------------------------------
	// Guards
	// -------------------------------------------------------------------------

	/**
	 * Screen front-end pagename values for page-template traversal.
	 */
	public function guard_page_template_traversal() {
		if ( is_admin() ) {
			return;
		}

		if ( 'block' === $this->screen( self::RULE_PAGE_TEMPLATE, array( $this, 'find_page_template_traversal' ) ) ) {
			$this->deny_request();
		}
	}

	/**
	 * Screen front-end query arguments for author__in / author__not_in injection.
	 */
	public function guard_author_query_injection() {
		if ( is_admin() ) {
			return;
		}

		if ( 'block' === $this->screen( self::RULE_AUTHOR, array( $this, 'find_author_query_injection' ) ) ) {
			$this->deny_request();
		}
	}

	/**
	 * Count probe-shaped 404s per IP. Once an IP reaches PROBE_THRESHOLD in
	 * PROBE_WINDOW seconds the rule trips for PROBE_RETRY_AFTER seconds: in
	 * enforce mode the next probe-shaped requests get 429. Only requests that
	 * WordPress resolves as 404 and whose path is on the probe list count.
	 * Fails open.
	 */
	public function guard_probe_paths() {
		$retry = 0;

		try {
			if ( is_admin() || is_user_logged_in() || ! is_404() ) {
				return;
			}

			$path = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Matched, never output.

			if ( ! is_string( $path ) || ! ADC_Security_Firewall_Matchers::is_probe_path( $path ) ) {
				return;
			}

			$ip = ADC_Security_Ip::get_client_ip();

			if ( '' === $ip ) {
				return;
			}

			$normalised  = ADC_Security_Firewall_Matchers::normalize_probe_path( $path );
			$fingerprint = ADC_Security_Firewall_Engine::fingerprint( self::RULE_PROBE, $normalised );

			if ( $this->should_skip( $fingerprint ) ) {
				return;
			}

			$hit = array(
				'target' => 'probe_path',
				'value'  => $normalised,
				'detail' => 'Request for a secret file or a known vulnerable path.',
			);

			if ( ! get_transient( self::PROBE_TRIP_TRANSIENT . md5( $ip ) ) ) {
				$hits = $this->record_probe_hit( $ip );

				if ( $hits < self::PROBE_THRESHOLD ) {
					$this->log_throttled(
						self::RULE_PROBE,
						$hit,
						'monitor',
						$fingerprint,
						$ip,
						sprintf( 'Probe 404 %1$d of %2$d within %3$d seconds. Not blocked yet.', $hits, self::PROBE_THRESHOLD, self::PROBE_WINDOW )
					);
					return;
				}

				set_transient( self::PROBE_TRIP_TRANSIENT . md5( $ip ), 1, self::PROBE_RETRY_AFTER );

				$this->log_throttled(
					self::RULE_PROBE,
					$hit,
					'monitor',
					$fingerprint,
					$ip,
					sprintf( 'Probe threshold reached (%1$d probe 404s within %2$d seconds). Further probe requests from this IP are blocked for %3$d minutes in enforce mode.', $hits, self::PROBE_WINDOW, self::PROBE_RETRY_AFTER / MINUTE_IN_SECONDS ),
					true
				);
				return;
			}

			$decision = $this->generic_decision( self::RULE_PROBE, $ip );

			if ( 'block' === $decision['action'] ) {
				$retry = self::PROBE_RETRY_AFTER;
				$this->log_throttled( self::RULE_PROBE, $hit, 'block', $fingerprint, $ip, $decision['reason'] );
			} elseif ( 'monitor' === $decision['action'] ) {
				$this->log_throttled( self::RULE_PROBE, $hit, 'monitor', $fingerprint, $ip, $decision['reason'] );
			}
		} catch ( Throwable $error ) {
			$this->log_error( $error, self::RULE_PROBE );
			return;
		}

		if ( $retry > 0 ) {
			$this->send_too_many_requests( $retry );
		}
	}

	/**
	 * Per-IP token bucket for anonymous front-end searches. Over the limit:
	 * enforce mode answers 429, monitor mode only logs. Fails open.
	 *
	 * @param WP_Query $query Query being prepared.
	 */
	public function guard_anonymous_search( $query ) {
		$retry = 0;

		try {
			if ( is_admin() || is_user_logged_in() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
				return;
			}

			if ( ! ( $query instanceof WP_Query ) || ! $query->is_main_query() || ! $query->is_search() ) {
				return;
			}

			if ( '' === trim( (string) $query->get( 's' ) ) ) {
				return;
			}

			$ip = ADC_Security_Ip::get_client_ip();

			if ( '' === $ip ) {
				return;
			}

			$fingerprint = ADC_Security_Firewall_Engine::fingerprint( self::RULE_SEARCH, 'search' );

			if ( $this->should_skip( $fingerprint ) || ! class_exists( 'ADC_Security_Rate_Limit' ) ) {
				return;
			}

			if ( ADC_Security_Rate_Limit::consume_token( 'search', $ip, self::SEARCH_CAPACITY, self::SEARCH_REFILL_SECS ) ) {
				return;
			}

			$decision = $this->generic_decision( self::RULE_SEARCH, $ip );

			if ( 'block' === $decision['action'] ) {
				$retry = self::SEARCH_REFILL_SECS;
			}

			if ( 'allow' !== $decision['action'] ) {
				$this->log_throttled(
					self::RULE_SEARCH,
					array(
						'target' => 'search',
						'value'  => 'search',
						'detail' => 'More searches than the limit allows.',
					),
					$decision['action'],
					$fingerprint,
					$ip,
					$decision['reason']
				);
			}
		} catch ( Throwable $error ) {
			$this->log_error( $error, self::RULE_SEARCH );
			return;
		}

		if ( $retry > 0 ) {
			$this->send_too_many_requests( $retry );
		}
	}

	/**
	 * Engine decision for a generic rule on an anonymous request from $ip.
	 *
	 * @param string $rule_id Generic rule id.
	 * @param string $ip      Client IP.
	 * @return array{action:string,reason:string}
	 */
	private function generic_decision( $rule_id, $ip ) {
		return ADC_Security_Firewall_Engine::decide(
			array(
				'rule_id'        => $rule_id,
				'wp_version'     => $this->wp_version,
				'logged_in'      => false,
				'can_edit'       => false,
				'is_cli'         => self::is_cli(),
				'is_cron'        => wp_doing_cron(),
				'ip_allowlisted' => $this->ip_allowlisted( $ip ),
				'kill_switch'    => self::kill_switch(),
				'matched'        => true,
			),
			$this->decision_options()
		);
	}

	/**
	 * Add one probe 404 to the IP's sliding window.
	 *
	 * @param string $ip Client IP.
	 * @return int Probe 404s from this IP in the window, including this one. The window is cleared when the threshold is reached.
	 */
	private function record_probe_hit( $ip ) {
		$key    = self::PROBE_HITS_TRANSIENT . md5( $ip );
		$now    = time();
		$stamps = get_transient( $key );
		$stamps = is_array( $stamps ) ? $stamps : array();

		$stamps[] = $now;
		$stamps   = array_slice( $stamps, -self::PROBE_MAX_STAMPS );

		$hits = 0;
		foreach ( $stamps as $stamp ) {
			if ( (int) $stamp >= $now - self::PROBE_WINDOW ) {
				++$hits;
			}
		}

		if ( $hits >= self::PROBE_THRESHOLD ) {
			delete_transient( $key );
			return $hits;
		}

		set_transient( $key, $stamps, self::PROBE_WINDOW );

		return $hits;
	}

	/**
	 * Log a generic-rule match at most once per minute per IP and rule, so a
	 * scanner cannot flood the Activity log. The first match is always logged.
	 *
	 * @param string $rule_id     Generic rule id.
	 * @param array  $hit         Hit array (target, value, detail).
	 * @param string $action      monitor|block.
	 * @param string $fingerprint Match fingerprint.
	 * @param string $ip          Client IP.
	 * @param string $reason      Reason text.
	 * @param bool   $force       Log even inside the throttle window.
	 */
	private function log_throttled( $rule_id, array $hit, $action, $fingerprint, $ip, $reason, $force = false ) {
		$key = self::LOG_THROTTLE_KEY . md5( $rule_id . '|' . $ip );

		if ( ! $force && get_transient( $key ) ) {
			return;
		}

		set_transient( $key, 1, self::LOG_THROTTLE_SECS );

		$this->log_match( self::rule( $rule_id ), $hit, $action, $fingerprint, $ip, $reason );
	}

	/**
	 * Send a 429 response and stop the request.
	 *
	 * @param int $retry_after Seconds until the client may retry.
	 */
	private function send_too_many_requests( $retry_after ) {
		status_header( 429 );
		nocache_headers();
		header( 'Retry-After: ' . (int) $retry_after );
		wp_die(
			esc_html__( 'Too many requests. Please slow down and try again shortly.', 'adc-security' ),
			429,
			array( 'response' => 429 )
		);
	}

	/**
	 * REST guard: unauthenticated batch requests, and invalid author_exclude
	 * values in REST requests and batch sub-requests.
	 *
	 * @param mixed           $result  Short-circuit result from earlier filters.
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request Current REST request.
	 * @return mixed WP_Error when blocked, otherwise the value passed in.
	 */
	public function guard_rest( $result, $server, $request ) {
		if ( null !== $result || ! ( $request instanceof WP_REST_Request ) ) {
			return $result;
		}

		if ( isset( $this->active[ self::RULE_BATCH ] ) ) {
			$action = $this->screen(
				self::RULE_BATCH,
				function () use ( $request ) {
					return $this->find_batch_unauth( $request );
				}
			);

			if ( 'block' === $action ) {
				return $this->rest_denied( 'adc_virtual_patch_rest_batch_blocked' );
			}
		}

		if ( isset( $this->active[ self::RULE_AUTHOR ] ) ) {
			$action = $this->screen(
				self::RULE_AUTHOR,
				function () use ( $request ) {
					return $this->find_author_exclude( $request );
				}
			);

			if ( 'block' === $action ) {
				return $this->rest_denied( 'adc_firewall_author_exclude_blocked' );
			}
		}

		return $result;
	}

	/**
	 * @param string $code WP_Error code.
	 * @return WP_Error
	 */
	private function rest_denied( $code ) {
		return new WP_Error(
			$code,
			esc_html__( 'This request was blocked by the ADC Security virtual patch rules.', 'adc-security' ),
			array( 'status' => 403 )
		);
	}

	/**
	 * Send the 403 page. Called outside screen() so a wp_die() that throws
	 * (test harnesses) is never swallowed by the fail-open handler.
	 */
	private function deny_request() {
		status_header( 403 );
		nocache_headers();
		wp_die(
			esc_html__( 'This request was blocked by the ADC Security virtual patch rules.', 'adc-security' ),
			403,
			array( 'response' => 403 )
		);
	}

	// -------------------------------------------------------------------------
	// Finders (return null, or array(target, value, detail))
	// -------------------------------------------------------------------------

	/**
	 * @return array|null
	 */
	public function find_page_template_traversal() {
		foreach ( array( $_GET, $_POST ) as $source ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Request screening, not a form handler.
			if ( ! isset( $source['pagename'] ) || ! is_string( $source['pagename'] ) ) {
				continue;
			}

			$value = wp_unslash( $source['pagename'] );

			if ( ADC_Security_Firewall_Matchers::contains_traversal( $value ) ) {
				return array(
					'target' => 'pagename',
					'value'  => $value,
					'detail' => 'page-template path traversal',
				);
			}
		}

		return null;
	}

	/**
	 * @return array|null
	 */
	public function find_author_query_injection() {
		foreach ( array( $_GET, $_POST ) as $source ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Request screening, not a form handler.
			if ( ! ADC_Security_Firewall_Matchers::contains_author_injection_arg( $source ) ) {
				continue;
			}

			return array(
				'target' => 'author__not_in',
				'value'  => self::first_author_arg( $source ),
				'detail' => 'WP_Query author argument injection',
			);
		}

		return null;
	}

	/**
	 * @param mixed $args  Request array.
	 * @param int   $depth Recursion depth.
	 * @return string Key=value text of the first author__in / author__not_in argument.
	 */
	private static function first_author_arg( $args, $depth = 0 ) {
		if ( ! is_array( $args ) || $depth > ADC_Security_Firewall_Matchers::MAX_ARG_DEPTH ) {
			return '';
		}

		foreach ( $args as $key => $value ) {
			if ( ADC_Security_Firewall_Matchers::is_author_injection_arg( $key, $value ) ) {
				return (string) $key . '=' . ( is_scalar( $value ) ? (string) $value : wp_json_encode( $value ) );
			}

			if ( is_array( $value ) ) {
				$nested = self::first_author_arg( $value, $depth + 1 );
				if ( '' !== $nested ) {
					return $nested;
				}
			}
		}

		return '';
	}

	/**
	 * @param WP_REST_Request $request Current request.
	 * @return array|null
	 */
	public function find_batch_unauth( $request ) {
		if ( is_user_logged_in() ) {
			return null;
		}

		$route = self::request_route( $request );

		if ( ! ADC_Security_Firewall_Matchers::is_batch_route( $route ) ) {
			return null;
		}

		return array(
			'target' => ADC_Security_Firewall_Matchers::REST_BATCH_ROUTE,
			'value'  => $route,
			'detail' => 'unauthenticated REST batch request',
		);
	}

	/**
	 * @param WP_REST_Request $request Current request.
	 * @return array|null
	 */
	public function find_author_exclude( $request ) {
		$violation = self::author_exclude_violation( (array) $request->get_params() );

		if ( null === $violation && ADC_Security_Firewall_Matchers::is_batch_route( self::request_route( $request ) ) ) {
			$violation = self::batch_author_exclude_violation( $request );
		}

		if ( null === $violation ) {
			return null;
		}

		return array(
			'target' => 'author_exclude',
			'value'  => $violation,
			'detail' => 'author_exclude is not a plain list of integer IDs',
		);
	}

	/**
	 * Return the offending author_exclude value, or null when absent or valid.
	 *
	 * @param array $params Request parameters.
	 * @return string|null
	 */
	private static function author_exclude_violation( array $params ) {
		if ( ! array_key_exists( 'author_exclude', $params ) || null === $params['author_exclude'] ) {
			return null;
		}

		$value = $params['author_exclude'];

		if ( ADC_Security_Firewall_Matchers::is_valid_int_list( $value ) ) {
			return null;
		}

		return is_scalar( $value ) ? (string) $value : (string) wp_json_encode( $value );
	}

	/**
	 * Check author_exclude on every sub-request of a /batch/v1 call.
	 *
	 * @param WP_REST_Request $request Batch request.
	 * @return string|null
	 */
	private static function batch_author_exclude_violation( $request ) {
		$requests = $request->get_param( 'requests' );

		if ( ! is_array( $requests ) ) {
			return null;
		}

		foreach ( $requests as $sub_request ) {
			if ( ! is_array( $sub_request ) ) {
				continue;
			}

			$params = array();

			if ( isset( $sub_request['path'] ) && is_string( $sub_request['path'] ) ) {
				$query = (string) wp_parse_url( $sub_request['path'], PHP_URL_QUERY );

				if ( '' !== $query ) {
					parse_str( $query, $params );
				}
			}

			if ( isset( $sub_request['body'] ) && is_array( $sub_request['body'] ) ) {
				$params = array_merge( $params, $sub_request['body'] );
			}

			$violation = self::author_exclude_violation( $params );

			if ( null !== $violation ) {
				return $violation;
			}
		}

		return null;
	}

	/**
	 * Route the request addresses: ?rest_route= first, then the REQUEST_URI /wp-json/ path,
	 * then the route WordPress resolved.
	 *
	 * @param WP_REST_Request $request Current request.
	 * @return string
	 */
	private static function request_route( $request ) {
		$path = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Parsed by the matcher, never output.
		$route = ADC_Security_Firewall_Matchers::rest_route_from_request( $_GET, is_string( $path ) ? $path : '' ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request screening.

		if ( '' === $route ) {
			$route = (string) $request->get_route();
		}

		return $route;
	}

	// -------------------------------------------------------------------------
	// Decision, logging and safe mode
	// -------------------------------------------------------------------------

	/**
	 * Run a finder and the decision for its hit. Fails open.
	 *
	 * @param string   $rule_id Rule id.
	 * @param callable $finder  Returns null or array(target, value, detail).
	 * @return string allow|monitor|block
	 */
	private function screen( $rule_id, $finder ) {
		try {
			$hit = call_user_func( $finder );

			if ( ! is_array( $hit ) ) {
				return 'allow';
			}

			return $this->process( $rule_id, $hit );
		} catch ( Throwable $error ) {
			$this->log_error( $error, $rule_id );

			return 'allow';
		}
	}

	/**
	 * Decide one hit, apply safe mode, and log it.
	 *
	 * @param string $rule_id Rule id.
	 * @param array  $hit     Finder result.
	 * @return string allow|monitor|block
	 */
	private function process( $rule_id, array $hit ) {
		$rule      = self::rule( $rule_id );
		$logged_in = is_user_logged_in();

		if ( ! empty( $rule['requires_unauth'] ) && $logged_in ) {
			return 'allow';
		}

		$value       = isset( $hit['value'] ) ? (string) $hit['value'] : '';
		$fingerprint = ADC_Security_Firewall_Engine::fingerprint( $rule_id, $value );

		if ( $this->should_skip( $fingerprint ) ) {
			return 'allow';
		}

		$options = $this->current_options();
		$ip      = ADC_Security_Ip::get_client_ip();

		$decision = ADC_Security_Firewall_Engine::decide(
			array(
				'rule_id'        => $rule_id,
				'wp_version'     => $this->wp_version,
				'logged_in'      => $logged_in,
				'can_edit'       => $logged_in && current_user_can( 'edit_posts' ),
				'is_cli'         => self::is_cli(),
				'is_cron'        => wp_doing_cron(),
				'ip_allowlisted' => $this->ip_allowlisted( $ip ),
				'kill_switch'    => self::kill_switch(),
				'matched'        => true,
			),
			$options
		);

		$action = isset( $decision['action'] ) ? (string) $decision['action'] : 'monitor';
		$reason = isset( $decision['reason'] ) ? (string) $decision['reason'] : '';

		if ( 'allow' === $action ) {
			return 'allow';
		}

		if ( 'block' === $action && self::safe_mode_active( $options, $rule_id ) ) {
			$action = 'monitor';
			$reason = 'Safe mode: this rule only monitors until ' . self::safe_mode_until_label( $options, $rule_id ) . '.';
		}

		if ( 'block' === $action && self::has_legitimacy_signals() && $this->record_legitimate_block( $rule_id ) ) {
			$until = time() + self::SAFE_MODE_DURATION;

			$options['safe_mode'][ $rule_id ] = $until;
			update_option( self::OPTION_NAME, $options, false );
			$this->options_cache = $options;

			$this->log_event(
				'firewall_safe_mode',
				ADC_Security_Events::SEVERITY_WARNING,
				$ip,
				$rule_id,
				array(
					'rule_id' => $rule_id,
					'cve'     => (string) $rule['cve'],
					'until'   => $until,
					'reason'  => sprintf( 'The rule blocked legitimate-looking traffic %d times within %d seconds.', self::SAFE_MODE_LIMIT, self::SAFE_MODE_WINDOW ),
				)
			);

			$action = 'monitor';
			$reason = 'Safe mode: this rule switched to monitor for 24 hours after repeated blocks of legitimate-looking traffic.';
		}

		$this->log_match( $rule, $hit, $action, $fingerprint, $ip, $reason );

		return $action;
	}

	/**
	 * Write one virtual_patch event.
	 *
	 * @param array  $rule        Registry rule.
	 * @param array  $hit         Finder result.
	 * @param string $action      allow|monitor|block (never allow here).
	 * @param string $fingerprint Match fingerprint.
	 * @param string $ip          Client IP.
	 * @param string $reason      Engine or safe-mode reason.
	 */
	private function log_match( array $rule, array $hit, $action, $fingerprint, $ip, $reason ) {
		$enforced = 'block' === $action;
		$cve      = (string) $rule['cve'];
		$target   = isset( $hit['target'] ) ? (string) $hit['target'] : '';
		$detail   = isset( $hit['detail'] ) && '' !== $hit['detail'] ? (string) $hit['detail'] : (string) $rule['title'];

		// Generic rules have no CVE; the rule title names the match instead.
		$label = '' !== $cve ? $cve : (string) $rule['title'];

		$this->log_event(
			self::EVENT_TYPE,
			$enforced ? ADC_Security_Events::SEVERITY_CRITICAL : ADC_Security_Events::SEVERITY_WARNING,
			$ip,
			trim( $label . ' ' . $target ),
			array(
				'cve'         => $cve,
				'target'      => $target,
				'detail'      => $detail,
				'monitor'     => ! $enforced,
				'rule_id'     => (string) $rule['id'],
				'mode'        => $enforced ? 'enforce' : 'monitor',
				'fingerprint' => $fingerprint,
				'action'      => $action,
				'reason'      => $reason,
			)
		);
	}

	/**
	 * @param string $type     Event type.
	 * @param int    $severity Severity constant.
	 * @param string $ip       Client IP.
	 * @param string $object   Event object text.
	 * @param array  $context  Context payload.
	 */
	private function log_event( $type, $severity, $ip, $object, array $context ) {
		if ( ! class_exists( 'ADC_Security_Events' ) ) {
			return;
		}

		ADC_Security_Events::log(
			$type,
			$severity,
			array(
				'ip'      => $ip,
				'object'  => $object,
				'context' => $context,
			)
		);
	}

	/**
	 * Log a guard failure at most once per hour.
	 *
	 * @param Throwable $error   Caught error.
	 * @param string    $rule_id Rule being screened.
	 */
	private function log_error( $error, $rule_id ) {
		try {
			if ( get_transient( self::ERROR_TRANSIENT ) ) {
				return;
			}

			set_transient( self::ERROR_TRANSIENT, 1, HOUR_IN_SECONDS );

			$this->log_event(
				'firewall_error',
				ADC_Security_Events::SEVERITY_WARNING,
				'',
				(string) $rule_id,
				array(
					'rule_id' => (string) $rule_id,
					'error'   => substr( get_class( $error ) . ': ' . $error->getMessage(), 0, 200 ),
				)
			);
		} catch ( Throwable $ignored ) {
			// Logging must never break the request.
			unset( $ignored );
		}
	}

	/**
	 * @param array  $options Options.
	 * @param string $rule_id Rule id.
	 * @return bool
	 */
	private static function safe_mode_active( array $options, $rule_id ) {
		return isset( $options['safe_mode'][ $rule_id ] ) && (int) $options['safe_mode'][ $rule_id ] > time();
	}

	/**
	 * @param array  $options Options.
	 * @param string $rule_id Rule id.
	 * @return string Human-readable expiry.
	 */
	private static function safe_mode_until_label( array $options, $rule_id ) {
		return wp_date( 'Y-m-d H:i', (int) $options['safe_mode'][ $rule_id ] );
	}

	/**
	 * Whether the request looks like real use: a logged-in cookie, or a
	 * Referer from this site.
	 *
	 * @return bool
	 */
	private static function has_legitimacy_signals() {
		foreach ( array_keys( $_COOKIE ) as $name ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read only to detect a session.
			if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}

		$referer = isset( $_SERVER['HTTP_REFERER'] ) ? wp_unslash( $_SERVER['HTTP_REFERER'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Host comparison only.
		if ( ! is_string( $referer ) || '' === $referer ) {
			return false;
		}

		$referer_host = strtolower( (string) wp_parse_url( $referer, PHP_URL_HOST ) );
		$site_host    = strtolower( (string) wp_parse_url( home_url(), PHP_URL_HOST ) );

		return '' !== $referer_host && $referer_host === $site_host;
	}

	/**
	 * Record one legitimate-looking block; true when safe mode should start.
	 *
	 * @param string $rule_id Rule id.
	 * @return bool
	 */
	private function record_legitimate_block( $rule_id ) {
		$key    = self::STREAK_TRANSIENT . md5( (string) $rule_id );
		$stamps = get_transient( $key );
		$stamps = is_array( $stamps ) ? $stamps : array();
		$now    = time();

		$stamps[] = $now;
		$stamps   = array_slice( $stamps, -self::SAFE_MODE_MAX_STAMPS );

		if ( ADC_Security_Firewall_Engine::should_enter_safe_mode( $stamps, $now, self::SAFE_MODE_LIMIT, self::SAFE_MODE_WINDOW ) ) {
			delete_transient( $key );
			return true;
		}

		set_transient( $key, $stamps, self::SAFE_MODE_WINDOW );

		return false;
	}

	// -------------------------------------------------------------------------
	// Public helpers (admin screens)
	// -------------------------------------------------------------------------

	/**
	 * Add a fingerprint to the allowlist.
	 *
	 * @param string $fingerprint 16 hex characters.
	 * @return bool False when the fingerprint is malformed or the list is full.
	 */
	public static function allow_fingerprint( $fingerprint ) {
		$fingerprint = strtolower( trim( (string) $fingerprint ) );

		if ( ! preg_match( '/^[a-f0-9]{16}$/', $fingerprint ) ) {
			return false;
		}

		$options = self::get_options();

		if ( in_array( $fingerprint, $options['allowlist_patterns'], true ) ) {
			return true;
		}

		if ( count( $options['allowlist_patterns'] ) >= self::ALLOWLIST_MAX ) {
			return false;
		}

		$options['allowlist_patterns'][] = $fingerprint;
		update_option( self::OPTION_NAME, $options, false );

		return true;
	}

	/**
	 * Most recent virtual_patch events, newest first.
	 *
	 * @param int $limit Maximum rows (1-200).
	 * @return array<int,array{time:string,rule_id:string,cve:string,mode:string,fingerprint:string,ip:string,target:string,detail:string}>
	 */
	public static function get_recent_matches( $limit = 20 ) {
		global $wpdb;

		$limit = max( 1, min( 200, (int) $limit ) );
		$table = ADC_Security_Install::events_table();

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
			$wpdb->prepare( "SELECT event_time, ip, context FROM {$table} WHERE event_type = %s ORDER BY id DESC LIMIT %d", self::EVENT_TYPE, $limit ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
			ARRAY_A
		);

		$matches = array();

		foreach ( (array) $rows as $row ) {
			$context = self::decode_context( $row['context'] );
			$cve     = isset( $context['cve'] ) ? (string) $context['cve'] : '';
			$rule_id = isset( $context['rule_id'] ) ? (string) $context['rule_id'] : self::rule_id_for_cve( $cve );

			if ( isset( $context['mode'] ) ) {
				$mode = (string) $context['mode'];
			} else {
				$mode = empty( $context['monitor'] ) ? 'enforce' : 'monitor';
			}

			$matches[] = array(
				'time'        => (string) $row['event_time'],
				'rule_id'     => $rule_id,
				'cve'         => $cve,
				'mode'        => $mode,
				'fingerprint' => isset( $context['fingerprint'] ) ? (string) $context['fingerprint'] : '',
				'ip'          => (string) $row['ip'],
				'target'      => isset( $context['target'] ) ? (string) $context['target'] : '',
				'detail'      => isset( $context['detail'] ) ? (string) $context['detail'] : '',
			);
		}

		return $matches;
	}

	/**
	 * Blocked (enforced) requests per rule over the last 7 days.
	 *
	 * @return array<string,int> rule_id => count, for every registry rule.
	 */
	public static function get_block_counts_7d() {
		global $wpdb;

		$counts = array_fill_keys( ADC_Security_Firewall_Registry::get_rule_ids(), 0 );
		$table  = ADC_Security_Install::events_table();
		$since  = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - ( self::BLOCK_COUNT_DAYS * DAY_IN_SECONDS ) );

		$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
			$wpdb->prepare( "SELECT context FROM {$table} WHERE event_type = %s AND severity = %d AND event_time >= %s ORDER BY id DESC LIMIT %d", self::EVENT_TYPE, ADC_Security_Events::SEVERITY_CRITICAL, $since, self::BLOCK_COUNT_MAX_ROWS ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
			ARRAY_A
		);

		foreach ( (array) $rows as $row ) {
			$context = self::decode_context( $row['context'] );
			$rule_id = isset( $context['rule_id'] ) ? (string) $context['rule_id'] : self::rule_id_for_cve( isset( $context['cve'] ) ? (string) $context['cve'] : '' );

			if ( isset( $counts[ $rule_id ] ) ) {
				++$counts[ $rule_id ];
			}
		}

		return $counts;
	}

	/**
	 * Registry status with the firewall option and safe mode applied.
	 *
	 * @param string $rule_id Rule id.
	 * @return array{state:string,reason:string}
	 */
	public static function get_effective_status( $rule_id ) {
		$options                  = self::get_options();
		$options['ip_unreliable'] = ! self::read_ip_reliable();
		$status                   = ADC_Security_Firewall_Registry::status( $rule_id, (string) get_bloginfo( 'version' ), $options );

		if ( ADC_Security_Firewall_Registry::STATE_ACTIVE === $status['state'] && self::safe_mode_active( $options, $rule_id ) ) {
			return array(
				'state'  => ADC_Security_Firewall_Registry::STATE_MONITOR,
				'reason' => 'Safe mode: this rule only monitors until ' . self::safe_mode_until_label( $options, $rule_id ) . '. ' . $status['reason'],
			);
		}

		return $status;
	}

	/**
	 * @param string $cve CVE id.
	 * @return string Rule id for that CVE, or ''.
	 */
	private static function rule_id_for_cve( $cve ) {
		foreach ( ADC_Security_Firewall_Registry::all() as $rule_id => $rule ) {
			if ( '' !== $cve && $rule['cve'] === $cve ) {
				return (string) $rule_id;
			}
		}

		return '';
	}

	/**
	 * @param string $rule_id Rule id.
	 * @return array Registry rule, or an empty array.
	 */
	private static function rule( $rule_id ) {
		$rules = ADC_Security_Firewall_Registry::all();

		return isset( $rules[ $rule_id ] ) ? $rules[ $rule_id ] : array( 'id' => $rule_id, 'cve' => '', 'title' => '', 'requires_unauth' => false );
	}

	/**
	 * @param mixed $raw Stored context column.
	 * @return array
	 */
	private static function decode_context( $raw ) {
		if ( ! is_string( $raw ) || '' === $raw ) {
			return array();
		}

		$decoded = json_decode( $raw, true );

		return is_array( $decoded ) ? $decoded : array();
	}

	// -------------------------------------------------------------------------
	// Site Health
	// -------------------------------------------------------------------------

	/**
	 * @param array $tests Site Health direct tests.
	 * @return array
	 */
	public function add_site_health_test( $tests ) {
		$tests['direct']['adc_firewall_rules'] = array(
			'label' => __( 'ADC Firewall Rules', 'adc-security' ),
			'test'  => array( $this, 'site_health_test' ),
		);

		return $tests;
	}

	/**
	 * Site Health result for the firewall.
	 *
	 * Critical: enabled, but every rule that applies to this WordPress version is off.
	 * Recommended: a rule has been in monitor mode for more than 14 days, or safe mode has triggered.
	 * Good: otherwise, including when no rule applies.
	 *
	 * @return array
	 */
	public function site_health_test() {
		$options    = self::get_options();
		$applicable = 0;
		$off        = 0;
		$stale      = false;
		$cutoff     = time() - ( self::MONITOR_STALE_DAYS * DAY_IN_SECONDS );

		foreach ( ADC_Security_Firewall_Registry::get_rule_ids() as $rule_id ) {
			$status = self::get_effective_status( $rule_id );

			// "Every rule is off" is about the CVE rules; generic rules are optional extras.
			if ( ! ADC_Security_Firewall_Registry::is_generic( $rule_id ) ) {
				if ( ADC_Security_Firewall_Registry::STATE_NOT_NEEDED === $status['state'] ) {
					continue;
				}

				++$applicable;

				if ( ADC_Security_Firewall_Registry::STATE_DISABLED === $status['state'] ) {
					++$off;
				}
			}

			if ( ADC_Security_Firewall_Registry::STATE_MONITOR === $status['state'] && isset( $options['monitor_since'][ $rule_id ] ) && (int) $options['monitor_since'][ $rule_id ] < $cutoff ) {
				$stale = true;
			}
		}

		$safe_mode_triggered = ! empty( $options['safe_mode'] );

		if ( $options['enabled'] && $applicable > 0 && $off === $applicable ) {
			$status      = 'critical';
			$label       = __( 'ADC Firewall Rules are enabled but every rule is off', 'adc-security' );
			$description = __( 'The firewall is turned on, but none of the rules that apply to this WordPress version are switched on, so no requests are screened. Turn on the rule for each listed CVE, or turn the firewall off if it is not wanted.', 'adc-security' );
		} elseif ( $stale || $safe_mode_triggered ) {
			$status      = 'recommended';
			$label       = __( 'ADC Firewall Rules need review', 'adc-security' );
			$description = $safe_mode_triggered
				? __( 'A firewall rule switched to monitor mode for a day after it blocked repeated legitimate-looking traffic. Review the Activity log to confirm the blocks were false positives, then allow the fingerprint or keep monitoring.', 'adc-security' )
				: __( 'A firewall rule has been in monitor mode for more than 14 days. Monitor mode logs matches but does not block them. Switch the rule to enforce once the logged matches are reviewed.', 'adc-security' );
		} else {
			$status      = 'good';
			$label       = __( 'ADC Firewall Rules are configured', 'adc-security' );
			$description = $options['enabled']
				? __( 'The firewall is screening requests for the CVEs that apply to this WordPress version.', 'adc-security' )
				: __( 'The firewall is off. It is opt-in, and it is not needed when this WordPress version already includes the fixes.', 'adc-security' );
		}

		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'adc-security' ),
				'color' => 'critical' === $status ? 'red' : 'blue',
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'actions'     => '',
			'test'        => 'adc_firewall_rules',
		);
	}
}
