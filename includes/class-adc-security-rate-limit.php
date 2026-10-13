<?php
/**
 * ADC Security Rate Limit Class
 *
 * Lightweight per-IP token bucket over transients, applied to the request
 * surfaces most commonly hammered by bots: wp-login.php POSTs, xmlrpc.php,
 * ?author= enumeration, and unauthenticated REST reads/writes to sensitive
 * routes. Complements (does not replace) the brute-force lockout in
 * ADC_Security_Login, which tracks failed *credentials* rather than raw
 * request volume.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Rate_Limit {

	/**
	 * Per-scope bucket definitions: capacity (max burst) and refill rate
	 * (seconds per token regenerated).
	 *
	 * @var array
	 */
	private static $buckets = array(
		'login'       => array(
			'capacity'    => 20,
			'refill_secs' => 6,
		),
		'xmlrpc'      => array(
			'capacity'    => 20,
			'refill_secs' => 6,
		),
		'author_scan' => array(
			'capacity'    => 30,
			'refill_secs' => 4,
		),
		'rest_read'   => array(
			'capacity'    => 60,
			'refill_secs' => 2,
		),
		'rest_write'  => array(
			'capacity'    => 20,
			'refill_secs' => 6,
		),
	);

	/**
	 * @var ADC_Security_Login|null Used only for is_ip_allowlisted() reuse.
	 */
	private $login;

	public function __construct( ?ADC_Security_Login $login = null ) {
		$this->login = $login instanceof ADC_Security_Login ? $login : new ADC_Security_Login();

		add_action( 'init', array( $this, 'guard_login_and_xmlrpc' ), 0 );
		add_action( 'parse_request', array( $this, 'guard_author_scan' ) );
		add_filter( 'rest_pre_dispatch', array( $this, 'guard_rest' ), 5, 3 );
	}

	/**
	 * @return bool Whether rate limiting is enabled in settings (default on).
	 */
	private function is_enabled() {
		$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		return ! isset( $options['rate_limiting_enabled'] ) || ! empty( $options['rate_limiting_enabled'] );
	}

	/**
	 * Guard wp-login.php POST requests and xmlrpc.php requests.
	 */
	public function guard_login_and_xmlrpc() {
		if ( ! $this->is_enabled() ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
		$method      = isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( $_SERVER['REQUEST_METHOD'] ) : 'GET';

		if ( 'POST' === $method && false !== strpos( $request_uri, 'wp-login.php' ) ) {
			$this->enforce( 'login' );
			return;
		}

		if ( false !== strpos( $request_uri, 'xmlrpc.php' ) ) {
			$this->enforce( 'xmlrpc' );
		}
	}

	/**
	 * Guard ?author=N enumeration requests on the frontend.
	 */
	public function guard_author_scan() {
		if ( ! $this->is_enabled() || is_admin() ) {
			return;
		}

		if ( isset( $_GET['author'] ) && '' !== $_GET['author'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$this->enforce( 'author_scan' );
		}
	}

	/**
	 * Guard unauthenticated REST requests: reads to sensitive routes and any write.
	 *
	 * @param mixed           $result  Short-circuit result, passed through unchanged.
	 * @param WP_REST_Server  $server  REST server instance.
	 * @param WP_REST_Request $request Current REST request.
	 * @return mixed
	 */
	public function guard_rest( $result, $server, $request ) {
		if ( ! $this->is_enabled() || is_user_logged_in() ) {
			return $result;
		}

		$method = $request->get_method();
		$route  = $request->get_route();

		// CSP violation reports come from browsers and have their own per-IP bucket.
		if ( '/adc-security/v1/csp-report' === $route ) {
			return $result;
		}

		$sensitive_read = 'GET' === $method && ( 0 === strpos( $route, '/wp/v2/users' ) );
		$write          = in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true );

		if ( $sensitive_read ) {
			$this->enforce( 'rest_read' );
		} elseif ( $write ) {
			$this->enforce( 'rest_write' );
		}

		return $result;
	}

	/**
	 * Consume a token from the given bucket for the current IP, or fail the
	 * request with 429 if none are available. Allowlisted IPs always pass.
	 *
	 * @param string $scope One of the keys in self::$buckets.
	 */
	private function enforce( $scope ) {
		$ip = ADC_Security_Ip::get_client_ip();
		if ( '' === $ip || $this->login->is_ip_allowlisted( $ip ) ) {
			return;
		}

		if ( $this->consume( $scope, $ip ) ) {
			return;
		}

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				'rate_limited',
				ADC_Security_Events::SEVERITY_WARNING,
				array(
					'ip'     => $ip,
					'object' => $scope,
				)
			);
		}

		status_header( 429 );
		nocache_headers();
		header( 'Retry-After: ' . (int) self::$buckets[ $scope ]['refill_secs'] );
		wp_die( esc_html__( 'Too many requests. Please slow down and try again shortly.', 'adc-security' ), 429, array( 'response' => 429 ) );
	}

	/**
	 * Try to consume one token from $scope's bucket for $ip.
	 *
	 * @param string $scope Bucket scope key.
	 * @param string $ip    Client IP.
	 * @return bool True if a token was available and consumed.
	 */
	private function consume( $scope, $ip ) {
		$config = self::$buckets[ $scope ];

		return self::consume_token( $scope, $ip, $config['capacity'], $config['refill_secs'] );
	}

	/**
	 * Consume one token from a named bucket for an IP, for callers outside the
	 * fixed scopes above (for example the firewall's search limit). Same
	 * transient storage and arithmetic as the built-in buckets.
	 *
	 * @param string $name        Bucket name, unique per feature.
	 * @param string $ip          Client IP (must be non-empty).
	 * @param int    $capacity    Maximum burst, in tokens.
	 * @param int    $refill_secs Seconds per regenerated token.
	 * @return bool True if a token was available and consumed.
	 */
	public static function consume_token( $name, $ip, $capacity, $refill_secs ) {
		$capacity    = max( 1, (int) $capacity );
		$refill_secs = max( 1, (int) $refill_secs );
		$key         = 'adc_rl_' . $name . '_' . md5( $ip );
		$step        = self::step( get_transient( $key ), microtime( true ), $capacity, $refill_secs );

		set_transient( $key, $step['bucket'], $capacity * $refill_secs );

		return $step['allowed'];
	}

	/**
	 * Pure bucket step: refill the stored bucket for the time elapsed, then
	 * take one token if one is available. Unit tested in tests/test-rate-limit.php.
	 *
	 * @param mixed $bucket      Stored bucket array (tokens, updated), or anything else for a new bucket.
	 * @param float $now         Current time in seconds.
	 * @param int   $capacity    Maximum tokens.
	 * @param int   $refill_secs Seconds per token.
	 * @return array{bucket:array,allowed:bool} Updated bucket and whether a token was taken.
	 */
	public static function step( $bucket, $now, $capacity, $refill_secs ) {
		if ( ! is_array( $bucket ) || ! isset( $bucket['tokens'], $bucket['updated'] ) ) {
			$bucket = array(
				'tokens'  => $capacity,
				'updated' => $now,
			);
		}

		$elapsed = max( 0, $now - $bucket['updated'] );
		$tokens  = self::refill( $bucket['tokens'], $elapsed, $capacity, $refill_secs );

		$allowed = $tokens >= 1;
		if ( $allowed ) {
			$tokens -= 1;
		}

		return array(
			'bucket'  => array(
				'tokens'  => $tokens,
				'updated' => $now,
			),
			'allowed' => $allowed,
		);
	}

	/**
	 * Pure token-bucket refill calculation, exposed publicly so it can be
	 * unit tested without a WordPress environment (tests/test-rate-limit.php).
	 *
	 * @param float $tokens      Current token count.
	 * @param float $elapsed     Seconds elapsed since the bucket was last updated.
	 * @param int   $capacity    Maximum tokens the bucket can hold.
	 * @param int   $refill_secs Seconds required to regenerate one token.
	 * @return float New token count, capped at $capacity.
	 */
	public static function refill( $tokens, $elapsed, $capacity, $refill_secs ) {
		$regenerated = max( 0, $elapsed ) / max( 1, $refill_secs );
		return min( $capacity, $tokens + $regenerated );
	}
}
