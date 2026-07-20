<?php
/**
 * ADC Security Login Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Login {

	/**
	 * Options
	 *
	 * @var array
	 */
	private $options;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->options = get_option( 'adc_security_options' );

		if ( ! empty( $this->options['custom_login_slug'] ) ) {
			$this->init_custom_login();
		}

		if ( ! empty( $this->options['brute_force_protection'] ) ) {
			$this->init_brute_force_protection();
		}

		$this->init_login_success_notification();
		$this->init_ip_access_control();
	}

	// -------------------------------------------------------------------------
	// IP helpers
	// -------------------------------------------------------------------------

	/**
	 * Return the validated client IP from REMOTE_ADDR or empty string.
	 *
	 * @return string
	 */
	private function get_client_ip() {
		if ( empty( $_SERVER['REMOTE_ADDR'] ) ) {
			return '';
		}

		$ip = trim( $_SERVER['REMOTE_ADDR'] );

		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return $ip;
		}

		return '';
	}

	/**
	 * Validate and canonise a single IP or CIDR rule.
	 *
	 * @param string $rule Raw rule string.
	 * @return string|false Normalised rule or false on failure.
	 */
	public function normalize_ip_rule( $rule ) {
		$rule = trim( $rule );

		if ( '' === $rule ) {
			return false;
		}

		if ( strpos( $rule, '/' ) !== false ) {
			$parts = explode( '/', $rule, 2 );
			$addr  = $parts[0];
			$cidr  = (int) $parts[1];

			if ( ! filter_var( $addr, FILTER_VALIDATE_IP ) ) {
				return false;
			}

			$packed = @inet_pton( $addr );
			if ( false === $packed ) {
				return false;
			}

			$bits = strlen( $packed ) * 8;

			if ( $cidr < 0 || $cidr > $bits ) {
				return false;
			}

			return $addr . '/' . $cidr;
		}

		if ( ! filter_var( $rule, FILTER_VALIDATE_IP ) ) {
			return false;
		}

		return $rule;
	}

	/**
	 * Check whether a single IP matches a rule (IP or CIDR).
	 *
	 * @param string $ip   Client IP.
	 * @param string $rule IP or CIDR rule.
	 * @return bool
	 */
	private function ip_matches_rule( $ip, $rule ) {
		if ( strpos( $rule, '/' ) !== false ) {
			$parts = explode( '/', $rule, 2 );
			$net   = $parts[0];
			$cidr  = (int) $parts[1];

			$ip_bin     = @inet_pton( $ip );
			$net_bin    = @inet_pton( $net );

			if ( false === $ip_bin || false === $net_bin ) {
				return false;
			}

			$mask = -1 << ( 32 - $cidr );
			// IPv6: work with packed binary directly for the mask length.
			if ( strlen( $ip_bin ) === 16 ) {
				// Create a mask for IPv6.
				$mask_bits = str_repeat( "\xff", intdiv( $cidr, 8 ) );
				$remainder = $cidr % 8;
				if ( $remainder > 0 ) {
					$mask_bits .= chr( 0xff << ( 8 - $remainder ) );
				}
				$mask_bits .= str_repeat( "\x00", 16 - strlen( $mask_bits ) );

				return ( $ip_bin & $mask_bits ) === ( $net_bin & $mask_bits );
			}

			// IPv4
			$mask_bin = pack( 'N', $mask );

			return ( $ip_bin & $mask_bin ) === ( $net_bin & $mask_bin );
		}

		return $ip === $rule;
	}

	/**
	 * Check whether an IP matches any rule in a list.
	 *
	 * @param string $ip    Client IP.
	 * @param array  $rules Array of normalised rules.
	 * @return bool
	 */
	private function ip_matches_list( $ip, $rules ) {
		foreach ( $rules as $rule ) {
			if ( $this->ip_matches_rule( $ip, $rule ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Parse a textarea-style list into normalised unique rules.
	 *
	 * @param string $raw Newline-separated rules.
	 * @return array
	 */
	private function parse_ip_list( $raw ) {
		$lines = array_map( 'trim', explode( "\n", $raw ) );
		$rules = array();
		$seen  = array();

		foreach ( $lines as $line ) {
			$norm = $this->normalize_ip_rule( $line );
			if ( false === $norm ) {
				continue;
			}
			if ( ! isset( $seen[ $norm ] ) ) {
				$seen[ $norm ] = true;
				$rules[]       = $norm;
			}
		}

		return $rules;
	}

	// -------------------------------------------------------------------------
	// IP Access Control (allowlist / denylist)
	// -------------------------------------------------------------------------

	/**
	 * Register the IP access control check early in init.
	 */
	private function init_ip_access_control() {
		add_action( 'init', array( $this, 'evaluate_ip_access' ), 1 );
	}

	/**
	 * Evaluate allowlist / denylist for the current request.
	 */
	public function evaluate_ip_access() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		if ( wp_doing_cron() ) {
			return;
		}

		if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
			// Allow AJAX to proceed; wp-admin checks will gate access.
		}

		// WordPress automatic update endpoint from CLI context.
		if ( defined( 'DOING_UPGRADE' ) && DOING_UPGRADE && ! empty( $_GET['step'] ) ) {
			return;
		}

		$ip = $this->get_client_ip();
		if ( '' === $ip ) {
			return;
		}

		$allow_rules = $this->parse_ip_list( isset( $this->options['ip_allowlist'] ) ? $this->options['ip_allowlist'] : '' );
		$deny_rules  = $this->parse_ip_list( isset( $this->options['ip_denylist'] ) ? $this->options['ip_denylist'] : '' );

		// Allowlist takes priority.
		if ( ! empty( $allow_rules ) && $this->ip_matches_list( $ip, $allow_rules ) ) {
			return;
		}

		if ( ! empty( $deny_rules ) && $this->ip_matches_list( $ip, $deny_rules ) ) {
			status_header( 403 );
			nocache_headers();
			echo '403 Forbidden';
			exit;
		}
	}

	/**
	 * Check whether an IP is in the allowlist.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function is_ip_allowlisted( $ip ) {
		if ( '' === $ip ) {
			return false;
		}

		$allow_rules = $this->parse_ip_list( isset( $this->options['ip_allowlist'] ) ? $this->options['ip_allowlist'] : '' );

		return ! empty( $allow_rules ) && $this->ip_matches_list( $ip, $allow_rules );
	}

	// -------------------------------------------------------------------------
	// Login success notification
	// -------------------------------------------------------------------------

	/**
	 * Register wp_login hook for admin success notifications.
	 */
	private function init_login_success_notification() {
		add_action( 'wp_login', array( $this, 'handle_login_success' ), 10, 2 );
	}

	/**
	 * Send an email when an administrator logs in successfully.
	 *
	 * @param string     $user_login Username.
	 * @param WP_User    $user       User object.
	 */
	public function handle_login_success( $user_login, $user ) {
		if ( empty( $this->options['login_success_notification'] ) ) {
			return;
		}

		if ( ! is_a( $user, 'WP_User' ) || ! is_user_logged_in() ) {
			return;
		}

		if ( ! is_multisite() ) {
			if ( ! user_can( $user, 'manage_options' ) ) {
				return;
			}
		} else {
			if ( ! is_super_admin( $user->ID ) ) {
				return;
			}
		}

		$ip      = $this->get_client_ip();
		$agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 200 ) : 'Unknown';
		$now     = current_time( 'mysql' );
		$display = ! empty( $user->display_name ) ? $user->display_name : $user_login;

		$subject = 'ADC Security: Administrator login detected';

		$message  = "Administrator login detected.\n\n";
		$message .= "User: {$display}\n";
		$message .= "Time: {$now}\n";
		$message .= "IP: {$ip}\n";
		$message .= "User Agent: {$agent}\n";

		$result = wp_mail( get_option( 'admin_email' ), $subject, $message );

		if ( ! $result && class_exists( 'ADC_Security_Logger' ) ) {
			$logger = new ADC_Security_Logger();
			$logger->log( 'Failed to send admin login notification email for user: ' . $user_login, 'ERROR' );
		}
	}

	// -------------------------------------------------------------------------
	// Custom Login URL
	// -------------------------------------------------------------------------

	/**
	 * Init Custom Login URL
	 */
	private function init_custom_login() {
		add_action( 'init', array( $this, 'add_login_rewrite_rule' ) );
		add_filter( 'query_vars', array( $this, 'add_login_query_var' ) );
		add_action( 'template_redirect', array( $this, 'handle_custom_login' ), 1 );

		add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
		add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 3 );
		add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );

		add_action( 'init', array( $this, 'block_wp_login' ) );
		add_action( 'init', array( $this, 'block_wp_admin' ) );
		add_action( 'init', array( $this, 'maybe_flush_rewrite_rules' ), 999 );
		add_action( 'parse_request', array( $this, 'check_custom_login_request' ) );
	}

	/**
	 * Fallback to detect custom login slug if rewrite rules fail.
	 *
	 * @param WP $wp Current WordPress environment instance.
	 */
	public function check_custom_login_request( $wp ) {
		if ( isset( $wp->query_vars['adc_login'] ) ) {
			return;
		}

		$slug = isset( $this->options['custom_login_slug'] ) ? $this->options['custom_login_slug'] : '';
		if ( empty( $slug ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
		$home_path   = parse_url( home_url(), PHP_URL_PATH );

		if ( $home_path && '/' !== $home_path ) {
			$request_uri = preg_replace( '#^' . preg_quote( $home_path, '#' ) . '#', '', $request_uri );
		}

		$request_path = strtok( $request_uri, '?' );
		$request_path = trim( $request_path, '/' );

		if ( $request_path === $slug ) {
			$wp->query_vars['adc_login'] = 1;
		}
	}

	/**
	 * Maybe Flush Rewrite Rules
	 */
	public function maybe_flush_rewrite_rules() {
		if ( get_transient( 'adc_security_flush_rewrite_rules' ) ) {
			delete_transient( 'adc_security_flush_rewrite_rules' );
			flush_rewrite_rules();
		}
	}

	public function add_login_rewrite_rule() {
		$slug = $this->options['custom_login_slug'];
		add_rewrite_rule( '^' . $slug . '/?$', 'index.php?adc_login=1', 'top' );
	}

	public function add_login_query_var( $vars ) {
		$vars[] = 'adc_login';
		return $vars;
	}

	/**
	 * Handle the custom login request processing
	 */
	public function handle_custom_login() {
		if ( get_query_var( 'adc_login' ) || isset( $_GET['adc_login'] ) ) {
			$file = ABSPATH . 'wp-login.php';
			if ( file_exists( $file ) ) {
				global $user_login, $user_identity, $error, $action;

				if ( ! isset( $user_login ) ) $user_login = '';
				if ( ! isset( $error ) ) $error = '';

				status_header( 200 );

				include $file;
				exit;
			}
		}
	}

	public function filter_site_url( $url, $path, $scheme, $blog_id = null ) {
		return $this->replace_login_url( $url, $scheme );
	}

	public function filter_wp_redirect( $location, $status ) {
		return $this->replace_login_url( $location );
	}

	private function replace_login_url( $url, $scheme = null ) {
		if ( empty( $this->options['custom_login_slug'] ) ) {
			return $url;
		}

		if ( strpos( $url, 'wp-login.php' ) !== false && ! empty( $this->options['custom_login_slug'] ) ) {
			$slug       = $this->options['custom_login_slug'];
			$parsed_url = parse_url( $url );
			$query      = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';

			$new_url = home_url( '/' . $slug . '/' . $query, $scheme );
			return $new_url;
		}
		return $url;
	}

	public function block_wp_login() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( strpos( $request_uri, 'wp-login.php' ) !== false && ! isset( $_REQUEST['adc_login'] ) ) {
			if ( defined( 'DOING_AJAX' ) || ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) ) {
				return;
			}

			wp_safe_redirect( home_url() );
			exit;
		}
	}

	public function block_wp_admin() {
		if ( is_admin() && ! is_user_logged_in() && ! defined( 'DOING_AJAX' ) ) {
			$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
			if ( strpos( $request_uri, 'admin-post.php' ) !== false ) {
				return;
			}

			wp_safe_redirect( home_url() );
			exit;
		}
	}

	// -------------------------------------------------------------------------
	// Brute Force
	// -------------------------------------------------------------------------

	/**
	 * Init Brute Force Protection
	 */
	private function init_brute_force_protection() {
		add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
		add_filter( 'authenticate', array( $this, 'check_login_attempts' ), 30, 3 );
	}

	public function handle_failed_login( $username ) {
		$ip = $this->get_client_ip();
		if ( '' === $ip ) {
			return;
		}

		if ( $this->is_ip_allowlisted( $ip ) ) {
			return;
		}

		$transient_name = 'adc_bf_' . md5( $ip );
		$attempts       = get_transient( $transient_name );

		if ( ! $attempts ) {
			$attempts = 0;
		}
		$attempts++;

		$max_attempts    = ! empty( $this->options['bf_max_attempts'] ) ? (int) $this->options['bf_max_attempts'] : 5;
		$lockout_duration = ! empty( $this->options['bf_lockout_duration'] ) ? (int) $this->options['bf_lockout_duration'] : 60;
		$expiration      = $lockout_duration * MINUTE_IN_SECONDS;

		set_transient( $transient_name, $attempts, $expiration );

		if ( $attempts === $max_attempts ) {
			$locked_ips          = get_option( 'adc_locked_ips', array() );
			$locked_ips[ $ip ]   = time() + $expiration;
			update_option( 'adc_locked_ips', $locked_ips );

			if ( ! empty( $this->options['login_notification'] ) ) {
				$admin_email = get_option( 'admin_email' );
				$subject     = 'ADC Security: Failed Login Alert';
				$message     = sprintf(
					'Too many failed login attempts detected from IP: %s' . "\r\n" .
					'Username tried: %s' . "\r\n" .
					'Time: %s',
					$ip,
					$username,
					current_time( 'mysql' )
				);
				wp_mail( $admin_email, $subject, $message );
			}
		}
	}

	public function check_login_attempts( $user, $username, $password ) {
		$ip = $this->get_client_ip();
		if ( '' === $ip ) {
			return $user;
		}

		if ( $this->is_ip_allowlisted( $ip ) ) {
			return $user;
		}

		$transient_name    = 'adc_bf_' . md5( $ip );
		$attempts          = get_transient( $transient_name );
		$max_attempts      = ! empty( $this->options['bf_max_attempts'] ) ? (int) $this->options['bf_max_attempts'] : 5;
		$lockout_duration  = ! empty( $this->options['bf_lockout_duration'] ) ? (int) $this->options['bf_lockout_duration'] : 60;

		if ( $attempts && $attempts >= $max_attempts ) {
			return new WP_Error( 'too_many_attempts', sprintf( 'Too many failed login attempts. Please try again in %d minutes.', $lockout_duration ) );
		}

		return $user;
	}

	/**
	 * Unblock an IP address.
	 *
	 * @param string $ip IP Address.
	 */
	public function unblock_ip( $ip ) {
		$transient_name = 'adc_bf_' . md5( $ip );
		delete_transient( $transient_name );

		$locked_ips = get_option( 'adc_locked_ips', array() );
		if ( isset( $locked_ips[ $ip ] ) ) {
			unset( $locked_ips[ $ip ] );
			update_option( 'adc_locked_ips', $locked_ips );
		}
	}
}
