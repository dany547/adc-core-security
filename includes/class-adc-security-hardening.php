<?php
/**
 * ADC Security Hardening Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Hardening {

	/**
	 * Fixed security headers exposed to the admin allowlist.
	 *
	 * @return array<string,array<string,string>>
	 */
	public static function get_security_header_definitions() {
		return array(
			'content_type_options' => array(
				'label'       => 'X-Content-Type-Options',
				'description' => 'Blocks MIME-type sniffing.',
			),
			'frame_options' => array(
				'label'       => 'X-Frame-Options',
				'description' => 'Prevents the site from being framed by other origins.',
			),
			'xss_protection' => array(
				'label'       => 'X-XSS-Protection (legacy)',
				'description' => 'Enables the legacy browser XSS filter where supported.',
			),
			'referrer_policy' => array(
				'label'       => 'Referrer-Policy',
				'description' => 'Limits referrer information sent to other origins.',
			),
			'csp' => array(
				'label'       => 'Content-Security-Policy',
				'description' => 'Controls script, frame, image, font, and connection origins.',
			),
			'permissions_policy' => array(
				'label'       => 'Permissions-Policy',
				'description' => 'Disables sensitive browser features by default.',
			),
			'hsts' => array(
				'label'       => 'Strict-Transport-Security',
				'description' => 'Forces HTTPS in supporting browsers when the request is already HTTPS.',
			),
		);
	}

	/**
	 * Permissions-Policy emitted in standard mode (and when a custom value is empty or invalid).
	 */
	const PERMISSIONS_POLICY_DEFAULT = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()';

	/**
	 * Referrer-Policy emitted when the stored value is missing or not allowlisted.
	 */
	const REFERRER_POLICY_DEFAULT = 'strict-origin-when-cross-origin';

	/**
	 * Valid Referrer-Policy tokens, keyed by token.
	 *
	 * @return array<string,string>
	 */
	public static function get_referrer_policy_options() {
		return array(
			'no-referrer'                     => 'no-referrer - never send a referrer',
			'no-referrer-when-downgrade'      => 'no-referrer-when-downgrade - send a referrer except HTTPS to HTTP',
			'origin'                          => 'origin - scheme, host and port only',
			'origin-when-cross-origin'        => 'origin-when-cross-origin - full URL on the same site, origin elsewhere',
			'same-origin'                     => 'same-origin - send a referrer only to the same site',
			'strict-origin'                   => 'strict-origin - origin only, nothing on HTTPS to HTTP',
			'strict-origin-when-cross-origin' => 'strict-origin-when-cross-origin - recommended',
			'unsafe-url'                      => 'unsafe-url - always send the full URL',
		);
	}

	/**
	 * Resolve the effective CSP mode (off|standard|custom).
	 *
	 * Options saved before 1.12.0 have no csp_mode key; the migration in the core
	 * class normally sets it, this fallback keeps an unmigrated read consistent.
	 *
	 * @param array $options Plugin options.
	 * @return string
	 */
	public static function get_csp_mode( $options ) {
		$options = is_array( $options ) ? $options : array();

		if ( isset( $options['csp_mode'] ) && in_array( $options['csp_mode'], array( 'off', 'standard', 'custom' ), true ) ) {
			return $options['csp_mode'];
		}

		$toggles = isset( $options['security_header_toggles'] ) && is_array( $options['security_header_toggles'] ) ? $options['security_header_toggles'] : array();
		if ( ! in_array( 'csp', $toggles, true ) ) {
			return 'off';
		}

		$custom = isset( $options['security_headers_csp'] ) && is_string( $options['security_headers_csp'] ) ? trim( $options['security_headers_csp'] ) : '';
		return '' !== $custom ? 'custom' : 'standard';
	}

	/**
	 * Validate a custom Permissions-Policy value.
	 *
	 * Accepts comma, semicolon or newline separated entries shaped like
	 * feature=(), feature=(self), feature=(self "https://example.com") or feature=*.
	 *
	 * @param mixed $raw Raw input.
	 * @return array{value: string, errors: string[]}
	 */
	public static function sanitize_permissions_policy( $raw ) {
		$raw    = is_string( $raw ) ? str_replace( array( "\r\n", "\r", "\n" ), ',', $raw ) : '';
		$valid  = array();
		$errors = array();
		$seen   = array();
		$item   = '(?:\*|self|src|"https?://[a-z0-9.\-]+(?::[0-9]{1,5})?")';
		$pattern = '#^([a-z][a-z0-9-]*)=(\*|\(\s*(?:' . $item . '(?:\s+' . $item . ')*)?\s*\))$#';

		foreach ( preg_split( '/[,;]/', $raw ) as $entry ) {
			$entry = trim( strtolower( $entry ) );
			if ( '' === $entry ) {
				continue;
			}

			if ( ! preg_match( $pattern, $entry, $matches ) ) {
				$errors[] = 'Permissions-Policy entry "' . $entry . '" was ignored. Use feature=(), feature=(self) or feature=*.';
				continue;
			}

			if ( isset( $seen[ $matches[1] ] ) ) {
				continue;
			}
			$seen[ $matches[1] ] = true;
			$valid[]             = $matches[1] . '=' . $matches[2];
		}

		return array(
			'value'  => implode( ', ', $valid ),
			'errors' => $errors,
		);
	}

	/**
	 * Options
	 *
	 * @var array
	 */
	private $options;

	/**
	 * CSP policy module.
	 *
	 * @var ADC_Security_Csp_Policy
	 */
	private $csp;

	/**
	 * Constructor.
	 */
	public function __construct( $csp = null ) {
		$this->options = get_option( 'adc_security_options' );
		$this->csp     = $csp instanceof ADC_Security_Csp_Policy ? $csp : new ADC_Security_Csp_Policy();

		if ( ! empty( $this->options['hide_wp_version'] ) ) {
			$this->init_hide_version();
		}

		if ( ! empty( $this->options['disable_xmlrpc'] ) ) {
			$this->init_disable_xmlrpc();
		}

		if ( ! empty( $this->options['disable_file_editor'] ) ) {
			$this->init_disable_file_editor();
		}

		if ( ! empty( $this->options['disable_rest_api'] ) ) {
			$this->init_disable_rest_api();
		}

		if ( ! empty( $this->options['security_headers'] ) ) {
			$this->init_security_headers();
		}

		if ( ! empty( $this->options['prevent_user_enumeration'] ) ) {
			$this->init_user_enumeration_prevention();
		}

		if ( ! empty( $this->options['admin_session_expiration_enabled'] ) ) {
			$this->init_admin_session_expiration();
		}

		if ( ! empty( $this->options['disable_pingbacks'] ) ) {
			$this->init_disable_pingbacks();
		}

		if ( ! empty( $this->options['disable_script_concat'] ) ) {
			$this->init_disable_script_concatenation();
		}

		if ( ! empty( $this->options['alert_admin_username'] ) ) {
			$this->init_admin_username_alert();
		}

		$this->init_auto_updates();
	}

	// -------------------------------------------------------------------------
	// Auto Updates
	// -------------------------------------------------------------------------

	/**
	 * Auto Updates Logic
	 */
	private function init_auto_updates() {
		if ( isset( $this->options['auto_update_plugins'] ) ) {
			switch ( $this->options['auto_update_plugins'] ) {
				case 'enable':
					add_filter( 'auto_update_plugin', '__return_true' );
					break;
				case 'disable':
					add_filter( 'auto_update_plugin', '__return_false' );
					break;
			}
		}

		if ( isset( $this->options['auto_update_themes'] ) ) {
			switch ( $this->options['auto_update_themes'] ) {
				case 'enable':
					add_filter( 'auto_update_theme', '__return_true' );
					break;
				case 'disable':
					add_filter( 'auto_update_theme', '__return_false' );
					break;
			}
		}

		if ( isset( $this->options['auto_update_core'] ) ) {
			switch ( $this->options['auto_update_core'] ) {
				case 'major':
					add_filter( 'allow_major_auto_core_updates', '__return_true' );
					add_filter( 'allow_minor_auto_core_updates', '__return_true' );
					break;
				case 'disable':
					add_filter( 'auto_update_core', '__return_false' );
					break;
			}
		}
	}

	// -------------------------------------------------------------------------
	// Hide WP Version
	// -------------------------------------------------------------------------

	/**
	 * Hide WP Version
	 */
	private function init_hide_version() {
		remove_action( 'wp_head', 'wp_generator' );
		add_filter( 'the_generator', '__return_empty_string' );
	}

	// -------------------------------------------------------------------------
	// Disable XML-RPC
	// -------------------------------------------------------------------------

	/**
	 * Disable XML-RPC
	 */
	private function init_disable_xmlrpc() {
		add_filter( 'xmlrpc_enabled', '__return_false' );
	}

	// -------------------------------------------------------------------------
	// Disable File Editor
	// -------------------------------------------------------------------------

	/**
	 * Disable File Editor
	 */
	private function init_disable_file_editor() {
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
			define( 'DISALLOW_FILE_EDIT', true );
		}
	}

	// -------------------------------------------------------------------------
	// Disable REST API (Public)
	// -------------------------------------------------------------------------

	/**
	 * Disable REST API for non-authenticated users
	 */
	private function init_disable_rest_api() {
		add_filter( 'rest_authentication_errors', function( $result ) {
			if ( ! empty( $result ) ) {
				return $result;
			}
			if ( ! is_user_logged_in() ) {
				return new WP_Error( 'rest_not_logged_in', 'You are not currently logged in.', array( 'status' => 401 ) );
			}
			return $result;
		});
	}

	// -------------------------------------------------------------------------
	// Security Headers
	// -------------------------------------------------------------------------

	/**
	 * Add Security Headers
	 */
	private function init_security_headers() {
		add_action( 'send_headers', function() {
			if ( $this->is_security_header_enabled( 'content_type_options' ) ) {
				header( 'X-Content-Type-Options: nosniff' );
			}
			if ( $this->is_security_header_enabled( 'frame_options' ) ) {
				header( 'X-Frame-Options: SAMEORIGIN' );
			}
			if ( $this->is_security_header_enabled( 'xss_protection' ) ) {
				header( 'X-XSS-Protection: 1; mode=block' );
			}
			if ( $this->is_security_header_enabled( 'referrer_policy' ) ) {
				header( 'Referrer-Policy: ' . $this->get_referrer_policy_value() );
			}

			// CSP is controlled by csp_mode (off|standard|custom), not by a checkbox.
			$this->send_csp_header();

			if ( $this->is_security_header_enabled( 'permissions_policy' ) ) {
				header( 'Permissions-Policy: ' . $this->get_permissions_policy_value() );
			}

			// HSTS: only send when HTTPS is active to avoid issues on HTTP-only sites.
			if ( $this->is_security_header_enabled( 'hsts' ) && is_ssl() ) {
				header( 'Strict-Transport-Security: ' . $this->get_hsts_value() );
			}
		});
	}

	/**
	 * Emit the Content-Security-Policy (or Report-Only) header for the configured mode.
	 */
	private function send_csp_header() {
		$request_uri = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$header      = self::get_csp_header( $this->options, is_admin(), $request_uri, $this->csp );

		if ( null !== $header ) {
			header( $header['name'] . ': ' . $header['value'] );
		}
	}

	/**
	 * Build the Content-Security-Policy header for a request.
	 *
	 * The header emitter and the admin "Header sent right now" preview both call this,
	 * so the preview always shows the header that is actually sent. Returns null when
	 * no CSP header is sent (mode off).
	 *
	 * @param mixed                   $options     Plugin options.
	 * @param bool                    $is_admin    Whether the request is an admin request.
	 * @param string                  $request_uri Request path, used for the dynamic-script decision.
	 * @param ADC_Security_Csp_Policy $csp         Optional policy builder.
	 * @return array{name: string, value: string}|null
	 */
	public static function get_csp_header( $options, $is_admin, $request_uri, $csp = null ) {
		$options = is_array( $options ) ? $options : array();
		$mode    = self::get_csp_mode( $options );
		if ( 'off' === $mode ) {
			return null;
		}

		$csp         = $csp instanceof ADC_Security_Csp_Policy ? $csp : new ADC_Security_Csp_Policy();
		$report_only = ! empty( $options['csp_report_only'] );
		$report_uri  = $report_only && class_exists( 'ADC_Security_Csp_Reports' ) ? ADC_Security_Csp_Reports::report_uri() : '';
		$policy      = '';

		if ( 'custom' === $mode ) {
			$custom = ADC_Security_Csp_Policy::sanitize_policy( isset( $options['security_headers_csp'] ) ? $options['security_headers_csp'] : '' );
			$policy = $custom['value'];
			if ( '' !== $policy && '' !== $report_uri && false === stripos( $policy, 'report-uri' ) ) {
				$policy = rtrim( $policy, '; ' ) . '; report-uri ' . $report_uri . ';';
			}
		}

		// Standard mode, or a custom mode with no usable text: generated policy.
		if ( '' === $policy ) {
			$allow_dynamic_scripts = $csp->allows_dynamic_scripts(
				! empty( $options['csp_dynamic_scripts_compatibility'] ),
				$is_admin,
				$request_uri
			);

			$policy = $csp->build_generated(
				self::read_option_list( $options, 'csp_presets' ),
				self::read_option_list( $options, 'csp_extra_sources' ),
				self::read_option_list( $options, 'csp_removed_defaults' ),
				$allow_dynamic_scripts,
				$report_uri
			);
		}

		return array(
			'name'  => $report_only ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy',
			'value' => trim( preg_replace( '/[\r\n]+/', ' ', $policy ) ),
		);
	}

	/**
	 * Read an array-valued option, tolerating missing or malformed data.
	 *
	 * @param array  $options Plugin options.
	 * @param string $key     Option key.
	 * @return array
	 */
	private static function read_option_list( $options, $key ) {
		return isset( $options[ $key ] ) && is_array( $options[ $key ] ) ? $options[ $key ] : array();
	}

	/**
	 * Referrer-Policy token from the allowlist.
	 *
	 * @return string
	 */
	private function get_referrer_policy_value() {
		$value = isset( $this->options['referrer_policy_value'] ) && is_string( $this->options['referrer_policy_value'] ) ? $this->options['referrer_policy_value'] : '';
		return array_key_exists( $value, self::get_referrer_policy_options() ) ? $value : self::REFERRER_POLICY_DEFAULT;
	}

	/**
	 * Permissions-Policy value: the standard policy, or a validated custom one.
	 *
	 * @return string
	 */
	private function get_permissions_policy_value() {
		$mode = isset( $this->options['permissions_policy_mode'] ) ? $this->options['permissions_policy_mode'] : 'standard';
		if ( 'custom' === $mode ) {
			$custom = self::sanitize_permissions_policy( isset( $this->options['permissions_policy_custom'] ) ? $this->options['permissions_policy_custom'] : '' );
			if ( '' !== $custom['value'] ) {
				return $custom['value'];
			}
		}
		return self::PERMISSIONS_POLICY_DEFAULT;
	}

	/**
	 * Strict-Transport-Security value. Minimum max-age is 300 seconds.
	 *
	 * Preload is only added together with includeSubDomains, as the preload list requires.
	 *
	 * @return string
	 */
	private function get_hsts_value() {
		$max_age = isset( $this->options['hsts_max_age'] ) ? absint( $this->options['hsts_max_age'] ) : 31536000;
		if ( $max_age < 300 ) {
			$max_age = 300;
		}

		$value = 'max-age=' . $max_age;
		$include_subdomains = ! isset( $this->options['hsts_include_subdomains'] ) || ! empty( $this->options['hsts_include_subdomains'] );
		if ( $include_subdomains ) {
			$value .= '; includeSubDomains';
			if ( ! empty( $this->options['hsts_preload'] ) ) {
				$value .= '; preload';
			}
		}

		return $value;
	}

	/**
	 * Check the fixed header allowlist, preserving the old all-enabled behavior
	 * for installs that predate the fine-tuning option.
	 *
	 * @param string $header_key Fixed header key.
	 * @return bool
	 */
	private function is_security_header_enabled( $header_key ) {
		$default_headers = array_values( array_diff( array_keys( self::get_security_header_definitions() ), array( 'csp' ) ) );
		$selected = isset( $this->options['security_header_toggles'] ) && is_array( $this->options['security_header_toggles'] ) ? $this->options['security_header_toggles'] : $default_headers;

		return in_array( $header_key, $selected, true );
	}


	// -------------------------------------------------------------------------
	// User Enumeration Prevention
	// -------------------------------------------------------------------------

	/**
	 * Register hooks to prevent user enumeration.
	 */
	private function init_user_enumeration_prevention() {
		add_action( 'init', array( $this, 'block_author_enumeration' ), 1 );
		add_filter( 'rest_request_before_callbacks', array( $this, 'block_rest_user_enumeration' ), 5, 3 );
	}

	/**
	 * Redirect public author=N queries to the homepage.
	 */
	public function block_author_enumeration() {
		if ( is_user_logged_in() ) {
			return;
		}

		if ( is_admin() ) {
			return;
		}

		if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
			wp_safe_redirect( home_url( '/' ), 302 );
			exit;
		}
	}

	/**
	 * Block REST API access to user endpoints for unauthenticated visitors.
	 *
	 * Uses rest_request_before_callbacks instead of matching REQUEST_URI so the
	 * block cannot be evaded via alternate request forms for the same route
	 * (e.g. the ?rest_route= query var on sites without pretty permalinks,
	 * differing path casing, or a trailing slash) -- $request->get_route()
	 * reflects the route WordPress actually resolved and dispatched to.
	 *
	 * @param mixed            $response Existing response/error.
	 * @param array            $handler  Matched route handler.
	 * @param WP_REST_Request  $request  Current REST request.
	 * @return mixed
	 */
	public function block_rest_user_enumeration( $response, $handler, $request ) {
		if ( ! empty( $response ) ) {
			return $response;
		}

		if ( is_user_logged_in() ) {
			return $response;
		}

		$route = $request instanceof WP_REST_Request ? $request->get_route() : '';

		if ( ! preg_match( '#^/wp/v2/users(/\d+)?$#i', untrailingslashit( $route ) ) ) {
			return $response;
		}

		return new WP_Error( 'rest_user_enumeration_blocked', 'User enumeration is not permitted.', array( 'status' => 403 ) );
	}

	// -------------------------------------------------------------------------
	// Admin Session Expiration
	// -------------------------------------------------------------------------

	/**
	 * Register the auth_cookie_expiration filter.
	 */
	private function init_admin_session_expiration() {
		add_filter( 'auth_cookie_expiration', array( $this, 'filter_admin_cookie_expiration' ), 10, 3 );
	}

	/**
	 * Override the authentication cookie lifetime for administrators.
	 *
	 * @param int      $length    Original cookie lifetime in seconds.
	 * @param int      $user_id   User ID.
	 * @param bool     $remember  Whether "Remember Me" was checked.
	 * @return int
	 */
	public function filter_admin_cookie_expiration( $length, $user_id, $remember ) {
		$user = get_userdata( $user_id );

		if ( ! $user || is_wp_error( $user ) ) {
			return $length;
		}

		if ( is_multisite() ) {
			if ( ! is_super_admin( $user_id ) ) {
				return $length;
			}
		} else {
			if ( ! user_can( $user, 'manage_options' ) ) {
				return $length;
			}
		}

		$days = isset( $this->options['admin_session_expiration_days'] ) ? (int) $this->options['admin_session_expiration_days'] : 7;

		if ( $days < 1 || $days > 30 ) {
			$days = 7;
		}

		return $days * DAY_IN_SECONDS;
	}

	// -------------------------------------------------------------------------
	// Disable Pingbacks
	// -------------------------------------------------------------------------

	/**
	 * Register hooks to disable pingbacks independently of XML-RPC.
	 */
	private function init_disable_pingbacks() {
		add_filter( 'wp_headers', array( $this, 'remove_pingback_header' ) );
		add_filter( 'xmlrpc_methods', array( $this, 'remove_pingback_xmlrpc_methods' ) );
		add_filter( 'option_default_ping_status', array( $this, 'force_default_ping_status_closed' ) );
		add_filter( 'option_default_pingback_flag', '__return_zero' );
	}

	/**
	 * Remove the X-Pingback header advertised to clients.
	 *
	 * @param array $headers Response headers.
	 * @return array
	 */
	public function remove_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/**
	 * Remove pingback methods from the XML-RPC method list.
	 *
	 * @param array $methods Registered XML-RPC methods.
	 * @return array
	 */
	public function remove_pingback_xmlrpc_methods( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	/**
	 * Force the default_ping_status option to the string WordPress core expects.
	 *
	 * @return string
	 */
	public function force_default_ping_status_closed() {
		return 'closed';
	}

	// -------------------------------------------------------------------------
	// Disable Admin Script Concatenation
	// -------------------------------------------------------------------------

	/**
	 * Disable script concatenation in wp-admin.
	 */
	private function init_disable_script_concatenation() {
		if ( ! defined( 'CONCATENATE_SCRIPTS' ) ) {
			define( 'CONCATENATE_SCRIPTS', false );
		}
	}

	// -------------------------------------------------------------------------
	// Default Administrator Username Alert
	// -------------------------------------------------------------------------

	/**
	 * Register the admin notice for a default "admin" username.
	 */
	private function init_admin_username_alert() {
		add_action( 'admin_notices', array( $this, 'render_admin_username_notice' ) );
		add_action( 'admin_post_adc_security_dismiss_admin_username_notice', array( $this, 'handle_dismiss_admin_username_notice' ) );
	}

	/**
	 * Warn administrators when an account still uses the default "admin" username.
	 */
	public function render_admin_username_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id && get_user_meta( $user_id, 'adc_security_dismiss_admin_username_notice', true ) ) {
			return;
		}

		$admin_user = get_user_by( 'login', 'admin' );
		if ( ! $admin_user || ! user_can( $admin_user, 'manage_options' ) ) {
			return;
		}

		$dismiss_url = wp_nonce_url(
			admin_url( 'admin-post.php?action=adc_security_dismiss_admin_username_notice' ),
			'adc_security_dismiss_admin_username_notice'
		);

		echo '<div class="notice notice-warning"><p>' .
			esc_html__( 'ADC Security: an administrator account still uses the default username "admin". This is a common target for brute-force attacks — create a new administrator account with a different username and remove this one.', 'adc-security' ) .
			' <a href="' . esc_url( $dismiss_url ) . '">' . esc_html__( 'Dismiss', 'adc-security' ) . '</a>' .
			'</p></div>';
	}

	/**
	 * Persist the admin-username notice dismissal for the current user.
	 */
	public function handle_dismiss_admin_username_notice() {
		check_admin_referer( 'adc_security_dismiss_admin_username_notice' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		update_user_meta( get_current_user_id(), 'adc_security_dismiss_admin_username_notice', 1 );

		wp_safe_redirect( wp_get_referer() ? wp_get_referer() : admin_url() );
		exit;
	}
}
