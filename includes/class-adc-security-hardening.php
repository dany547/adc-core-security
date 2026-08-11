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
				header( 'Referrer-Policy: strict-origin-when-cross-origin' );
			}

			// CSP: use admin-configured value or a secure restrictive default.
			if ( $this->is_security_header_enabled( 'csp' ) ) {
				$custom_csp = isset( $this->options['security_headers_csp'] ) ? $this->options['security_headers_csp'] : '';
				if ( ! empty( $custom_csp ) ) {
					header( 'Content-Security-Policy: ' . $custom_csp );
				} else {
					// Balanced default: WordPress page builders need inline configuration scripts.
					// Keep eval disabled, allow HTTPS XHR/fetch for third-party integrations,
					// and limit external executable resources to known origins.
					$request_uri = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
					$allow_dynamic_scripts = $this->csp->allows_dynamic_scripts(
						! empty( $this->options['csp_dynamic_scripts_compatibility'] ),
						is_admin(),
						$request_uri
					);

					header( 'Content-Security-Policy: ' . $this->csp->build( '', $allow_dynamic_scripts ) );
				}
			}

			if ( $this->is_security_header_enabled( 'permissions_policy' ) ) {
				header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()' );
			}

			// HSTS: only send when HTTPS is active to avoid issues on HTTP-only sites.
			if ( $this->is_security_header_enabled( 'hsts' ) && is_ssl() ) {
				header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
			}
		});
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
