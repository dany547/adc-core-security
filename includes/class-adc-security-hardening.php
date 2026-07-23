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
			header( 'X-Content-Type-Options: nosniff' );
			header( 'X-Frame-Options: SAMEORIGIN' );
			header( 'X-XSS-Protection: 1; mode=block' );
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );

			// CSP: use admin-configured value or a secure restrictive default.
			$custom_csp = isset( $this->options['security_headers_csp'] ) ? $this->options['security_headers_csp'] : '';
			if ( ! empty( $custom_csp ) ) {
				header( 'Content-Security-Policy: ' . $custom_csp );
			} else {
				// Balanced default: WordPress page builders need inline configuration scripts.
				// Keep eval disabled, allow HTTPS XHR/fetch for third-party integrations,
				// and limit external executable resources to known origins.
				header( "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.googletagmanager.com https://googleads.g.doubleclick.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https:; frame-src 'self' https://challenges.cloudflare.com https://maps.google.com https://www.google.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none';" );
			}

			header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()' );

			// HSTS: only send when HTTPS is active to avoid issues on HTTP-only sites.
			if ( is_ssl() ) {
				header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
			}
		});
	}

	// -------------------------------------------------------------------------
	// User Enumeration Prevention
	// -------------------------------------------------------------------------

	/**
	 * Register hooks to prevent user enumeration.
	 */
	private function init_user_enumeration_prevention() {
		add_action( 'init', array( $this, 'block_author_enumeration' ), 1 );
		add_filter( 'rest_authentication_errors', array( $this, 'block_rest_user_enumeration' ), 5 );
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
	 * Priority 5 runs before the default 10, so this fires before the
	 * full-REST-disable filter. If disable_rest_api already returned an
	 * error we respect it and do not add a second one.
	 *
	 * @param mixed $result Existing authentication result.
	 * @return mixed
	 */
	public function block_rest_user_enumeration( $result ) {
		if ( ! empty( $result ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';

		if ( ! preg_match( '#/wp-json/wp/v2/users(/\d+)?#i', $request_uri ) ) {
			return $result;
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
}
