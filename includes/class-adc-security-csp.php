<?php
/**
 * Content-Security-Policy builder.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Csp_Policy {

	/**
	 * Build the configured policy or the safe default policy.
	 *
	 * @param string $custom_policy Custom policy from the administrator.
	 * @param bool   $allow_dynamic_scripts Whether frontend dynamic compilation is enabled.
	 * @return string
	 */
	public function build( $custom_policy, $allow_dynamic_scripts = false ) {
		if ( ! empty( $custom_policy ) ) {
			return $custom_policy;
		}

		$script_src = "'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.googletagmanager.com https://googleads.g.doubleclick.net";
		if ( $allow_dynamic_scripts ) {
			$script_src .= " 'unsafe-eval'";
		}

		return "default-src 'self'; script-src {$script_src}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https:; frame-src 'self' https://challenges.cloudflare.com https://maps.google.com https://www.google.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none';";
	}

	/**
	 * Decide whether dynamic script compatibility can be used for this request.
	 *
	 * Fails closed for admin, login, REST, and malformed request paths.
	 *
	 * @param bool   $enabled Whether the administrator enabled compatibility.
	 * @param bool   $is_admin Whether WordPress considers this an admin request.
	 * @param string $request_uri Raw request URI.
	 * @return bool
	 */
	public function allows_dynamic_scripts( $enabled, $is_admin, $request_uri ) {
		if ( ! $enabled || $is_admin || ! is_string( $request_uri ) || '' === $request_uri ) {
			return false;
		}

		$path = parse_url( $request_uri, PHP_URL_PATH );
		if ( ! is_string( $path ) || '' === $path ) {
			return false;
		}

		$path = '/' . ltrim( strtolower( $path ), '/' );

		if ( '/wp-login.php' === $path || 0 === strpos( $path, '/wp-admin/' ) || '/wp-admin' === $path ) {
			return false;
		}

		if ( '/wp-json' === $path || 0 === strpos( $path, '/wp-json/' ) ) {
			return false;
		}

		return true;
	}
}
