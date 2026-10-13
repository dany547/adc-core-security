<?php
/**
 * ADC Security IP Helper Class
 *
 * Single source of truth for "what is the client's IP". Every IP-based
 * feature (brute-force lockout, denylist, rate limiting, audit log, captcha)
 * should read the address through here instead of $_SERVER['REMOTE_ADDR']
 * directly, so that sites behind a trusted reverse proxy / CDN (Cloudflare,
 * a load balancer, etc.) see the real visitor IP everywhere at once instead
 * of the proxy's IP.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Ip {

	/**
	 * Resolve the client IP for the current request.
	 *
	 * By default this is REMOTE_ADDR. If the plugin is configured with a
	 * trusted proxy header and REMOTE_ADDR matches the configured trusted
	 * proxy IP/CIDR list, the closest untrusted IP in that header is used instead.
	 *
	 * @return string A validated IPv4/IPv6 address, or '' if none could be determined.
	 */
	public static function get_client_ip() {
		$remote = self::sanitize_ip( isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '' );
		if ( '' === $remote ) {
			return '';
		}

		$options = get_option( 'adc_security_options', array() );
		$header  = isset( $options['trusted_proxy_header'] ) ? trim( (string) $options['trusted_proxy_header'] ) : '';
		$proxies = isset( $options['trusted_proxies'] ) ? self::parse_list( (string) $options['trusted_proxies'] ) : array();

		if ( '' === $header || empty( $proxies ) || ! self::ip_matches_any( $remote, $proxies ) ) {
			return $remote;
		}

		$server_key = 'HTTP_' . str_replace( '-', '_', strtoupper( $header ) );
		if ( empty( $_SERVER[ $server_key ] ) ) {
			return $remote;
		}

		$header_value = (string) wp_unslash( $_SERVER[ $server_key ] );
		$candidate    = self::resolve_forwarded_ip( $header_value, $proxies );

		return '' !== $candidate ? $candidate : $remote;
	}

	/**
	 * Pick the client IP out of a forwarded-for style header.
	 *
	 * The left side of X-Forwarded-For is client-controlled, so the list is read
	 * from the right and every hop that is itself a trusted proxy is skipped; the
	 * first untrusted address is the closest one a trusted proxy actually saw.
	 *
	 * @param string   $header_value Raw header value (comma separated).
	 * @param string[] $proxies      Trusted proxy IPs/CIDRs.
	 * @return string Validated IP, or '' if none usable.
	 */
	public static function resolve_forwarded_ip( $header_value, array $proxies ) {
		$hops = array_reverse( array_map( 'trim', explode( ',', (string) $header_value ) ) );

		foreach ( $hops as $hop ) {
			$ip = self::sanitize_ip( $hop );
			if ( '' === $ip ) {
				// A malformed hop means we cannot trust anything further left.
				return '';
			}
			if ( ! self::ip_matches_any( $ip, $proxies ) ) {
				return $ip;
			}
		}

		return '';
	}

	/**
	 * @param string $ip Raw value.
	 * @return string Trimmed, validated IP, or ''.
	 */
	private static function sanitize_ip( $ip ) {
		$ip = trim( (string) $ip );
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Split a newline/comma separated list of IPs and CIDR ranges.
	 *
	 * @param string $raw Raw textarea/option value.
	 * @return string[]
	 */
	private static function parse_list( $raw ) {
		$parts = preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY );
		return $parts ? $parts : array();
	}

	/**
	 * @param string   $ip   IP to test.
	 * @param string[] $list IPs/CIDRs to test against.
	 * @return bool
	 */
	private static function ip_matches_any( $ip, array $list ) {
		foreach ( $list as $entry ) {
			if ( self::ip_matches( $ip, trim( $entry ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether $ip matches a single IP address or CIDR range. Public so the
	 * matcher can be exercised directly in tests/test-ip-helper.php without
	 * a WordPress environment.
	 *
	 * @param string $ip    IP to test.
	 * @param string $entry Single IP or CIDR range.
	 * @return bool
	 */
	public static function ip_matches( $ip, $entry ) {
		if ( '' === $entry ) {
			return false;
		}

		if ( false === strpos( $entry, '/' ) ) {
			return hash_equals( $entry, $ip );
		}

		list( $subnet, $mask_bits ) = explode( '/', $entry, 2 );
		if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) || ! ctype_digit( $mask_bits ) ) {
			return false;
		}

		$ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			return false;
		}

		$mask_bits  = min( (int) $mask_bits, strlen( $ip_bin ) * 8 );
		$byte_count = intdiv( $mask_bits, 8 );
		$bit_remainder = $mask_bits % 8;

		if ( $byte_count > 0 && substr( $ip_bin, 0, $byte_count ) !== substr( $subnet_bin, 0, $byte_count ) ) {
			return false;
		}

		if ( 0 === $bit_remainder ) {
			return true;
		}

		$mask_byte = chr( 0xff << ( 8 - $bit_remainder ) & 0xff );
		return ( $ip_bin[ $byte_count ] & $mask_byte ) === ( $subnet_bin[ $byte_count ] & $mask_byte );
	}
}
