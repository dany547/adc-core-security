<?php
/**
 * ADC Security Firewall Matchers
 *
 * Pure, WordPress-free request matchers for the ADC Firewall Rules module.
 * contains_traversal(), is_author_injection_arg() and
 * contains_author_injection_arg() are behaviour-identical ports of the
 * matchers that ship in ADC_Security_Virtual_Patch, so that both code paths
 * agree on what a hostile request looks like.
 *
 * Nothing here calls WordPress functions, so the matchers run under plain PHP
 * (tests/test-firewall-matchers via tests/test-firewall-corpus.php).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Firewall_Matchers {

	/**
	 * Decode passes performed while probing for encoded values.
	 */
	const MAX_DECODE_PASSES = 4;

	/**
	 * Maximum recursion depth when walking nested request arrays.
	 */
	const MAX_ARG_DEPTH = 5;

	/**
	 * Maximum number of integers accepted in an ID list argument.
	 */
	const MAX_INT_LIST_ITEMS = 100;

	/**
	 * Core REST route abused by CVE-2026-63030.
	 */
	const REST_BATCH_ROUTE = '/batch/v1';

	/**
	 * Detect path traversal in a request value, at any encoding depth.
	 *
	 * Traversal always needs a ".." component, so that is the invariant this
	 * checks for instead of one specific exploit string. The value is decoded
	 * repeatedly because CVE-2026-87902 relies on sanitization running before
	 * a late urldecode().
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

	/**
	 * Whether a value is a plain list of integer IDs, such as author_exclude.
	 *
	 * Accepts an int, a comma-separated string of ints ("1,2,3"), or a flat
	 * array whose elements are ints or such strings. Anything containing other
	 * characters (quotes, parentheses, comment markers) is rejected, as are
	 * nested arrays deeper than one level and lists longer than 100 items.
	 * An empty string is a valid, empty list.
	 *
	 * @param mixed $value Raw request value.
	 * @return bool
	 */
	public static function is_valid_int_list( $value ) {
		if ( is_int( $value ) ) {
			return true;
		}

		if ( is_string( $value ) ) {
			$items = self::count_int_list_string( $value );

			return false !== $items && $items <= self::MAX_INT_LIST_ITEMS;
		}

		if ( ! is_array( $value ) || count( $value ) > self::MAX_INT_LIST_ITEMS ) {
			return false;
		}

		$total = 0;

		foreach ( $value as $item ) {
			if ( is_int( $item ) ) {
				++$total;
				continue;
			}

			if ( ! is_string( $item ) ) {
				return false;
			}

			$items = self::count_int_list_string( $item );

			if ( false === $items ) {
				return false;
			}

			$total += $items;
		}

		return $total <= self::MAX_INT_LIST_ITEMS;
	}

	/**
	 * Whether a REST route is the core batch route, including case, duplicate
	 * slash and URL-encoded variants, and sub-paths of it.
	 *
	 * @param string $route REST route (for example "/batch/v1").
	 * @return bool
	 */
	public static function is_batch_route( $route ) {
		if ( ! is_string( $route ) || '' === $route ) {
			return false;
		}

		$normalised = $route;

		for ( $i = 0; $i < self::MAX_DECODE_PASSES; $i++ ) {
			$decoded = rawurldecode( $normalised );

			if ( $decoded === $normalised ) {
				break;
			}

			$normalised = $decoded;
		}

		$normalised = strtolower( explode( '?', $normalised, 2 )[0] );
		$normalised = preg_replace( '#/+#', '/', $normalised );

		if ( '' === $normalised || '/' !== $normalised[0] ) {
			$normalised = '/' . $normalised;
		}

		return 1 === preg_match( '#^' . preg_quote( self::REST_BATCH_ROUTE, '#' ) . '(?:/|$)#D', $normalised );
	}

	/**
	 * Work out the REST route a request is addressing.
	 *
	 * Prefers the ?rest_route= query parameter (plain permalinks), then falls
	 * back to a /wp-json/ path (pretty permalinks).
	 *
	 * @param array  $get  Query parameters ($_GET or equivalent).
	 * @param string $path Request path, optionally with a query string.
	 * @return string The route, or an empty string when the request is not a REST request.
	 */
	public static function rest_route_from_request( array $get, $path ) {
		if ( isset( $get['rest_route'] ) && is_string( $get['rest_route'] ) && '' !== trim( $get['rest_route'] ) ) {
			return trim( $get['rest_route'] );
		}

		if ( ! is_string( $path ) || '' === $path ) {
			return '';
		}

		$path = rawurldecode( explode( '?', $path, 2 )[0] );

		if ( ! preg_match( '#(?:^|/)wp-json(?:/(.*))?$#iD', $path, $matches ) ) {
			return '';
		}

		$route = isset( $matches[1] ) ? $matches[1] : '';

		return '/' . ltrim( $route, '/' );
	}

	/**
	 * Count the integers in a comma-separated list string.
	 *
	 * @param string $value Candidate list.
	 * @return int|false Item count (0 for an empty string), or false when the string is not an int list.
	 */
	private static function count_int_list_string( $value ) {
		if ( '' === trim( $value ) ) {
			return 0;
		}

		if ( ! preg_match( '/^\s*-?\d+\s*(?:,\s*-?\d+\s*)*$/D', $value ) ) {
			return false;
		}

		return substr_count( $value, ',' ) + 1;
	}
}
