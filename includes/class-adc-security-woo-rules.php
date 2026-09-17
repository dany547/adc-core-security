<?php
/**
 * ADC Security WooCommerce Rule Helpers
 *
 * Pure, WordPress-free decision helpers shared by the WooCommerce abuse
 * prevention module (ADC_Security_Woocommerce): disposable email matching,
 * fixed-window counters for rate limiting/order velocity, and the
 * "submitted too fast" check.
 *
 * Nothing in this class touches the database, options or filters, so the
 * logic can be unit tested without a WordPress bootstrap
 * (tests/test-woo-rules.php). The plugin applies its settings and the
 * `adc_security_blocked_email_domains` filter before calling these helpers.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Woo_Rules {

	/**
	 * Domains that provide disposable (throwaway) mailboxes, commonly used by
	 * bots to place fake orders and register fake accounts. Kept intentionally
	 * conservative: only well known throwaway providers are listed, so that
	 * legitimate mail providers are never blocked.
	 *
	 * @var array
	 */
	const DISPOSABLE_DOMAINS = array(
		'0-mail.com',
		'10minutemail.com',
		'10minutemail.net',
		'20minutemail.com',
		'anonbox.net',
		'byom.de',
		'discard.email',
		'discardmail.com',
		'dispostable.com',
		'dropmail.me',
		'email-temp.com',
		'emailfake.com',
		'emailondeck.com',
		'fakeinbox.com',
		'filzmail.com',
		'generator.email',
		'getairmail.com',
		'getnada.com',
		'grr.la',
		'guerrillamail.com',
		'guerrillamail.net',
		'guerrillamail.org',
		'guerrillamailblock.com',
		'inboxbear.com',
		'jetable.org',
		'junk1e.com',
		'kurzepost.de',
		'linshiyouxiang.net',
		'mail7.io',
		'mailcatch.com',
		'maildrop.cc',
		'mailinator.com',
		'mailinator.net',
		'mailinator2.com',
		'mailmetrash.com',
		'mailnesia.com',
		'moakt.com',
		'mohmal.com',
		'mt2015.com',
		'mytemp.email',
		'notmailinator.com',
		'nowmymail.com',
		'objectmail.com',
		'pokemail.net',
		'proxymail.eu',
		'rcpt.at',
		'reallymymail.com',
		'sharklasers.com',
		'spam.la',
		'spam4.me',
		'spambog.com',
		'spamgourmet.com',
		'temp-mail.io',
		'temp-mail.org',
		'tempail.com',
		'tempinbox.com',
		'tempmail.com',
		'tempmail.dev',
		'tempmail.net',
		'tempmailo.com',
		'tempr.email',
		'throwam.com',
		'throwawaymail.com',
		'tmail.ws',
		'trash-mail.de',
		'trashmail.at',
		'trashmail.com',
		'trashmail.de',
		'trashmail.io',
		'trashmail.me',
		'trashmail.xyz',
		'trbvm.com',
		'wegwerfmail.de',
		'wegwerfmail.net',
		'wegwerfmail.org',
		'yopmail.com',
		'yopmail.fr',
		'yopmail.net',
	);

	/**
	 * Maximum number of distinct identities (emails) tracked per window state.
	 */
	const MAX_TRACKED_IDENTITIES = 20;

	/**
	 * Extract the domain part of an email address, lowercased.
	 *
	 * @param string $email Email address.
	 * @return string Domain, or '' when the address has no valid shape.
	 */
	public static function email_domain( $email ) {
		$email = trim( (string) $email );
		$at    = strrpos( $email, '@' );

		if ( false === $at ) {
			return '';
		}

		$domain = strtolower( trim( substr( $email, $at + 1 ) ) );

		return rtrim( $domain, '.' );
	}

	/**
	 * Normalise a user supplied list of domains: one per line (comma/semicolon
	 * separated is also accepted), scheme, "local@" and paths are stripped.
	 *
	 * @param string $raw Raw textarea value.
	 * @return array Unique, lowercase domain names.
	 */
	public static function parse_domain_list( $raw ) {
		$raw = (string) $raw;

		if ( '' === trim( $raw ) ) {
			return array();
		}

		$lines  = preg_split( '/[\r\n,;]+/', $raw );
		$domains = array();

		foreach ( $lines as $line ) {
			$domain = strtolower( trim( $line ) );

			if ( '' === $domain ) {
				continue;
			}

			$domain = preg_replace( '#^[a-z0-9+.\-]+://#', '', $domain ); // Strip a scheme.
			$domain = preg_replace( '#^.*@#', '', $domain );              // Strip "local@" or "user@".
			$domain = preg_replace( '~[/:?#].*$~', '', $domain );         // Strip path, port and query.
			$domain = rtrim( (string) $domain, '.' );

			// Only accept a plausible DNS name; drop anything else silently.
			if ( ! preg_match( '/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/', $domain ) ) {
				continue;
			}

			$domains[ $domain ] = true;
		}

		return array_keys( $domains );
	}

	/**
	 * Reduce a phone number to digits, ignoring values too short to identify a
	 * subscriber so junk input never shares a counter bucket.
	 *
	 * @param string $phone Raw phone number.
	 * @return string Digits, or '' when the value is unusable.
	 */
	public static function normalize_phone( $phone ) {
		$digits = preg_replace( '/\D+/', '', (string) $phone );
		$digits = is_string( $digits ) ? $digits : '';

		return strlen( $digits ) >= 6 ? $digits : '';
	}

	/**
	 * Build a comparable key from a street address and postcode.
	 *
	 * Lowercased, punctuation and repeated whitespace removed, so that
	 * "Str. Exemplu 10, Ap. 3" and "str exemplu 10 ap 3" match. Addresses too
	 * short to be meaningful return '' so they never create a shared bucket.
	 *
	 * @param string $address  Street address.
	 * @param string $postcode Postcode.
	 * @return string Address key, or '' when unusable.
	 */
	public static function normalize_address( $address, $postcode = '' ) {
		$parts = array();

		foreach ( array( $address, $postcode ) as $raw ) {
			$part = strtolower( trim( (string) $raw ) );

			if ( '' === $part ) {
				continue;
			}

			$part = preg_replace( '/[^a-z0-9 ]+/', ' ', $part );
			$part = is_string( $part ) ? preg_replace( '/\s+/', ' ', $part ) : '';
			$part = trim( (string) $part );

			if ( '' !== $part ) {
				$parts[] = $part;
			}
		}

		if ( empty( $parts ) ) {
			return '';
		}

		// The street is the identifying part; a one-word/near-empty street is noise.
		if ( strlen( str_replace( ' ', '', $parts[0] ) ) < 5 ) {
			return '';
		}

		return implode( '|', $parts );
	}

	/**
	 * Extract the hostname from a URL or origin header value.
	 *
	 * @param string $url URL or origin, protocol-relative URLs included.
	 * @return string Lowercased host, or '' when none can be found.
	 */
	public static function host_from_url( $url ) {
		$url = trim( (string) $url );

		if ( '' === $url ) {
			return '';
		}

		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'http:' . $url;
		}

		$parts = parse_url( $url );

		if ( ! is_array( $parts ) || empty( $parts['host'] ) ) {
			return '';
		}

		return strtolower( (string) $parts['host'] );
	}

	/**
	 * Compare two hostnames, treating a leading "www." and subdomains as the
	 * same site (store.example.com is accepted for example.com).
	 *
	 * @param string $host    Host to test.
	 * @param string $allowed Allowed host.
	 * @return bool
	 */
	public static function is_same_host( $host, $allowed ) {
		$host    = strtolower( trim( (string) $host ) );
		$allowed = strtolower( trim( (string) $allowed ) );

		if ( '' === $host || '' === $allowed ) {
			return false;
		}

		$host    = self::strip_www( $host );
		$allowed = self::strip_www( $allowed );

		if ( $host === $allowed ) {
			return true;
		}

		$suffix = '.' . $allowed;

		return strlen( $host ) > strlen( $suffix ) && substr( $host, -strlen( $suffix ) ) === $suffix;
	}

	/**
	 * Remove a leading "www." label.
	 *
	 * @param string $host Hostname.
	 * @return string
	 */
	private static function strip_www( $host ) {
		return ( 0 === strpos( $host, 'www.' ) ) ? substr( $host, 4 ) : $host;
	}

	/**
	 * Merge the built-in disposable provider list with a user supplied list.
	 *
	 * @param string $custom_raw Raw textarea value.
	 * @return array Complete, deduplicated domain list.
	 */
	public static function get_blocked_domains( $custom_raw = '' ) {
		$domains = array_merge( self::DISPOSABLE_DOMAINS, self::parse_domain_list( $custom_raw ) );

		return array_values( array_unique( $domains ) );
	}

	/**
	 * Check whether a domain matches (or belongs to) a blocked domain.
	 * "user@sub.mailinator.com" is blocked because it ends with ".mailinator.com".
	 *
	 * @param string $domain  Domain to test.
	 * @param array  $blocked Blocked domain list.
	 * @return bool
	 */
	public static function is_blocked_domain( $domain, array $blocked ) {
		$domain = strtolower( rtrim( (string) $domain, '.' ) );

		if ( '' === $domain ) {
			return false;
		}

		foreach ( $blocked as $rule ) {
			$rule = strtolower( rtrim( (string) $rule, '.' ) );

			if ( '' === $rule ) {
				continue;
			}

			if ( $domain === $rule ) {
				return true;
			}

			$suffix = '.' . $rule;
			if ( strlen( $domain ) > strlen( $suffix ) && substr( $domain, -strlen( $suffix ) ) === $suffix ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Increment a fixed-window counter, restarting it when the window elapsed
	 * (or when the clock moved backwards between requests).
	 *
	 * An optional identity (e.g. the billing email) is tracked in the same state
	 * so callers can tell "one actor repeated" from "many actors used the same
	 * key", which is the difference between a repeat customer and abuse.
	 *
	 * @param mixed  $state          Stored state: array( 'count' => int, 'start' => float ).
	 * @param float  $now            Current timestamp (seconds, microseconds allowed).
	 * @param int    $window_seconds Window length in seconds.
	 * @param string $identity       Optional raw identity string to track (hashed internally).
	 * @return array Fresh state.
	 */
	public static function bump_window( $state, $now, $window_seconds, $identity = '' ) {
		$now            = (float) $now;
		$window_seconds = max( 1, (int) $window_seconds );
		$identity       = (string) $identity;

		if ( ! is_array( $state ) || ! isset( $state['count'], $state['start'] ) ) {
			return self::fresh_window( $now, $identity );
		}

		$start = (float) $state['start'];
		$count = max( 0, (int) $state['count'] );

		if ( $now < $start || ( $now - $start ) >= $window_seconds ) {
			return self::fresh_window( $now, $identity );
		}

		$state['count'] = $count + 1;

		if ( '' !== $identity ) {
			$ids = ( isset( $state['ids'] ) && is_array( $state['ids'] ) ) ? $state['ids'] : array();
			$ids[ md5( $identity ) ] = true;

			if ( count( $ids ) > self::MAX_TRACKED_IDENTITIES ) {
				// Bound the state size; the newest identities are the relevant ones.
				$ids = array_slice( $ids, -self::MAX_TRACKED_IDENTITIES, null, true );
			}

			$state['ids'] = $ids;
		}

		return $state;
	}

	/**
	 * Build a fresh window state.
	 *
	 * @param float  $now      Current timestamp.
	 * @param string $identity Optional raw identity string.
	 * @return array
	 */
	private static function fresh_window( $now, $identity ) {
		$state = array(
			'count' => 1,
			'start' => $now,
		);

		if ( '' !== $identity ) {
			$state['ids'] = array( md5( $identity ) => true );
		}

		return $state;
	}

	/**
	 * Number of distinct identities recorded in the current window.
	 *
	 * @param mixed $state Stored state.
	 * @return int
	 */
	public static function window_distinct( $state ) {
		return ( isset( $state['ids'] ) && is_array( $state['ids'] ) ) ? count( $state['ids'] ) : 0;
	}

	/**
	 * Read the count currently held by a fixed-window counter.
	 *
	 * @param mixed $state          Stored state.
	 * @param float $now            Current timestamp.
	 * @param int   $window_seconds Window length in seconds.
	 * @return int Count, or 0 when the window elapsed.
	 */
	public static function window_count( $state, $now, $window_seconds ) {
		if ( ! is_array( $state ) || ! isset( $state['count'], $state['start'] ) ) {
			return 0;
		}

		$now   = (float) $now;
		$start = (float) $state['start'];

		if ( $now < $start || ( $now - $start ) >= max( 1, (int) $window_seconds ) ) {
			return 0;
		}

		return max( 0, (int) $state['count'] );
	}

	/**
	 * Check whether a count reached its limit. A limit of 0 (or lower) disables
	 * the rule, which is how the settings expose "off".
	 *
	 * @param int $count Current count.
	 * @param int $limit Configured limit.
	 * @return bool
	 */
	public static function is_over_limit( $count, $limit ) {
		$limit = (int) $limit;

		if ( $limit <= 0 ) {
			return false;
		}

		return (int) $count >= $limit;
	}

	/**
	 * Check whether a submission arrived faster than the configured minimum.
	 * A missing timestamp (0) cannot be judged and never blocks.
	 *
	 * @param int $started_at  Unix timestamp of when the form/page was rendered.
	 * @param int $now         Current Unix timestamp.
	 * @param int $min_seconds Minimum expected delay; 0 disables the check.
	 * @return bool
	 */
	public static function is_too_fast( $started_at, $now, $min_seconds ) {
		$min_seconds = (int) $min_seconds;

		if ( $min_seconds <= 0 ) {
			return false;
		}

		$started_at = (int) $started_at;

		if ( $started_at <= 0 ) {
			return false;
		}

		return ( (int) $now - $started_at ) < $min_seconds;
	}
}
