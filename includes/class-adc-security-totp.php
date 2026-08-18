<?php
/**
 * ADC Security TOTP Class
 *
 * Pure RFC 4226 (HOTP) / RFC 6238 (TOTP) implementation. No WordPress calls
 * of any kind so it can be unit tested offline with the RFC 6238 test
 * vectors (see tests/test-totp.php).
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Totp {

	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Generate a random Base32 secret.
	 *
	 * @param int $byte_length Number of random bytes to encode (default 20 = 160 bits).
	 * @return string Base32-encoded secret, no padding.
	 */
	public static function generate_secret( $byte_length = 20 ) {
		return self::base32_encode( random_bytes( max( 10, (int) $byte_length ) ) );
	}

	/**
	 * Base32-encode raw bytes (RFC 4648), no padding.
	 *
	 * @param string $data Raw binary data.
	 * @return string
	 */
	public static function base32_encode( $data ) {
		if ( '' === $data ) {
			return '';
		}

		$bits   = '';
		$length = strlen( $data );
		for ( $i = 0; $i < $length; $i++ ) {
			$bits .= str_pad( decbin( ord( $data[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			if ( 5 !== strlen( $chunk ) ) {
				$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			}
			$output .= self::BASE32_ALPHABET[ bindec( $chunk ) ];
		}

		return $output;
	}

	/**
	 * Base32-decode a secret back to raw bytes. Non-alphabet characters
	 * (spaces, padding, lowercase) are tolerated and normalized.
	 *
	 * @param string $secret Base32 string.
	 * @return string Raw binary data.
	 */
	public static function base32_decode( $secret ) {
		$secret = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $secret ) );
		if ( '' === $secret ) {
			return '';
		}

		$bits = '';
		foreach ( str_split( $secret ) as $char ) {
			$pos = strpos( self::BASE32_ALPHABET, $char );
			if ( false === $pos ) {
				continue;
			}
			$bits .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}

		$output = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 !== strlen( $byte ) ) {
				continue; // Trailing padding bits, not a full byte.
			}
			$output .= chr( bindec( $byte ) );
		}

		return $output;
	}

	/**
	 * HOTP value for a given counter (RFC 4226).
	 *
	 * @param string $secret_binary Raw secret bytes.
	 * @param int    $counter       Moving factor.
	 * @param int    $digits        Output digit count.
	 * @return string Zero-padded numeric code.
	 */
	public static function hotp( $secret_binary, $counter, $digits = 6 ) {
		$counter_bytes = pack( 'N*', 0, $counter ); // 8-byte big-endian counter.
		$hash          = hash_hmac( 'sha1', $counter_bytes, $secret_binary, true );

		$offset = ord( $hash[19] ) & 0xf;
		$code   = ( ( ord( $hash[ $offset ] ) & 0x7f ) << 24 )
			| ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
			| ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
			| ( ord( $hash[ $offset + 3 ] ) & 0xff );

		$code %= pow( 10, $digits );

		return str_pad( (string) $code, $digits, '0', STR_PAD_LEFT );
	}

	/**
	 * TOTP value for the given (or current) time (RFC 6238).
	 *
	 * @param string   $secret Base32-encoded secret.
	 * @param int|null $time   Unix timestamp, defaults to now.
	 * @param int      $period Time step in seconds.
	 * @param int      $digits Output digit count.
	 * @return string
	 */
	public static function totp( $secret, $time = null, $period = 30, $digits = 6 ) {
		$time    = null === $time ? time() : (int) $time;
		$counter = (int) floor( $time / max( 1, $period ) );

		return self::hotp( self::base32_decode( $secret ), $counter, $digits );
	}

	/**
	 * Verify a submitted code against the current time, tolerating clock
	 * drift within +/- $window time steps.
	 *
	 * @param string   $secret Base32-encoded secret.
	 * @param string   $code   Submitted code.
	 * @param int      $window Number of steps to check on either side of now.
	 * @param int|null $time   Unix timestamp, defaults to now.
	 * @param int      $period Time step in seconds.
	 * @param int      $digits Output digit count.
	 * @return bool
	 */
	public static function verify( $secret, $code, $window = 1, $time = null, $period = 30, $digits = 6 ) {
		$code = preg_replace( '/\s+/', '', (string) $code );
		if ( '' === $code || ! ctype_digit( $code ) ) {
			return false;
		}

		$time          = null === $time ? time() : (int) $time;
		$secret_binary = self::base32_decode( $secret );

		for ( $offset = -$window; $offset <= $window; $offset++ ) {
			$counter  = (int) floor( $time / max( 1, $period ) ) + $offset;
			$expected = self::hotp( $secret_binary, $counter, $digits );
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Build an otpauth:// provisioning URI for QR-code enrollment.
	 *
	 * @param string $secret  Base32-encoded secret.
	 * @param string $account Account label, e.g. user email or login.
	 * @param string $issuer  Issuer name, e.g. site name.
	 * @return string
	 */
	public static function provisioning_uri( $secret, $account, $issuer ) {
		$label = rawurlencode( $issuer ) . ':' . rawurlencode( $account );

		return sprintf(
			'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			$label,
			rawurlencode( $secret ),
			rawurlencode( $issuer )
		);
	}
}
