<?php
/**
 * Secret-encryption round-trip tests for the 2FA class: current v2 formats,
 * tamper detection, and read-only compatibility with legacy ciphertexts.
 * Runs offline with a stubbed wp_salt(); no WordPress installation needed.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

if ( ! function_exists( 'wp_salt' ) ) {
	function wp_salt( $scheme = 'auth' ) {
		return 'test-salt-' . $scheme;
	}
}

require_once ABSPATH . 'includes/class-adc-security-2fa.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$plain = 'JBSWY3DPEHPK3PXP';

// Current format round-trip (sodium2 when libsodium is present, else openssl2).
$encrypted = ADC_Security_2fa::encrypt( $plain );
$expected_prefix = function_exists( 'sodium_crypto_secretbox' ) ? 'sodium2:' : 'openssl2:';
if ( 0 !== strpos( $encrypted, $expected_prefix ) ) {
	$fail( "encrypt() did not produce the $expected_prefix format: $encrypted" );
}
if ( $plain !== ADC_Security_2fa::decrypt( $encrypted ) ) {
	$fail( 'Round-trip through encrypt()/decrypt() failed.' );
}
if ( ADC_Security_2fa::is_legacy_ciphertext( $encrypted ) ) {
	$fail( 'A current-format value was flagged as legacy.' );
}

// Encrypt-then-MAC path (openssl2) round-trips explicitly.
$openssl_v2 = new ReflectionMethod( ADC_Security_2fa::class, 'encrypt_openssl_v2' );
$openssl_v2->setAccessible( true );
$value = $openssl_v2->invoke( null, $plain );
if ( 0 !== strpos( $value, 'openssl2:' ) || $plain !== ADC_Security_2fa::decrypt( $value ) ) {
	$fail( 'openssl2 round-trip failed.' );
}

// Tampering with the ciphertext or the tag must be rejected (returns '').
$raw       = base64_decode( substr( $value, strlen( 'openssl2:' ) ), true );
$flipped   = $raw;
$flipped[ 16 ] = chr( ord( $flipped[16] ) ^ 0x01 ); // Flip one ciphertext bit.
if ( '' !== ADC_Security_2fa::decrypt( 'openssl2:' . base64_encode( $flipped ) ) ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	$fail( 'openssl2 accepted a tampered ciphertext.' );
}
$bad_tag = $raw;
$bad_tag[ strlen( $bad_tag ) - 1 ] = chr( ord( $bad_tag[ strlen( $bad_tag ) - 1 ] ) ^ 0x01 );
if ( '' !== ADC_Security_2fa::decrypt( 'openssl2:' . base64_encode( $bad_tag ) ) ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	$fail( 'openssl2 accepted a tampered MAC tag.' );
}

// Tampered sodium2 payload must also be rejected.
if ( function_exists( 'sodium_crypto_secretbox' ) ) {
	$sodium_raw = base64_decode( substr( $encrypted, strlen( 'sodium2:' ) ), true );
	$sodium_raw[ strlen( $sodium_raw ) - 1 ] = chr( ord( $sodium_raw[ strlen( $sodium_raw ) - 1 ] ) ^ 0x01 );
	if ( '' !== ADC_Security_2fa::decrypt( 'sodium2:' . base64_encode( $sodium_raw ) ) ) { // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$fail( 'sodium2 accepted a tampered payload.' );
	}
}

// Legacy 'openssl:' value written with the OLD key derivation must still decrypt.
$legacy_key = hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ) . '|adc-security-totp', true );
$legacy_iv  = str_repeat( "\x11", 16 );
$legacy_ct  = openssl_encrypt( $plain, 'aes-256-cbc', $legacy_key, OPENSSL_RAW_DATA, $legacy_iv );
$legacy_ssl = 'openssl:' . base64_encode( $legacy_iv . $legacy_ct ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
if ( $plain !== ADC_Security_2fa::decrypt( $legacy_ssl ) ) {
	$fail( 'Legacy openssl: value no longer decrypts.' );
}
if ( ! ADC_Security_2fa::is_legacy_ciphertext( $legacy_ssl ) ) {
	$fail( 'Legacy openssl: value was not flagged for re-encryption.' );
}

// Legacy 'sodium:' value with the OLD key derivation.
if ( function_exists( 'sodium_crypto_secretbox' ) ) {
	$nonce      = str_repeat( "\x22", SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
	$legacy_sod = 'sodium:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $legacy_key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	if ( $plain !== ADC_Security_2fa::decrypt( $legacy_sod ) ) {
		$fail( 'Legacy sodium: value no longer decrypts.' );
	}
	// A legacy value must NOT decrypt under the new key (keys are really distinct).
	$new_key_value = 'sodium2:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, hash_hmac( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), 'adc-security-totp-v2', true ) ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	if ( $plain !== ADC_Security_2fa::decrypt( $new_key_value ) ) {
		$fail( 'sodium2 value built with the documented v2 key did not decrypt.' );
	}
}

// Garbage and empty input never throw and return ''.
foreach ( array( '', 'nocolon', 'sodium2:!!!', 'openssl2:AAAA', 'unknown:AAAA', 'openssl:AA' ) as $junk ) {
	if ( '' !== ADC_Security_2fa::decrypt( $junk ) ) {
		$fail( "decrypt() returned data for malformed input '$junk'." );
	}
}

fwrite( STDOUT, "2FA crypto tests passed.\n" );
