<?php
/**
 * TOTP tests against the official RFC 6238 SHA1 test vectors.
 * Does not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-totp.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

// RFC 6238 Appendix B: 20-byte SHA1 seed "12345678901234567890".
$secret_binary = '12345678901234567890';
$secret        = ADC_Security_Totp::base32_encode( $secret_binary );

// Round-trip encode/decode.
if ( $secret_binary !== ADC_Security_Totp::base32_decode( $secret ) ) {
	$fail( 'Base32 round-trip did not reproduce the original secret.' );
}

// RFC 6238 Appendix B, SHA1 column: Time, T (hex counter), TOTP.
$vectors = array(
	59          => '94287082',
	1111111109  => '07081804',
	1111111111  => '14050471',
	1234567890  => '89005924',
	2000000000  => '69279037',
);

foreach ( $vectors as $time => $expected ) {
	$actual = ADC_Security_Totp::totp( $secret, $time, 30, 8 );
	if ( $expected !== $actual ) {
		$fail( "TOTP mismatch at time $time: expected $expected, got $actual." );
	}
}

// verify() should accept the exact code at its own time step.
if ( ! ADC_Security_Totp::verify( $secret, '94287082', 1, 59, 30, 8 ) ) {
	$fail( 'verify() rejected a valid code at the exact time step.' );
}

// verify() should accept a code from one step in the past (clock drift window).
$one_step_ago = ADC_Security_Totp::totp( $secret, 1111111109, 30, 8 );
if ( ! ADC_Security_Totp::verify( $secret, $one_step_ago, 1, 1111111109 + 30, 30, 8 ) ) {
	$fail( 'verify() rejected a code from one step in the past within the window.' );
}

// verify() must reject a code well outside the window.
if ( ADC_Security_Totp::verify( $secret, '94287082', 1, 59 + 3600, 30, 8 ) ) {
	$fail( 'verify() accepted a stale code far outside the drift window.' );
}

// verify() must reject non-numeric / malformed input rather than throwing.
if ( ADC_Security_Totp::verify( $secret, 'not-a-code', 1, 59, 30, 8 ) ) {
	$fail( 'verify() accepted non-numeric input.' );
}
if ( ADC_Security_Totp::verify( $secret, '', 1, 59, 30, 8 ) ) {
	$fail( 'verify() accepted an empty code.' );
}

// Provisioning URI should carry the secret and be otpauth://totp/...
$uri = ADC_Security_Totp::provisioning_uri( $secret, 'user@example.com', 'ADC Security' );
if ( 0 !== strpos( $uri, 'otpauth://totp/' ) || false === strpos( $uri, rawurlencode( $secret ) ) ) {
	$fail( 'Provisioning URI is malformed: ' . $uri );
}

fwrite( STDOUT, "TOTP tests passed.\n" );
