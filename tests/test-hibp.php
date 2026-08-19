<?php
/**
 * Lightweight HIBP range-response matcher tests that do not require a
 * WordPress installation. Only exercises the pure parsing logic — no
 * network calls are made.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-2fa.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

// A realistic range response, with a real match, a zero-count padding
// entry, and an unrelated suffix.
$body = "003D68EB55068C33ACE09247EE4C639306:0\r\n"
	. "0018A45C4D1DEF81644B54AB7F969B88D65:12\r\n"
	. "121212121212121212121212121212121:0\r\n";

if ( ! ADC_Security_2fa::suffix_found_in_range_response( '0018A45C4D1DEF81644B54AB7F969B88D65', $body ) ) {
	$fail( 'Expected suffix with a positive count to be treated as a match.' );
}

if ( ADC_Security_2fa::suffix_found_in_range_response( '003D68EB55068C33ACE09247EE4C639306', $body ) ) {
	$fail( 'A padding entry (count 0) must not be treated as a match.' );
}

if ( ADC_Security_2fa::suffix_found_in_range_response( 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', $body ) ) {
	$fail( 'A suffix absent from the response must not match.' );
}

// Matching must be case-sensitive-safe / exact (hash_equals requires identical strings).
if ( ADC_Security_2fa::suffix_found_in_range_response( '0018a45c4d1def81644b54ab7f969b88d65', $body ) ) {
	$fail( 'Lowercase suffix should not match an uppercase entry (caller is responsible for normalizing case).' );
}

// Empty body / malformed lines must not match and must not error.
if ( ADC_Security_2fa::suffix_found_in_range_response( 'ANYTHING', '' ) ) {
	$fail( 'Empty response body should never match.' );
}
if ( ADC_Security_2fa::suffix_found_in_range_response( 'ANYTHING', "garbage line without a colon\r\n" ) ) {
	$fail( 'Malformed lines should be skipped, not matched.' );
}

fwrite( STDOUT, "HIBP matcher tests passed.\n" );
