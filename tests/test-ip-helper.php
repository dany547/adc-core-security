<?php
/**
 * Lightweight IP/CIDR matcher tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-ip.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$cases = array(
	array( '203.0.113.5', '203.0.113.5', true ),
	array( '203.0.113.5', '203.0.113.6', false ),
	array( '203.0.113.5', '203.0.113.0/24', true ),
	array( '203.0.114.5', '203.0.113.0/24', false ),
	array( '10.0.0.1', '10.0.0.0/8', true ),
	array( '11.0.0.1', '10.0.0.0/8', false ),
	array( '192.168.1.200', '192.168.1.128/25', true ),
	array( '192.168.1.100', '192.168.1.128/25', false ),
	array( '2001:db8::1', '2001:db8::1', true ),
	array( '2001:db8::1', '2001:db8::/32', true ),
	array( '2001:db9::1', '2001:db8::/32', false ),
	array( '203.0.113.5', 'not-an-ip/24', false ),
);

foreach ( $cases as list( $ip, $entry, $expected ) ) {
	$actual = ADC_Security_Ip::ip_matches( $ip, $entry );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'ip_matches(%s, %s) expected %s, got %s.', $ip, $entry, $expected ? 'true' : 'false', $actual ? 'true' : 'false' ) );
	}
}

$proxies = array( '10.0.0.0/8', '203.0.113.7' );
$xff_cases = array(
	// Spoofed leftmost value must be ignored; the real client is the first untrusted hop from the right.
	array( '1.2.3.4, 198.51.100.9, 10.0.0.2', '198.51.100.9' ),
	array( '198.51.100.9', '198.51.100.9' ),
	array( '198.51.100.9, 203.0.113.7, 10.1.1.1', '198.51.100.9' ),
	array( '10.0.0.5, 10.0.0.2', '' ),
	array( '198.51.100.9, garbage', '' ),
	array( '', '' ),
);
foreach ( $xff_cases as list( $header, $expected ) ) {
	$actual = ADC_Security_Ip::resolve_forwarded_ip( $header, $proxies );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'resolve_forwarded_ip(%s) expected "%s", got "%s".', $header, $expected, $actual ) );
	}
}

// is_client_ip_reliable() decision: arguments are ($server, $configured header, $trusted proxies).
$reliable_cases = array(
	// CF header arrives but no trusted proxy header is configured.
	array( 'CF header without setting', array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.9' ), '', array( '203.0.113.7' ), false ),
	// Header configured, request really comes from a trusted proxy.
	array( 'header plus matching proxy', array( 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_CF_CONNECTING_IP' => '198.51.100.9' ), 'CF-Connecting-IP', array( '203.0.113.7' ), true ),
	array( 'header plus proxy CIDR', array( 'REMOTE_ADDR' => '10.1.2.3', 'HTTP_X_FORWARDED_FOR' => '198.51.100.9' ), 'X-Forwarded-For', array( '10.0.0.0/8' ), true ),
	// No forwarding headers at all.
	array( 'no headers', array( 'REMOTE_ADDR' => '198.51.100.9' ), '', array(), true ),
	array( 'no headers with setting', array( 'REMOTE_ADDR' => '198.51.100.9' ), 'CF-Connecting-IP', array( '203.0.113.7' ), true ),
	// Spoofed header from a direct visitor while the setting is on.
	array( 'spoof from non-proxy', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_REAL_IP' => '1.2.3.4' ), 'X-Real-IP', array( '203.0.113.7' ), false ),
	array( 'spoof with empty proxy list', array( 'REMOTE_ADDR' => '198.51.100.9', 'HTTP_TRUE_CLIENT_IP' => '1.2.3.4' ), 'CF-Connecting-IP', array(), false ),
	array( 'invalid REMOTE_ADDR', array( 'REMOTE_ADDR' => 'garbage', 'HTTP_CF_CONNECTING_IP' => '1.2.3.4' ), 'CF-Connecting-IP', array( 'garbage' ), false ),
);
foreach ( $reliable_cases as list( $label, $server, $header, $proxies, $expected ) ) {
	$actual = ADC_Security_Ip::evaluate_client_ip_reliability( $server, $header, $proxies );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'evaluate_client_ip_reliability (%s) expected %s, got %s.', $label, $expected ? 'true' : 'false', $actual ? 'true' : 'false' ) );
	}
}

// ---------------------------------------------------------------------------
// Rule parsing / normalisation (pure).
// ---------------------------------------------------------------------------

$normalize_cases = array(
	array( '203.0.113.5', '203.0.113.5' ),
	array( '  203.0.113.5  ', '203.0.113.5' ),
	array( '203.0.113.0/24', '203.0.113.0/24' ),
	array( '0.0.0.0/0', '0.0.0.0/0' ),
	array( '203.0.113.5/32', '203.0.113.5/32' ),
	array( '2001:db8::1', '2001:db8::1' ),
	array( '2001:db8::/32', '2001:db8::/32' ),
	array( '::/0', '::/0' ),
	array( '::1/128', '::1/128' ),
	array( '1.2.3.4/33', false ),
	array( '1.2.3.4/-1', false ),
	array( '::1/129', false ),
	array( '1.2.3.4/', false ),
	array( '1.2.3.4/abc', false ),
	array( '1.2.3.4/8/9', false ),
	array( 'garbage', false ),
	array( 'not-an-ip/24', false ),
	array( '999.1.1.1', false ),
	array( '', false ),
	array( '   ', false ),
	array( null, false ),
);
foreach ( $normalize_cases as list( $rule, $expected ) ) {
	$actual = ADC_Security_Ip::normalize_rule( $rule );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'normalize_rule(%s) expected %s, got %s.', var_export( $rule, true ), var_export( $expected, true ), var_export( $actual, true ) ) );
	}
}

$parsed = ADC_Security_Ip::parse_rules( "10.0.0.1\r\n\r\n  10.0.0.0/8  \r\nnot-valid\n10.0.0.1\n2001:db8::1\r10.0.0.0/8\n" );
if ( $parsed !== array( '10.0.0.1', '10.0.0.0/8', '2001:db8::1' ) ) {
	$fail( 'parse_rules() dedupe/CRLF/blank/invalid handling failed: ' . json_encode( $parsed ) );
}
if ( ADC_Security_Ip::parse_rules( null ) !== array() || ADC_Security_Ip::parse_rules( array( '1.2.3.4' ) ) !== array() ) {
	$fail( 'parse_rules() must return an empty array for non-string input.' );
}
if ( ADC_Security_Ip::parse_rules( '' ) !== array() ) {
	$fail( 'parse_rules("") must return an empty array.' );
}

$list_expected = "10.0.0.1\n10.0.0.0/8\n2001:db8::1";
$list_actual   = ADC_Security_Ip::normalize_list( "10.0.0.1\r\n\r\n  10.0.0.0/8  \r\nnot-valid\n10.0.0.1\n2001:db8::1\r10.0.0.0/8\n" );
if ( $list_actual !== $list_expected ) {
	$fail( 'normalize_list() expected ' . json_encode( $list_expected ) . ', got ' . json_encode( $list_actual ) . '.' );
}
if ( ADC_Security_Ip::normalize_list( 'junk' ) !== '' ) {
	$fail( 'normalize_list() of only invalid lines must return "".' );
}

// ---------------------------------------------------------------------------
// matches_any (rules come from parse_rules()).
// ---------------------------------------------------------------------------

$rules = ADC_Security_Ip::parse_rules( "203.0.113.5\n10.0.0.0/8\n2001:db8::/32" );
$matches_cases = array(
	array( '203.0.113.5', true ),
	array( '10.9.8.7', true ),
	array( '198.51.100.1', false ),
	array( '2001:db8:1::5', true ),
	array( '2001:db9::5', false ),
	array( '', false ),
);
foreach ( $matches_cases as list( $ip, $expected ) ) {
	$actual = ADC_Security_Ip::matches_any( $ip, $rules );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'matches_any(%s) expected %s, got %s.', $ip, $expected ? 'true' : 'false', $actual ? 'true' : 'false' ) );
	}
}
if ( ADC_Security_Ip::matches_any( '203.0.113.5', array() ) ) {
	$fail( 'matches_any() with no rules must be false.' );
}

// Regression: mixed address families must never match.
$family_cases = array(
	array( '10.0.0.1', '::/0', false ),          // IPv4 client vs IPv6 catch-all.
	array( '10.0.0.1', '::ffff:0:0/96', false ), // IPv4 client vs IPv4-mapped range.
	array( '0a00:1::1', '10.0.0.0/8', false ),   // IPv6 client vs IPv4 range.
	array( '2001:db8::1', '0.0.0.0/0', false ),  // IPv6 client vs IPv4 catch-all.
	array( '0.0.0.0', '::/0', false ),
	array( '::1', '127.0.0.0/8', false ),
);
foreach ( $family_cases as list( $ip, $entry, $expected ) ) {
	$actual = ADC_Security_Ip::matches_any( $ip, ADC_Security_Ip::parse_rules( $entry ) );
	if ( $actual !== $expected ) {
		$fail( sprintf( 'family regression: matches_any(%s, %s) expected false, got true.', $ip, $entry ) );
	}
	if ( ADC_Security_Ip::ip_matches( $ip, $entry ) !== $expected ) {
		$fail( sprintf( 'family regression: ip_matches(%s, %s) expected false, got true.', $ip, $entry ) );
	}
}

// ---------------------------------------------------------------------------
// is_allowlisted / is_denylisted (option readers). Stub get_option() only
// when WordPress is not loaded.
// ---------------------------------------------------------------------------

if ( ! function_exists( 'get_option' ) ) {
	function get_option( $name, $default = false ) {
		global $adc_test_options;
		return array_key_exists( $name, $adc_test_options ) ? $adc_test_options[ $name ] : $default;
	}
}

$adc_test_options = array(
	'adc_security_options' => array(
		'ip_allowlist' => "203.0.113.5\n2001:db8::/32\n10.0.0.0/8",
		'ip_denylist'  => "198.51.100.0/24\r\n2001:db8:bad::/48\nnot-an-ip",
	),
);
$option_cases = array(
	array( 'is_allowlisted', '203.0.113.5', true ),
	array( 'is_allowlisted', '203.0.113.6', false ),
	array( 'is_allowlisted', '2001:db8::9', true ),
	array( 'is_allowlisted', '198.51.100.9', false ),
	array( 'is_allowlisted', '', false ),
	array( 'is_denylisted', '198.51.100.9', true ),
	array( 'is_denylisted', '198.51.101.9', false ),
	array( 'is_denylisted', '2001:db8:bad::1', true ),
	array( 'is_denylisted', '2001:db8:good::1', false ),
	array( 'is_denylisted', '10.0.0.1', false ),
	array( 'is_denylisted', '', false ),
	// Mixed family against option-driven lists.
	array( 'is_allowlisted', '0a00:1::1', false ),
	array( 'is_denylisted', '0.0.0.0', false ),
);
foreach ( $option_cases as list( $fn, $ip, $expected ) ) {
	$actual = 'is_allowlisted' === $fn ? ADC_Security_Ip::is_allowlisted( $ip ) : ADC_Security_Ip::is_denylisted( $ip );
	if ( $actual !== $expected ) {
		$fail( sprintf( '%s(%s) expected %s, got %s.', $fn, $ip, $expected ? 'true' : 'false', $actual ? 'true' : 'false' ) );
	}
}

// Non-array option value must not fatal and must match nothing.
$adc_test_options = array( 'adc_security_options' => 'corrupt' );
if ( ADC_Security_Ip::is_allowlisted( '203.0.113.5' ) || ADC_Security_Ip::is_denylisted( '203.0.113.5' ) ) {
	$fail( 'Non-array adc_security_options must match nothing.' );
}

fwrite( STDOUT, "IP helper tests passed.\n" );
