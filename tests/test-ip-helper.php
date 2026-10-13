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

fwrite( STDOUT, "IP helper tests passed.\n" );
