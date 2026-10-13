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

fwrite( STDOUT, "IP helper tests passed.\n" );
