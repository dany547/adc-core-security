<?php
/**
 * WooCommerce abuse-prevention rule tests that do not require a WordPress
 * installation. They cover the pure decision helpers used by
 * ADC_Security_Woocommerce (email domain matching, fixed-window counters and
 * the "submitted too fast" check).
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-woo-rules.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

// --- email_domain -----------------------------------------------------------

if ( 'example.com' !== ADC_Security_Woo_Rules::email_domain( 'User@Example.COM' ) ) {
	$fail( 'email_domain() must lowercase and extract the domain.' );
}

if ( 'sub.example.co.uk' !== ADC_Security_Woo_Rules::email_domain( 'a@sub.example.co.uk ' ) ) {
	$fail( 'email_domain() must tolerate surrounding whitespace.' );
}

if ( '' !== ADC_Security_Woo_Rules::email_domain( 'no-at-sign' ) ) {
	$fail( 'email_domain() must return an empty string when there is no @.' );
}

// --- parse_domain_list ------------------------------------------------------

$parsed = ADC_Security_Woo_Rules::parse_domain_list( "Evil.test\n@evil2.test\nhttps://evil3.test/path\nnot a domain\n\nEVIL.test" );
$expected = array( 'evil.test', 'evil2.test', 'evil3.test' );

if ( $expected !== $parsed ) {
	$fail( 'parse_domain_list() returned ' . var_export( $parsed, true ) . ' instead of ' . var_export( $expected, true ) . '.' );
}

if ( array() !== ADC_Security_Woo_Rules::parse_domain_list( '   ' ) ) {
	$fail( 'parse_domain_list() must return an empty array for blank input.' );
}

// --- get_blocked_domains / is_blocked_domain --------------------------------

$domains = ADC_Security_Woo_Rules::get_blocked_domains( "evil.test\nmailinator.com" );

if ( ! in_array( 'evil.test', $domains, true ) || ! in_array( 'mailinator.com', $domains, true ) ) {
	$fail( 'get_blocked_domains() must merge custom domains into the built-in list.' );
}

if ( count( $domains ) !== count( array_unique( $domains ) ) ) {
	$fail( 'get_blocked_domains() must not return duplicates.' );
}

$blocked = array( 'mailinator.com', 'evil.test' );

if ( ! ADC_Security_Woo_Rules::is_blocked_domain( 'mailinator.com', $blocked ) ) {
	$fail( 'An exact domain match must be blocked.' );
}

if ( ! ADC_Security_Woo_Rules::is_blocked_domain( 'sub.mailinator.com', $blocked ) ) {
	$fail( 'Subdomains of a blocked domain must be blocked.' );
}

if ( ADC_Security_Woo_Rules::is_blocked_domain( 'notmailinator.com', $blocked ) ) {
	$fail( 'A domain that merely ends with the blocked name must NOT be blocked.' );
}

if ( ADC_Security_Woo_Rules::is_blocked_domain( 'mailinator.com.example.org', $blocked ) ) {
	$fail( 'A domain that only starts with a blocked name must NOT be blocked.' );
}

if ( ADC_Security_Woo_Rules::is_blocked_domain( '', $blocked ) ) {
	$fail( 'An empty domain must not be treated as blocked.' );
}

if ( ADC_Security_Woo_Rules::is_blocked_domain( 'gmail.com', $blocked ) ) {
	$fail( 'Legitimate providers must never be blocked by the default rules.' );
}

// The built-in list must not contain any common legitimate provider.
foreach ( array( 'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com', 'icloud.com' ) as $legit ) {
	if ( in_array( $legit, ADC_Security_Woo_Rules::DISPOSABLE_DOMAINS, true ) ) {
		$fail( "$legit must not be part of the disposable domain list." );
	}
}

// --- fixed-window counters --------------------------------------------------

$window = 600;

$state = ADC_Security_Woo_Rules::bump_window( false, 1000, $window );
if ( 1 !== $state['count'] || 1000.0 !== $state['start'] ) {
	$fail( 'The first bump must start a new window with a count of 1.' );
}

$state = ADC_Security_Woo_Rules::bump_window( $state, 1010, $window );
$state = ADC_Security_Woo_Rules::bump_window( $state, 1020, $window );
if ( 3 !== $state['count'] || 1000.0 !== $state['start'] ) {
	$fail( 'Bumps inside the window must increment the count and keep the start time.' );
}

// A bump exactly at the window boundary starts a fresh window.
$fresh = ADC_Security_Woo_Rules::bump_window( $state, 1600, $window );
if ( 1 !== $fresh['count'] || 1600.0 !== $fresh['start'] ) {
	$fail( 'A bump after the window elapsed must restart the counter.' );
}

// A clock that moved backwards must not corrupt the counter.
$skewed = ADC_Security_Woo_Rules::bump_window( $state, 500, $window );
if ( 1 !== $skewed['count'] || 500.0 !== $skewed['start'] ) {
	$fail( 'A backwards clock must restart the counter instead of inflating it.' );
}

if ( 3 !== ADC_Security_Woo_Rules::window_count( $state, 1200, $window ) ) {
	$fail( 'window_count() must return the count while the window is active.' );
}

if ( 0 !== ADC_Security_Woo_Rules::window_count( $state, 1601, $window ) ) {
	$fail( 'window_count() must return 0 once the window elapsed.' );
}

if ( 0 !== ADC_Security_Woo_Rules::window_count( 'garbage', 1200, $window ) ) {
	$fail( 'window_count() must treat corrupt state as an empty window.' );
}

// --- phone / address normalisation ------------------------------------------

if ( '40721123456' !== ADC_Security_Woo_Rules::normalize_phone( '+40 (721) 123-456' ) ) {
	$fail( 'normalize_phone() must keep digits only.' );
}

if ( '' !== ADC_Security_Woo_Rules::normalize_phone( '12345' ) || '' !== ADC_Security_Woo_Rules::normalize_phone( '' ) ) {
	$fail( 'normalize_phone() must reject values too short to identify a subscriber.' );
}

if ( 'str exemplu 10 ap 3|010101' !== ADC_Security_Woo_Rules::normalize_address( 'Str. Exemplu 10, Ap. 3', '010101' ) ) {
	$fail( 'normalize_address() must fold case and punctuation.' );
}

if ( ADC_Security_Woo_Rules::normalize_address( 'Str. Exemplu 10', '010101' ) === ADC_Security_Woo_Rules::normalize_address( 'Str. Exemplu 11', '010101' ) ) {
	$fail( 'normalize_address() must keep different street numbers apart.' );
}

if ( '' !== ADC_Security_Woo_Rules::normalize_address( 'abc', '' ) ) {
	$fail( 'normalize_address() must ignore addresses too short to be meaningful.' );
}

if ( 'str exemplu 10|010101' !== ADC_Security_Woo_Rules::normalize_address( 'Str. Exemplu 10', '010101' ) ) {
	$fail( 'normalize_address() must include the postcode when present.' );
}

// --- host helpers -----------------------------------------------------------

if ( 'www.example.com' !== ADC_Security_Woo_Rules::host_from_url( 'https://WWW.Example.com/checkout/?x=1' ) ) {
	$fail( 'host_from_url() must extract a lowercased host.' );
}

if ( 'shop.example.com' !== ADC_Security_Woo_Rules::host_from_url( '//shop.example.com' ) ) {
	$fail( 'host_from_url() must handle protocol-relative values.' );
}

if ( '' !== ADC_Security_Woo_Rules::host_from_url( 'not a url' ) ) {
	$fail( 'host_from_url() must return an empty string when there is no host.' );
}

if ( ! ADC_Security_Woo_Rules::is_same_host( 'www.example.com', 'example.com' ) ) {
	$fail( 'is_same_host() must ignore a leading www.' );
}

if ( ! ADC_Security_Woo_Rules::is_same_host( 'shop.example.com', 'example.com' ) ) {
	$fail( 'is_same_host() must accept subdomains of the site.' );
}

if ( ADC_Security_Woo_Rules::is_same_host( 'evil.com', 'example.com' ) ) {
	$fail( 'is_same_host() must reject unrelated hosts.' );
}

if ( ADC_Security_Woo_Rules::is_same_host( 'notexample.com', 'example.com' ) ) {
	$fail( 'is_same_host() must not match on a partial label.' );
}

// --- fixed-window counters with identities ----------------------------------

$state = ADC_Security_Woo_Rules::bump_window( false, 1000, $window, 'a@example.com' );
$state = ADC_Security_Woo_Rules::bump_window( $state, 1001, $window, 'b@example.com' );
$state = ADC_Security_Woo_Rules::bump_window( $state, 1002, $window, 'a@example.com' );

if ( 3 !== $state['count'] || 2 !== ADC_Security_Woo_Rules::window_distinct( $state ) ) {
	$fail( 'Identities must be deduplicated inside a window state.' );
}

if ( 0 !== ADC_Security_Woo_Rules::window_distinct( ADC_Security_Woo_Rules::bump_window( false, 1000, $window ) ) ) {
	$fail( 'window_distinct() must be 0 when no identity was tracked.' );
}

if ( 1 !== ADC_Security_Woo_Rules::window_distinct( ADC_Security_Woo_Rules::bump_window( $state, 1700, $window, 'c@example.com' ) ) ) {
	$fail( 'A new window must reset the tracked identities.' );
}

// Tracked identities are capped so a transient can never grow unbounded.
$capped = false;
for ( $i = 0; $i < 40; $i++ ) {
	$capped = ADC_Security_Woo_Rules::bump_window( $capped, 1000 + $i, $window, 'user' . $i . '@example.com' );
}

if ( ADC_Security_Woo_Rules::window_distinct( $capped ) > ADC_Security_Woo_Rules::MAX_TRACKED_IDENTITIES ) {
	$fail( 'The number of tracked identities must stay bounded.' );
}

// --- limits -----------------------------------------------------------------

if ( ADC_Security_Woo_Rules::is_over_limit( 999, 0 ) ) {
	$fail( 'A limit of 0 must disable the rule.' );
}

if ( ! ADC_Security_Woo_Rules::is_over_limit( 5, 5 ) ) {
	$fail( 'Reaching the limit must block.' );
}

if ( ADC_Security_Woo_Rules::is_over_limit( 4, 5 ) ) {
	$fail( 'Staying below the limit must not block.' );
}

// --- minimum submission time ------------------------------------------------

if ( ADC_Security_Woo_Rules::is_too_fast( 100, 101, 0 ) ) {
	$fail( 'A minimum of 0 seconds must disable the timing rule.' );
}

if ( ADC_Security_Woo_Rules::is_too_fast( 0, 101, 5 ) ) {
	$fail( 'A missing start time must never block.' );
}

if ( ! ADC_Security_Woo_Rules::is_too_fast( 100, 102, 5 ) ) {
	$fail( 'A submission 2s after the page loaded must trip a 5s minimum.' );
}

if ( ADC_Security_Woo_Rules::is_too_fast( 100, 110, 5 ) ) {
	$fail( 'A submission 10s after the page loaded must pass a 5s minimum.' );
}

fwrite( STDOUT, "WooCommerce rule tests passed.\n" );
