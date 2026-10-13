<?php
/**
 * Lightweight virtual patch matcher tests that do not require a WordPress
 * installation. They cover the two pure matchers the request guards rely on:
 * encoded path-traversal detection (CVE-2026-87902) and author query-argument
 * detection (CVE-2026-60137).
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

if ( ! function_exists( 'sanitize_key' ) ) {
	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
	}
}

require_once ABSPATH . 'includes/class-adc-security-virtual-patch.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$assert = static function ( $condition, $message ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $message );
	}
};

// -------------------------------------------------------------------------
// Path traversal (CVE-2026-87902)
// -------------------------------------------------------------------------

$traversal_payloads = array(
	// As PHP hands it to the plugin: the request body was already decoded once.
	'templates%252E%252E%252F%252E%252E%252Findex' => 'double-encoded traversal (as received by PHP)',
	// The raw body of the published proof of concept.
	'templates%25252E%25252E%25252Findex'          => 'triple-encoded traversal (raw body)',
	'..%2Fwp-config'                                 => 'plain traversal with encoded separator',
	'../../wp-config'                                => 'plain traversal',
	'foo..'                                          => 'trailing double dot',
	"foo\0bar"                                       => 'null byte',
);

foreach ( $traversal_payloads as $payload => $label ) {
	$assert( ADC_Security_Virtual_Patch::contains_traversal( $payload ), 'Traversal not detected: ' . $label . '.' );
}

$legitimate_payloads = array(
	'about-us'            => 'plain slug',
	'parent/child'        => 'hierarchical page slug',
	'1.5-things'          => 'slug with a single dot',
	'caf%C3%A9'           => 'percent-encoded non-ASCII slug',
	'a%2eb'               => 'encoded single dot',
	'contact'             => 'simple slug',
	''                    => 'empty value',
);

foreach ( $legitimate_payloads as $payload => $label ) {
	$assert( ! ADC_Security_Virtual_Patch::contains_traversal( $payload ), 'False positive on ' . $label . ' (' . $payload . ').' );
}

$assert( ! ADC_Security_Virtual_Patch::contains_traversal( array( 'x' ) ), 'Non-string value must not match.' );
$assert( ! ADC_Security_Virtual_Patch::contains_traversal( null ), 'Null value must not match.' );

// -------------------------------------------------------------------------
// Author query-argument injection (CVE-2026-60137)
// -------------------------------------------------------------------------

$assert( ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_in', '1' ), 'author__not_in must match.' );
$assert( ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__in', '1,2' ), 'author__in must match.' );
$assert( ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_in', array( 1 ) ), 'Array value must match.' );
$assert( ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_in', '0' ), 'The string "0" is a value and must match.' );

$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_in', '' ), 'Empty value must not match.' );
$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_in', array() ), 'Empty array must not match.' );
$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'author', '1' ), 'Plain author argument must not match.' );
$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'author_in', '1' ), 'author_in (single underscore) must not match.' );
$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'author__not_ins', '1' ), 'Suffixed key must not match.' );
$assert( ! ADC_Security_Virtual_Patch::is_author_injection_arg( 'myauthor__in', '1' ), 'Prefixed key must not match.' );

$assert(
	ADC_Security_Virtual_Patch::contains_author_injection_arg( array( 's' => 'x', 'nested' => array( 'author__not_in' => '2' ) ) ),
	'Nested author__not_in must match.'
);
$assert(
	! ADC_Security_Virtual_Patch::contains_author_injection_arg( array( 'author' => '1', 's' => 'search' ) ),
	'Ordinary request arguments must not match.'
);
$assert(
	! ADC_Security_Virtual_Patch::contains_author_injection_arg( array( 's' => 'search' ), 99 ),
	'Recursion beyond the depth guard must not match.'
);

// Bracket notation passed to WP_Query directly (author__not_in[0]=1).
$assert(
	ADC_Security_Virtual_Patch::contains_author_injection_arg( array( 'author__not_in' => array( 0 => '1' ) ) ),
	'Bracket-notation author__not_in must match.'
);

// -------------------------------------------------------------------------
// Rule registry
// -------------------------------------------------------------------------

$keys = ADC_Security_Virtual_Patch::get_rule_keys();
$assert( 3 === count( $keys ), 'Expected three rules, got ' . count( $keys ) . '.' );

foreach ( $keys as $key ) {
	$definitions = ADC_Security_Virtual_Patch::get_rule_definitions();
	$assert( isset( $definitions[ $key ]['label'], $definitions[ $key ]['description'] ), 'Rule "' . $key . '" is missing its label or description.' );
}

$assert( array() === ADC_Security_Virtual_Patch::get_enabled_rules( array() ), 'No rules must be enabled by default.' );
$assert(
	array( ADC_Security_Virtual_Patch::RULE_REST_BATCH_UNAUTH ) === ADC_Security_Virtual_Patch::get_enabled_rules(
		array( 'virtual_patch_rules' => array( 'block_rest_batch_unauth', 'not_a_rule' ) )
	),
	'Unknown rule keys must be dropped from the enabled set.'
);
$assert(
	array() === ADC_Security_Virtual_Patch::get_enabled_rules( array( 'virtual_patch_rules' => 'block_rest_batch_unauth' ) ),
	'A non-array rule value must be ignored.'
);

echo 'Virtual patch tests passed.' . PHP_EOL;
