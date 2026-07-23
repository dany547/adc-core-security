<?php
/**
 * Lightweight CSP policy tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-csp.php';
require_once ABSPATH . 'includes/class-adc-security-hardening.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$policy = new ADC_Security_Csp_Policy();
$header_definitions = ADC_Security_Hardening::get_security_header_definitions();
$expected_header_keys = array(
	'content_type_options',
	'frame_options',
	'xss_protection',
	'referrer_policy',
	'csp',
	'permissions_policy',
	'hsts',
);

if ( $expected_header_keys !== array_keys( $header_definitions ) ) {
	$fail( 'Fine-tunable security header keys changed unexpectedly.' );
}

$strict = $policy->build( '', false );
if ( false !== strpos( $strict, "'unsafe-eval'" ) ) {
	$fail( 'Strict CSP unexpectedly allows unsafe-eval.' );
}

if ( false === strpos( $strict, 'https://www.googletagmanager.com' ) || false === strpos( $strict, 'style-src' ) ) {
	$fail( 'Common Google Tag Manager stylesheet origin is missing from style-src.' );
}

$compatibility = $policy->build( '', true );
if ( false === strpos( $compatibility, "'unsafe-eval'" ) ) {
	$fail( 'Compatibility CSP does not allow dynamic script compilation.' );
}

$custom = "default-src 'none'; script-src 'self';";
if ( $custom !== $policy->build( $custom, true ) ) {
	$fail( 'Custom CSP was not preserved exactly.' );
}

$frontend_paths = array(
	'/product/example/?attribute_pa_size=160',
	'/shop/?page=2',
	'/contact/',
);
foreach ( $frontend_paths as $path ) {
	if ( ! $policy->allows_dynamic_scripts( true, false, $path ) ) {
		$fail( 'Frontend compatibility was incorrectly rejected.' );
	}
}

$blocked_paths = array(
	'/wp-admin/options-general.php',
	'/wp-login.php?action=logout',
	'/wp-json/wc/store/v1/cart?context=view',
	'/wp-json?context=view',
);
foreach ( $blocked_paths as $path ) {
	if ( $policy->allows_dynamic_scripts( true, false, $path ) ) {
		$fail( 'Backend or API compatibility was incorrectly allowed.' );
	}
}

if ( $policy->allows_dynamic_scripts( true, true, '/product/example/' ) ) {
	$fail( 'Admin context incorrectly allowed dynamic scripts.' );
}

if ( $policy->allows_dynamic_scripts( true, false, '' ) ) {
	$fail( 'Malformed request context did not fail closed.' );
}

fwrite( STDOUT, "CSP policy tests passed.\n" );
