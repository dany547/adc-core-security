<?php
/**
 * Proves the 1.13.2 upgrade (service presets moved into csp_extra_sources) keeps the generated policy byte-identical.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-csp.php';
require_once ABSPATH . 'includes/class-adc-security-csp-scanner.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$policy = new ADC_Security_Csp_Policy();
$scanner = 'ADC_Security_Csp_Scanner';

$preset_sets = array(
	array(),
	array( 'gtm' ),
	array( 'ga4', 'gtm' ),
	array( 'google_ads', 'stripe', 'recaptcha' ),
	array( 'youtube', 'vimeo', 'google_fonts', 'google_maps', 'paypal', 'facebook_pixel', 'turnstile' ),
	array_keys( ADC_Security_Csp_Policy::get_service_presets() ),
);

$extra_sets = array(
	array(),
	array(
		'script-src' => array( 'https://cdn.one.net', 'https://www.googletagmanager.com', 'not a source' ),
		'img-src'    => array( 'https://img.one.net', 'https://img.one.net/', 'data:' ),
		'connect-src' => array( 'https://api.two.org' ),
		'worker-src' => array(),
		'bogus-src'  => array( 'https://ignored.example' ),
	),
	array(
		'frame-src' => array( 'https://www.youtube.com', 'https://player.vimeo.com/video/' ),
		'font-src'  => array( 'https://fonts.gstatic.com' ),
	),
);

$removed_sets = array(
	array(),
	array( 'img-src' => array( 'https:' ) ),
	array( 'script-src' => array( 'https://www.googletagmanager.com', "'unsafe-inline'" ) ),
	array( 'default-src' => array( "'self'" ), 'frame-src' => array( 'https://www.google.com' ) ),
);

$count = 0;
foreach ( $preset_sets as $presets ) {
	foreach ( $extra_sets as $extra ) {
		foreach ( $removed_sets as $removed ) {
			foreach ( array( false, true ) as $dynamic ) {
				foreach ( array( '', 'https://reports.site.test/csp' ) as $report ) {
					$before   = $policy->build_generated( $presets, $extra, $removed, $dynamic, $report );
					$migrated = $scanner::expand_presets( $presets, $extra );
					$after    = $policy->build_generated( array(), $migrated, $removed, $dynamic, $report );
					$count++;
					if ( $before !== $after ) {
						$fail( "Migrated policy differs for presets " . json_encode( $presets ) . "\nbefore: $before\nafter:  $after" );
					}
				}
			}
		}
	}
}

// Migrated storage holds only directives the policy supports, and no preset keys leak into it.
$migrated = $scanner::expand_presets( array( 'gtm', 'stripe' ), array( 'img-src' => array( 'https://img.one.net' ) ) );
$supported = ADC_Security_Csp_Policy::get_directives();
foreach ( array_keys( $migrated ) as $directive ) {
	if ( ! in_array( $directive, $supported, true ) || ! is_array( $migrated[ $directive ] ) ) {
		$fail( 'Migrated storage has an unexpected directive: ' . $directive );
	}
}

// Running the expansion again on the migrated storage (with no presets) changes nothing.
$again = $scanner::expand_presets( array(), $migrated );
if ( $again !== $migrated ) {
	$fail( 'Expansion is not idempotent on migrated storage.' );
}

fwrite( STDOUT, "CSP migration tests passed ($count policy comparisons).\n" );
