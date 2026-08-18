<?php
/**
 * Lightweight security score tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-score.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

// Nothing configured: score should be 0 and every check should fail.
$empty = ADC_Security_Score::calculate( array(), array(), array(), array( 'https' => false, 'default_admin_user' => true, 'admins_without_2fa' => 1 ) );
if ( 0 !== $empty['score'] ) {
	$fail( 'Empty configuration should score 0, got ' . $empty['score'] . '.' );
}
if ( 'F' !== $empty['grade'] ) {
	$fail( 'Empty configuration should grade F, got ' . $empty['grade'] . '.' );
}
foreach ( $empty['checks'] as $check ) {
	if ( $check['passed'] ) {
		$fail( 'Check "' . $check['id'] . '" unexpectedly passed with no configuration.' );
	}
}

// Everything enabled plus a healthy htaccess/keys status: score should be 100.
$full_options = array(
	'custom_login_slug'                => 'secret-login',
	'brute_force_protection'           => 1,
	'disable_xmlrpc'                   => 1,
	'disable_file_editor'              => 1,
	'prevent_user_enumeration'         => 1,
	'security_headers'                 => 1,
	'security_header_toggles'          => array( 'hsts', 'frame_options' ),
	'captcha_type'                     => 'math',
	'disable_pingbacks'                => 1,
	'admin_session_expiration_enabled' => 1,
);
$full = ADC_Security_Score::calculate(
	$full_options,
	array( 'managed' => true ),
	array( 'has_backup' => true ),
	array(
		'https'              => true,
		'default_admin_user' => false,
		'admins_without_2fa' => 0,
	)
);
if ( 100 !== $full['score'] ) {
	$fail( 'Fully hardened configuration should score 100, got ' . $full['score'] . '.' );
}
if ( 'A' !== $full['grade'] ) {
	$fail( 'Fully hardened configuration should grade A, got ' . $full['grade'] . '.' );
}

// A default "admin" account with manage_options should fail its own check
// regardless of everything else being enabled.
$with_default_admin = ADC_Security_Score::calculate(
	$full_options,
	array( 'managed' => true ),
	array( 'has_backup' => true ),
	array(
		'https'              => true,
		'default_admin_user' => true,
		'admins_without_2fa' => 0,
	)
);
if ( $with_default_admin['score'] >= $full['score'] ) {
	$fail( 'A default admin username should reduce the score below the fully hardened baseline.' );
}

$grade_map = array(
	100 => 'A',
	90  => 'A',
	89  => 'B',
	75  => 'B',
	74  => 'C',
	60  => 'C',
	59  => 'D',
	40  => 'D',
	39  => 'F',
	0   => 'F',
);
foreach ( $grade_map as $score => $expected_grade ) {
	$grade = ADC_Security_Score::grade_for_score( $score );
	if ( $expected_grade !== $grade ) {
		$fail( "Score $score should grade $expected_grade, got $grade." );
	}
}

fwrite( STDOUT, "Security score tests passed.\n" );
