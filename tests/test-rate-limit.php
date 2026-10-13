<?php
/**
 * Lightweight token-bucket math tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-rate-limit.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

// No time elapsed: token count is unchanged.
$tokens = ADC_Security_Rate_Limit::refill( 5, 0, 20, 6 );
if ( abs( $tokens - 5.0 ) > 0.0001 ) {
	$fail( "Expected 5 tokens with no elapsed time, got $tokens." );
}

// Exactly one refill interval elapsed: gains exactly one token.
$tokens = ADC_Security_Rate_Limit::refill( 5, 6, 20, 6 );
if ( abs( $tokens - 6.0 ) > 0.0001 ) {
	$fail( "Expected 6 tokens after one refill interval, got $tokens." );
}

// Refilling never exceeds capacity.
$tokens = ADC_Security_Rate_Limit::refill( 19, 3600, 20, 6 );
if ( abs( $tokens - 20.0 ) > 0.0001 ) {
	$fail( "Expected refill to cap at capacity 20, got $tokens." );
}

// Negative elapsed time (clock skew) must not remove tokens.
$tokens = ADC_Security_Rate_Limit::refill( 5, -10, 20, 6 );
if ( abs( $tokens - 5.0 ) > 0.0001 ) {
	$fail( "Expected negative elapsed time to be treated as zero, got $tokens." );
}

// Partial refill: half an interval yields half a token.
$tokens = ADC_Security_Rate_Limit::refill( 0, 3, 20, 6 );
if ( abs( $tokens - 0.5 ) > 0.0001 ) {
	$fail( "Expected 0.5 tokens after half a refill interval, got $tokens." );
}

// Bucket step: a new bucket starts full and one token is taken.
$step = ADC_Security_Rate_Limit::step( null, 1000.0, 20, 3 );
if ( ! $step['allowed'] || abs( $step['bucket']['tokens'] - 19.0 ) > 0.0001 ) {
	$fail( 'Expected a new bucket to allow one request and keep 19 tokens.' );
}

// Less than one token available: refused, and the stored tokens are kept.
$step = ADC_Security_Rate_Limit::step( array( 'tokens' => 0.5, 'updated' => 1000.0 ), 1000.0, 20, 3 );
if ( $step['allowed'] || abs( $step['bucket']['tokens'] - 0.5 ) > 0.0001 ) {
	$fail( 'Expected an empty bucket to refuse a request without taking a token.' );
}

// One refill interval later the bucket allows one request again.
$step = ADC_Security_Rate_Limit::step( array( 'tokens' => 0.0, 'updated' => 1000.0 ), 1003.0, 20, 3 );
if ( ! $step['allowed'] || abs( $step['bucket']['tokens'] - 0.0 ) > 0.0001 ) {
	$fail( 'Expected one token after one refill interval.' );
}

// A burst of 20 is allowed from a new bucket, the 21st is refused.
$bucket = null;
for ( $i = 0; $i < 20; $i++ ) {
	$step   = ADC_Security_Rate_Limit::step( $bucket, 1000.0, 20, 3 );
	$bucket = $step['bucket'];
	if ( ! $step['allowed'] ) {
		$fail( 'Expected request ' . ( $i + 1 ) . ' of the burst to be allowed.' );
	}
}
if ( ADC_Security_Rate_Limit::step( $bucket, 1000.0, 20, 3 )['allowed'] ) {
	$fail( 'Expected the 21st request in a burst to be refused.' );
}

fwrite( STDOUT, "Rate limit tests passed.\n" );
