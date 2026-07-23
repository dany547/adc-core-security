<?php
/**
 * Lightweight policy tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

class WP_Error {
	private $code;
	private $message;

	public function __construct( $code, $message ) {
		$this->code = $code;
		$this->message = $message;
	}

	public function get_error_code() {
		return $this->code;
	}

	public function get_error_message() {
		return $this->message;
	}
}

function is_wp_error( $value ) {
	return $value instanceof WP_Error;
}

function sanitize_key( $key ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
}

function wp_unslash( $value ) {
	return $value;
}

function sanitize_text_field( $value ) {
	return trim( (string) $value );
}

function trailingslashit( $value ) {
	return rtrim( $value, '/\\' ) . '/';
}

$test_home = sys_get_temp_dir() . '/adc-security-htaccess-test-' . uniqid( '', true );
mkdir( $test_home, 0700, true );

function get_home_path() {
	global $test_home;
	return trailingslashit( $test_home );
}

$test_options = array();
function get_option( $key, $default = false ) {
	global $test_options;
	return array_key_exists( $key, $test_options ) ? $test_options[ $key ] : $default;
}

function update_option( $key, $value ) {
	global $test_options;
	$test_options[ $key ] = $value;
	return true;
}

function delete_option( $key ) {
	global $test_options;
	unset( $test_options[ $key ] );
	return true;
}

function current_time( $type, $gmt = false ) {
	return gmdate( 'Y-m-d H:i:s' );
}

require_once ABSPATH . 'includes/class-adc-security-htaccess.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$definitions = ADC_Security_Htaccess::get_rule_definitions();
$expected_keys = array(
	'block_xmlrpc_endpoint',
	'block_sensitive_files',
	'disable_upload_php',
);

if ( $expected_keys !== array_keys( $definitions ) ) {
	$fail( 'Fixed .htaccess rule keys changed unexpectedly.' );
}

$manager = new ADC_Security_Htaccess();
$block = $manager->build_block( $expected_keys );

if ( false === strpos( $block, ADC_Security_Htaccess::BEGIN_MARKER ) || false === strpos( $block, ADC_Security_Htaccess::END_MARKER ) ) {
	$fail( 'Generated .htaccess block is missing its markers.' );
}

foreach ( $expected_keys as $key ) {
	foreach ( $definitions[ $key ]['lines'] as $line ) {
		if ( false === strpos( $block, $line ) ) {
			$fail( 'Generated .htaccess block is missing a fixed rule line.' );
		}
	}
}

$untrusted = $manager->build_block( array( 'block_xmlrpc_endpoint', 'RewriteRule evil' ) );
if ( false !== strpos( $untrusted, 'RewriteRule evil' ) ) {
	$fail( 'Untrusted directive text was included in the generated block.' );
}

if ( false !== strpos( $block, "\r" ) ) {
	$fail( 'Generated .htaccess block contains unexpected carriage returns.' );
}

$_SERVER['SERVER_SOFTWARE'] = 'LiteSpeed';
$original = "# WordPress rules\nRewriteEngine On\n";
file_put_contents( $test_home . '/.htaccess', $original );

$result = $manager->apply( $expected_keys );
if ( is_wp_error( $result ) ) {
	$fail( 'Applying fixed .htaccess rules failed: ' . $result->get_error_message() );
}

$updated = file_get_contents( $test_home . '/.htaccess' );
if ( false === strpos( $updated, ADC_Security_Htaccess::BEGIN_MARKER ) || false === strpos( $updated, '# WordPress rules' ) ) {
	$fail( 'Applying fixed .htaccess rules did not preserve the external content.' );
}

$result = $manager->apply( array( 'block_xmlrpc_endpoint', 'untrusted-directive' ) );
if ( ! is_wp_error( $result ) || 'adc_htaccess_unknown_rule' !== $result->get_error_code() ) {
	$fail( 'Unknown .htaccess rules were not rejected.' );
}

$result = $manager->revert();
if ( is_wp_error( $result ) || $original !== file_get_contents( $test_home . '/.htaccess' ) ) {
	$fail( 'Revert did not restore the original .htaccess contents.' );
}

$result = $manager->apply( $expected_keys );
if ( is_wp_error( $result ) ) {
	$fail( 'Applying fixed rules before drift testing failed.' );
}
file_put_contents( $test_home . '/.htaccess', file_get_contents( $test_home . '/.htaccess' ) . "# External rule\n" );
$result = $manager->revert();
if ( is_wp_error( $result ) || "# WordPress rules\nRewriteEngine On\n# External rule\n" !== file_get_contents( $test_home . '/.htaccess' ) ) {
	$fail( 'Revert did not preserve an external .htaccess change.' );
}

$_SERVER['SERVER_SOFTWARE'] = 'nginx';
$result = $manager->apply( $expected_keys );
if ( ! is_wp_error( $result ) || 'adc_htaccess_unsupported_server' !== $result->get_error_code() ) {
	$fail( 'Unsupported server families were not rejected.' );
}

$_SERVER['SERVER_SOFTWARE'] = 'LiteSpeed';
file_put_contents( $test_home . '/.htaccess', "# BEGIN ADC Security\nmalformed\n" );
$result = $manager->apply( $expected_keys );
if ( ! is_wp_error( $result ) || 'adc_htaccess_invalid_markers' !== $result->get_error_code() ) {
	$fail( 'Malformed marker blocks were not rejected.' );
}

unlink( $test_home . '/.htaccess' );
rmdir( $test_home );

fwrite( STDOUT, "Fixed .htaccess policy tests passed.\n" );
