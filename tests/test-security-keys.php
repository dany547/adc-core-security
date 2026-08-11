<?php
/**
 * Lightweight policy tests for wp-config.php security key regeneration
 * that do not require a WordPress installation.
 */

define( 'ABSPATH', sys_get_temp_dir() . '/adc-security-keys-test-' . uniqid( '', true ) . '/' );
mkdir( ABSPATH, 0700, true );

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

function current_time( $type, $gmt = false ) {
	return gmdate( 'Y-m-d H:i:s' );
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

$mock_salt_response = null;
function wp_remote_get( $url, $args = array() ) {
	global $mock_salt_response;
	return $mock_salt_response;
}

function wp_remote_retrieve_response_code( $response ) {
	return isset( $response['response']['code'] ) ? $response['response']['code'] : 0;
}

function wp_remote_retrieve_body( $response ) {
	return isset( $response['body'] ) ? $response['body'] : '';
}

require_once dirname( __DIR__ ) . '/includes/class-adc-security-keys.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$key_names = ADC_Security_Keys::get_key_names();
if ( 8 !== count( $key_names ) ) {
	$fail( 'Expected exactly eight key names.' );
}

$build_salt_body = static function ( $suffix ) use ( $key_names ) {
	$lines = array();
	foreach ( $key_names as $name ) {
		$lines[] = "define('" . $name . "',         'value-" . $suffix . "-" . $name . "');";
	}
	return implode( "\n", $lines ) . "\n";
};

$build_config = static function ( $suffix ) use ( $key_names ) {
	$lines = array( '<?php', "define( 'DB_NAME', 'wp' );" );
	foreach ( $key_names as $name ) {
		$lines[] = "define('" . $name . "', 'old-" . $suffix . "-" . $name . "');";
	}
	$lines[] = "\$table_prefix = 'wp_';";
	$lines[] = '/* That\'s all, stop editing! Happy publishing. */';
	return implode( "\n", $lines ) . "\n";
};

$config_path = ABSPATH . 'wp-config.php';
file_put_contents( $config_path, $build_config( 'orig' ) );

$manager = new ADC_Security_Keys();

$resolved = $manager->get_wp_config_path();
if ( is_wp_error( $resolved ) || realpath( $config_path ) !== $resolved ) {
	$fail( 'wp-config.php path was not resolved correctly.' );
}

// Successful regeneration replaces every key definition in place.
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => $build_salt_body( 'new' ),
);

$result = $manager->regenerate();
if ( is_wp_error( $result ) ) {
	$fail( 'Regeneration failed unexpectedly: ' . $result->get_error_message() );
}

$updated = file_get_contents( $config_path );
foreach ( $key_names as $name ) {
	if ( false === strpos( $updated, 'value-new-' . $name ) ) {
		$fail( 'Regenerated wp-config.php is missing the new value for ' . $name );
	}
	if ( false !== strpos( $updated, 'old-orig-' . $name ) ) {
		$fail( 'Regenerated wp-config.php still contains the old value for ' . $name );
	}
}
if ( false === strpos( $updated, "define( 'DB_NAME', 'wp' );" ) ) {
	$fail( 'Regeneration altered unrelated wp-config.php content.' );
}

// Restore reverts to the exact pre-regeneration contents.
$restore_result = $manager->restore();
if ( is_wp_error( $restore_result ) ) {
	$fail( 'Restore failed unexpectedly: ' . $restore_result->get_error_message() );
}
if ( $build_config( 'orig' ) !== file_get_contents( $config_path ) ) {
	$fail( 'Restore did not return wp-config.php to its original contents.' );
}

$no_backup_result = $manager->restore();
if ( ! is_wp_error( $no_backup_result ) || 'adc_keys_no_backup' !== $no_backup_result->get_error_code() ) {
	$fail( 'Restoring without a backup was not rejected.' );
}

// An incomplete API response is rejected without touching the file.
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => "define('AUTH_KEY', 'only-one-key');\n",
);
$before = file_get_contents( $config_path );
$incomplete_result = $manager->regenerate();
if ( ! is_wp_error( $incomplete_result ) || 'adc_keys_incomplete_response' !== $incomplete_result->get_error_code() ) {
	$fail( 'An incomplete secret-key response was not rejected.' );
}
if ( $before !== file_get_contents( $config_path ) ) {
	$fail( 'wp-config.php was modified despite an incomplete secret-key response.' );
}

// A config file missing one of the expected definitions is rejected without a partial write.
file_put_contents( $config_path, "<?php\ndefine('AUTH_KEY', 'old');\n" );
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => $build_salt_body( 'partial' ),
);
$missing_definition_result = $manager->regenerate();
if ( ! is_wp_error( $missing_definition_result ) || 'adc_keys_definition_not_found' !== $missing_definition_result->get_error_code() ) {
	$fail( 'A wp-config.php missing key definitions was not rejected.' );
}
if ( "<?php\ndefine('AUTH_KEY', 'old');\n" !== file_get_contents( $config_path ) ) {
	$fail( 'wp-config.php was partially modified despite missing definitions.' );
}

// A non-200 API response is rejected without touching the file.
file_put_contents( $config_path, $build_config( 'orig2' ) );
$mock_salt_response = array(
	'response' => array( 'code' => 500 ),
	'body'     => '',
);
$fetch_failed_result = $manager->regenerate();
if ( ! is_wp_error( $fetch_failed_result ) || 'adc_keys_fetch_failed' !== $fetch_failed_result->get_error_code() ) {
	$fail( 'A failed secret-key request was not rejected.' );
}

// A commented-out define() earlier in the file must never be the line that
// gets replaced -- only the live, uncommented definition may be touched.
$commented_config = "<?php\n// define('AUTH_KEY', 'stale-commented-value');\n";
foreach ( $key_names as $name ) {
	$commented_config .= "define('" . $name . "', 'live-" . $name . "');\n";
}
file_put_contents( $config_path, $commented_config );
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => $build_salt_body( 'rotated' ),
);
$comment_result = $manager->regenerate();
if ( is_wp_error( $comment_result ) ) {
	$fail( 'Regeneration failed unexpectedly with a commented-out definition present: ' . $comment_result->get_error_message() );
}
$after_comment = file_get_contents( $config_path );
if ( false === strpos( $after_comment, "// define('AUTH_KEY', 'stale-commented-value');" ) ) {
	$fail( 'The commented-out define() line was modified; it must be left untouched.' );
}
$live_auth_key_lines = preg_grep( "/^define\('AUTH_KEY',/", explode( "\n", $after_comment ) );
if ( 1 !== count( $live_auth_key_lines ) ) {
	$fail( 'Regeneration produced more than one live AUTH_KEY definition.' );
}
if ( false === strpos( $after_comment, 'value-rotated-AUTH_KEY' ) ) {
	$fail( 'The live AUTH_KEY definition was not updated.' );
}

// Restoring after two consecutive regenerations must still recover the
// original, pre-regeneration keys -- not the intermediate rotated set.
delete_option( ADC_Security_Keys::BACKUP_OPTION );
$original_config = $build_config( 'first' );
file_put_contents( $config_path, $original_config );
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => $build_salt_body( 'first-rotation' ),
);
if ( is_wp_error( $manager->regenerate() ) ) {
	$fail( 'First of two consecutive regenerations failed unexpectedly.' );
}
$mock_salt_response = array(
	'response' => array( 'code' => 200 ),
	'body'     => $build_salt_body( 'second-rotation' ),
);
if ( is_wp_error( $manager->regenerate() ) ) {
	$fail( 'Second of two consecutive regenerations failed unexpectedly.' );
}
if ( is_wp_error( $manager->restore() ) ) {
	$fail( 'Restore after two consecutive regenerations failed unexpectedly.' );
}
if ( $original_config !== file_get_contents( $config_path ) ) {
	$fail( 'Restore after two consecutive regenerations did not recover the true original keys.' );
}

unlink( $config_path );
rmdir( ABSPATH );

fwrite( STDOUT, "Security key regeneration policy tests passed.\n" );
