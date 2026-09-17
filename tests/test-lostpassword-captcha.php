<?php
/**
 * Lost-password captcha / honeypot tests (wp-login and Woo My Account share
 * lostpassword_post). Stubs only the WordPress APIs these callbacks touch.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
define( 'MINUTE_IN_SECONDS', 60 );

$GLOBALS['test_state'] = array(
	'options'    => array( 'adc_security_options' => array() ),
	'transients' => array(),
	'hooks'      => array(),
	'ip'         => '203.0.113.10',
);

function get_option( $name, $default = false ) {
	return array_key_exists( $name, $GLOBALS['test_state']['options'] ) ? $GLOBALS['test_state']['options'][ $name ] : $default;
}
function get_transient( $key ) {
	$state = $GLOBALS['test_state']['transients'];
	if ( ! isset( $state[ $key ] ) ) {
		return false;
	}
	return $state[ $key ]['expires'] > time() ? $state[ $key ]['value'] : false;
}
function set_transient( $key, $value, $ttl = 0 ) {
	$GLOBALS['test_state']['transients'][ $key ] = array(
		'value'   => $value,
		'expires' => time() + (int) $ttl,
	);
	return true;
}
function delete_transient( $key ) {
	unset( $GLOBALS['test_state']['transients'][ $key ] );
	return true;
}
function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	$GLOBALS['test_state']['hooks'][ $hook ][] = array( $callback, $priority, $args );
}
function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	add_action( $hook, $callback, $priority, $args );
}
function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}
function sanitize_text_field( $value ) {
	return trim( (string) $value );
}
function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}
function esc_attr( $value ) {
	return htmlspecialchars( (string) $value, ENT_QUOTES );
}
function wp_enqueue_script() {}
function wp_generate_password( $length = 12, $special = true ) {
	return str_repeat( 'a', (int) $length );
}

class WP_Error {
	public $errors = array();
	public function __construct( $code = '', $message = '', $data = '' ) {
		if ( '' !== $code ) {
			$this->errors[ $code ][] = $message;
		}
	}
	public function add( $code, $message, $data = '' ) {
		$this->errors[ $code ][] = $message;
	}
	public function get_error_codes() {
		return array_keys( $this->errors );
	}
	public function get_error_code() {
		$codes = array_keys( $this->errors );
		return $codes ? $codes[0] : '';
	}
	public function get_error_message( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}
		return isset( $this->errors[ $code ][0] ) ? $this->errors[ $code ][0] : '';
	}
}

class ADC_Security_Ip {
	public static function get_client_ip() {
		return $GLOBALS['test_state']['ip'];
	}
}

require_once ABSPATH . 'includes/class-adc-security-captcha.php';

$failures = 0;
$fail     = static function ( $label ) use ( &$failures ) {
	$failures++;
	fwrite( STDERR, 'FAIL: ' . $label . PHP_EOL );
};
$check = static function ( $label, $condition ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $label );
	}
};

$GLOBALS['test_state']['options']['adc_security_options'] = array(
	'captcha_type'   => 'math',
	'login_honeypot' => 1,
);
$captcha = new ADC_Security_Captcha();
$hooks   = $GLOBALS['test_state']['hooks'];

$check( 'lostpassword_form renders honeypot', isset( $hooks['lostpassword_form'] ) );
$check( 'woocommerce_lostpassword_form renders captcha', isset( $hooks['woocommerce_lostpassword_form'] ) );
$check( 'lostpassword_post validates math', isset( $hooks['lostpassword_post'] ) );

$_POST  = array( 'adc_hp_check' => 'filled-by-a-bot' );
$errors = new WP_Error();
$captcha->validate_honeypot_lostpassword( $errors );
$check( 'lost-password honeypot blocks', in_array( 'honeypot_fail', $errors->get_error_codes(), true ) );

$_POST  = array();
$errors = new WP_Error();
$captcha->validate_honeypot_lostpassword( $errors );
$check( 'empty honeypot passes', array() === $errors->errors );

$_POST  = array();
$errors = new WP_Error();
$captcha->validate_math_lostpassword( $errors );
$check( 'missing math captcha blocks', in_array( 'captcha_error', $errors->get_error_codes(), true ) );

set_transient( 'adc_math_captcha_token1', 7, 300 );
$_POST  = array(
	'adc_math_captcha' => '7',
	'adc_math_token'   => 'token1',
);
$errors = new WP_Error();
$captcha->validate_math_lostpassword( $errors );
$check( 'correct math captcha passes', array() === $errors->errors );

set_transient( 'adc_math_captcha_token2', 7, 300 );
$_POST  = array(
	'adc_math_captcha' => '1',
	'adc_math_token'   => 'token2',
);
$errors = new WP_Error();
$captcha->validate_math_lostpassword( $errors );
$check( 'wrong math captcha blocks', in_array( 'captcha_error', $errors->get_error_codes(), true ) );

if ( $failures > 0 ) {
	fwrite( STDERR, $failures . " check(s) failed.\n" );
	exit( 1 );
}

fwrite( STDOUT, "Lost-password captcha tests passed.\n" );
