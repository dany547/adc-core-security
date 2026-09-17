<?php
/**
 * WooCommerce abuse-prevention tests.
 *
 * These tests exercise ADC_Security_Woocommerce and ADC_Security_Users_Columns
 * through their public entry points (the same callbacks WordPress/WooCommerce
 * invoke), using lightweight stubs instead of a real WordPress installation.
 *
 * Only the WordPress APIs actually touched by the two classes are stubbed. If a
 * future change starts using another API, the test fails loudly here instead of
 * silently passing.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
define( 'MINUTE_IN_SECONDS', 60 );

// ---------------------------------------------------------------------------
// WordPress stubs
// ---------------------------------------------------------------------------

$GLOBALS['test_state'] = array(
	'options'    => array( 'adc_security_options' => array() ),
	'transients' => array(),
	'hooks'      => array(),
	'meta'       => array(),
	'ip'         => '203.0.113.10',
	'is_admin'   => false,
	'logged_in'  => false,
	'user'       => null,
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
function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
	$GLOBALS['test_state']['hooks'][ $hook ][] = array( $callback, $priority, $args );
}
function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
	add_action( $hook, $callback, $priority, $args );
}
function apply_filters( $tag, $value ) {
	return $value;
}
function did_action( $hook ) {
	return 1;
}
function is_admin() {
	return (bool) $GLOBALS['test_state']['is_admin'];
}
function is_user_logged_in() {
	return (bool) $GLOBALS['test_state']['logged_in'];
}
function current_user_can( $capability ) {
	return true;
}
function wp_unslash( $value ) {
	return is_string( $value ) ? stripslashes( $value ) : $value;
}
function esc_attr( $value ) {
	return htmlspecialchars( (string) $value, ENT_QUOTES );
}
function esc_html( $value ) {
	return htmlspecialchars( (string) $value, ENT_QUOTES );
}
function __( $text, $domain = null ) {
	return $text;
}
function wp_enqueue_script() {}
function wp_doing_cron() {
	return false;
}
function update_user_meta( $user_id, $key, $value ) {
	$GLOBALS['test_state']['meta'][ $user_id ][ $key ] = $value;
}
function get_user_meta( $user_id, $key, $single = false ) {
	return isset( $GLOBALS['test_state']['meta'][ $user_id ][ $key ] ) ? $GLOBALS['test_state']['meta'][ $user_id ][ $key ] : '';
}
function get_userdata( $user_id ) {
	return $GLOBALS['test_state']['user'];
}
function wp_date( $format, $timestamp = null ) {
	return gmdate( $format, $timestamp );
}
function is_checkout() {
	return true;
}
function is_cart() {
	return true;
}
function is_wp_error( $thing ) {
	return $thing instanceof WP_Error;
}
function home_url( $path = '' ) {
	return 'https://example.test' . $path;
}
function site_url( $path = '' ) {
	return 'https://example.test' . $path;
}
function wc_add_notice( $message, $type = 'success' ) {
	$GLOBALS['test_state']['notices'][] = array( 'message' => $message, 'type' => $type );
}
function esc_html__( $text, $domain = null ) {
	return $text;
}

// ---------------------------------------------------------------------------
// WordPress / WooCommerce test doubles
// ---------------------------------------------------------------------------

class WP_Error {
	public $errors = array();
	private $data = array();
	public function __construct( $code = '', $message = '', $data = '' ) {
		if ( '' !== $code ) {
			$this->errors[ $code ][] = $message;
			$this->data[ $code ]     = $data;
		}
	}
	public function add( $code, $message, $data = '' ) {
		$this->errors[ $code ][] = $message;
		$this->data[ $code ]     = $data;
	}
	public function get_error_codes() {
		return array_keys( $this->errors );
	}
	public function get_error_code() {
		$codes = array_keys( $this->errors );

		return $codes ? $codes[0] : '';
	}
	public function get_error_data( $code = '' ) {
		if ( '' === $code ) {
			$code = $this->get_error_code();
		}

		return isset( $this->data[ $code ] ) ? $this->data[ $code ] : null;
	}
}
class WP_User {
	public $ID              = 7;
	public $user_registered = '2026-01-02 03:04:05';
}
class WP_User_Query {
	private $vars = array();
	public function __construct( $vars = array() ) {
		$this->vars = $vars;
	}
	public function get( $key ) {
		return isset( $this->vars[ $key ] ) ? $this->vars[ $key ] : '';
	}
	public function set( $key, $value ) {
		$this->vars[ $key ] = $value;
	}
}
class WP_REST_Request {
	private $method;
	private $params;
	private $route = '';
	public function __construct( $method, $params = array() ) {
		$this->method = $method;
		$this->params = $params;
	}
	public function get_method() {
		return $this->method;
	}
	public function set_route( $route ) {
		$this->route = $route;
	}
	public function get_route() {
		return $this->route;
	}
	public function offsetExists( $key ) {
		return isset( $this->params[ $key ] );
	}
	public function offsetGet( $key ) {
		return isset( $this->params[ $key ] ) ? $this->params[ $key ] : null;
	}
}
class WC_Session {
	private $data = array();
	public function get( $key ) {
		return isset( $this->data[ $key ] ) ? $this->data[ $key ] : null;
	}
	public function set( $key, $value ) {
		$this->data[ $key ] = $value;
	}
}
class WC_Checkout {
	public $required = false;
	public $enabled  = true;
	public function is_registration_required() {
		return $this->required;
	}
	public function is_registration_enabled() {
		return $this->enabled;
	}
}
class WC_Customer {
	public $email    = '';
	public $phone    = '';
	public $address  = '';
	public $postcode = '';
	public function get_billing_email() {
		return $this->email;
	}
	public function get_billing_phone() {
		return $this->phone;
	}
	public function get_billing_address_1() {
		return $this->address;
	}
	public function get_billing_postcode() {
		return $this->postcode;
	}
}
class WC_Order {
	public $email    = '';
	public $phone    = '';
	public $address  = '';
	public $postcode = '';
	public $created  = null;
	public $meta     = array();
	public function get_billing_email() {
		return $this->email;
	}
	public function get_billing_phone() {
		return $this->phone;
	}
	public function get_billing_address_1() {
		return $this->address;
	}
	public function get_billing_postcode() {
		return $this->postcode;
	}
	public function get_date_created() {
		return $this->created;
	}
	public function get_meta( $key ) {
		return isset( $this->meta[ $key ] ) ? $this->meta[ $key ] : '';
	}
	public function update_meta_data( $key, $value ) {
		$this->meta[ $key ] = $value;
	}
	public function save_meta_data() {}
}
class WC {
	public $session;
	public $checkout;
	public function __construct() {
		$this->session  = new WC_Session();
		$this->checkout = new WC_Checkout();
	}
}
class WooCommerce {}
class ADC_Security_Test_RouteException extends Exception { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedClassFound
	public $error_code;
	public function __construct( $error_code, $message, $http_status_code = 400, $additional_data = array() ) {
		$this->error_code = $error_code;
		parent::__construct( $message, $http_status_code );
	}
	public function getErrorCode() {
		return $this->error_code;
	}
}
class ADC_Security_Settings {
	const OPTION_NAME = 'adc_security_options';
}
class ADC_Security_Ip {
	public static function get_client_ip() {
		return $GLOBALS['test_state']['ip'];
	}
}
class ADC_Security_Events {
	const SEVERITY_WARNING = 2;
	public static $logged = array();
	public static function log( $type, $severity, $args = array() ) {
		self::$logged[] = array(
			'type' => $type,
			'args' => $args,
		);
	}
}
class ADC_Security_Login {
	public $allowlisted = false;
	public function is_ip_allowlisted( $ip ) {
		return $this->allowlisted;
	}
}
class ADC_Security_Captcha {
	public $verified = true;
	public function verify_turnstile_response( $token ) {
		return $this->verified ? true : new WP_Error( 'turnstile_fail', 'CAPTCHA verification failed.' );
	}
}

class_alias( 'ADC_Security_Test_RouteException', 'Automattic\WooCommerce\StoreApi\Exceptions\RouteException' );

$GLOBALS['test_wc']         = new WC();
$GLOBALS['test_state']['user'] = new WP_User();

function WC() {
	return $GLOBALS['test_wc'];
}

require_once ABSPATH . 'includes/class-adc-security-woo-rules.php';
require_once ABSPATH . 'includes/class-adc-security-woocommerce.php';
require_once ABSPATH . 'includes/class-adc-security-users-columns.php';

// ---------------------------------------------------------------------------
// Test harness
// ---------------------------------------------------------------------------

$failures = 0;
$fail     = function ( $label ) use ( &$failures ) {
	$failures++;
	fwrite( STDERR, 'FAIL: ' . $label . PHP_EOL );
};

$defaults = array(
	'woo_checkout_protection'            => 1,
	'woo_checkout_honeypot'              => 1,
	'woo_checkout_min_seconds'           => 3,
	'woo_checkout_referrer_check'        => 'off',
	'woo_checkout_rate_limit'            => 30,
	'woo_cart_write_limit'               => 60,
	'woo_checkout_turnstile'             => 0,
	'woo_order_window_minutes'           => 60,
	'woo_order_ip_limit'                 => 10,
	'woo_order_email_limit'              => 20,
	'woo_order_phone_limit'              => 5,
	'woo_order_address_limit'            => 5,
	'woo_failed_order_limit'             => 5,
	'woo_registration_protection'        => 1,
	'woo_registration_honeypot'          => 1,
	'woo_registration_rate_limit'        => 5,
	'woo_registration_disable_checkout_accounts' => 0,
	'woo_registration_disable_myaccount_form'    => 0,
	'woo_registration_protect_wp_form'   => 1,
	'woo_block_disposable_emails'        => 1,
	'woo_monitor_mode'                   => 0,
);

$captcha = new ADC_Security_Captcha();
$login   = new ADC_Security_Login();
$woo     = new ADC_Security_Woocommerce( $login, $captcha );

/**
 * Reset options/transients/POST and re-read the options, like a fresh request.
 *
 * @param array $overrides Option overrides.
 */
$reset = function ( $overrides = array() ) use ( $defaults, $woo ) {
	$GLOBALS['test_state']['options']['adc_security_options'] = array_merge( $defaults, $overrides );
	$GLOBALS['test_state']['transients']                      = array();
	$_POST                                                    = array();
	$woo->init();
};

/**
 * Assert a condition.
 *
 * @param string $label Test label.
 * @param bool   $condition Result.
 */
$check = function ( $label, $condition ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $label );
	}
};

// ---------------------------------------------------------------------------
// Hook registration
// ---------------------------------------------------------------------------

$reset();
$hooks = $GLOBALS['test_state']['hooks'];

$check( 'classic checkout validation hook registered', isset( $hooks['woocommerce_after_checkout_validation'] ) );
$check( 'store API validation hook registered', isset( $hooks['woocommerce_store_api_checkout_update_customer_from_request'] ) );
$check( 'classic order recording hook registered', isset( $hooks['woocommerce_checkout_order_created'] ) );
$check( 'store API order recording hook registered', isset( $hooks['woocommerce_store_api_checkout_order_processed'] ) );
$check( 'classic checkout honeypot rendered', isset( $hooks['woocommerce_checkout_before_customer_details'] ) );
$check( 'my account registration honeypot rendered', isset( $hooks['woocommerce_register_form'] ) );
$check( 'WordPress registration honeypot rendered', isset( $hooks['register_form'] ) );
$check( 'WordPress registration errors filtered', isset( $hooks['registration_errors'] ) );
$check( 'WooCommerce registration errors filtered', isset( $hooks['woocommerce_process_registration_errors'] ) );

// ---------------------------------------------------------------------------
// Classic checkout rules
// ---------------------------------------------------------------------------

$reset();
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'clean classic checkout passes', array() === $errors->errors );

$reset();
$_POST['adc_woo_hp'] = 'filled-by-a-bot';
$errors              = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'classic honeypot blocks', in_array( 'adc_security_honeypot', $errors->get_error_codes(), true ) );

$reset();
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'bot@mailinator.com' ), $errors );
$check( 'disposable email blocks', in_array( 'adc_security_email_domain', $errors->get_error_codes(), true ) );

$reset( array( 'woo_checkout_rate_limit' => 2 ) );
for ( $i = 0; $i < 3; $i++ ) {
	$errors = new WP_Error();
	$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
}
$check( 'checkout attempt throttle blocks', in_array( 'adc_security_rate_limit', $errors->get_error_codes(), true ) );

// Order velocity: two orders from this IP with a limit of 2.
$reset( array( 'woo_order_ip_limit' => 2 ) );
$order        = new WC_Order();
$order->email = 'buyer@example.com';
$woo->record_order( $order );
$woo->record_order( $order );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'order velocity per IP blocks', in_array( 'adc_security_order_limit_ip', $errors->get_error_codes(), true ) );
$check( 'order IP meta stored for fraud review', '203.0.113.10' === $order->meta['_adc_security_order_ip'] );

$reset( array( 'woo_order_email_limit' => 1 ) );
$GLOBALS['test_state']['ip'] = '198.51.100.5';
$woo->record_order( $order );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'order velocity per email blocks', in_array( 'adc_security_order_limit_email', $errors->get_error_codes(), true ) );
$GLOBALS['test_state']['ip'] = '203.0.113.10';

// Minimum time on the checkout page (session stamp).
$reset( array( 'woo_checkout_min_seconds' => 5 ) );
WC()->session->set( ADC_Security_Woocommerce::SESSION_STARTED_KEY, time() - 1 );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'too-fast submission blocks', in_array( 'adc_security_too_fast', $errors->get_error_codes(), true ) );

WC()->session->set( ADC_Security_Woocommerce::SESSION_STARTED_KEY, time() - 30 );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'normal submission delay passes', array() === $errors->errors );

// The session stamp is set once and never pushed forward by later requests.
$reset( array( 'woo_checkout_min_seconds' => 5 ) );
$stamp = time() - 30;
WC()->session->set( ADC_Security_Woocommerce::SESSION_STARTED_KEY, $stamp );
$woo->mark_session_started();
$check( 'session stamp is not overwritten', $stamp === WC()->session->get( ADC_Security_Woocommerce::SESSION_STARTED_KEY ) );

// Monitor mode logs without blocking.
$reset( array( 'woo_monitor_mode' => 1 ) );
ADC_Security_Events::$logged = array();
$_POST['adc_woo_hp']         = 'filled-by-a-bot';
$errors                      = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'bot@mailinator.com' ), $errors );
$check( 'monitor mode never blocks', array() === $errors->errors );
$check( 'monitor mode logs the violations', count( ADC_Security_Events::$logged ) >= 2 );

// Turnstile on the classic checkout.
$reset(
	array(
		'woo_checkout_turnstile' => 1,
		'captcha_type'           => 'turnstile',
		'turnstile_site_key'     => 'site-key',
		'turnstile_secret_key'   => 'secret-key',
	)
);
$captcha->verified = false;
$errors            = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'failed Turnstile challenge blocks', in_array( 'adc_security_turnstile', $errors->get_error_codes(), true ) );
$captcha->verified = true;

// Origin / Referer enforcement.
$reset( array( 'woo_checkout_referrer_check' => 'mismatch' ) );
$_SERVER['HTTP_HOST']          = 'example.test';
$_SERVER['HTTP_REFERER']       = 'https://evil.example/checkout';
$errors                        = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'foreign referrer blocks', in_array( 'adc_security_referrer_mismatch', $errors->get_error_codes(), true ) );

unset( $_SERVER['HTTP_REFERER'] );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'missing referrer passes in mismatch mode', array() === $errors->errors );

$reset( array( 'woo_checkout_referrer_check' => 'required' ) );
unset( $_SERVER['HTTP_REFERER'] );
$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'missing referrer blocks in required mode', in_array( 'adc_security_referrer_missing', $errors->get_error_codes(), true ) );

$reset( array( 'woo_checkout_referrer_check' => 'mismatch' ) );
$_SERVER['HTTP_REFERER'] = 'https://www.example.test/checkout/';
$errors                  = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'same-site referrer passes through www', array() === $errors->errors );

$reset( array( 'woo_checkout_referrer_check' => 'off' ) );
$_SERVER['HTTP_REFERER'] = 'https://evil.example/checkout';
$errors                  = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'referrer check disabled by default', array() === $errors->errors );

// Phone / address velocity (an abuser rotating IPs and emails but not the buyer identity).
$reset( array( 'woo_order_phone_limit' => 1, 'woo_order_address_limit' => 0 ) );
$order           = new WC_Order();
$order->email    = 'buyer@example.com';
$order->phone    = '+40 (721) 111-222';
$order->address  = 'Str. Exemplu 10, Ap. 3';
$order->postcode = '010101';
$woo->record_order( $order );

$errors = new WP_Error();
$woo->validate_classic_checkout(
	array(
		'billing_email'     => 'another@example.com',
		'billing_phone'     => '40 721 111 222',
		'billing_address_1' => 'Altă Adresă 5',
	),
	$errors
);
$check( 'phone velocity blocks despite reformatting', in_array( 'adc_security_order_limit_phone', $errors->get_error_codes(), true ) );
$reset( array( 'woo_order_phone_limit' => 0, 'woo_order_address_limit' => 1 ) );
$woo->record_order( $order );

$errors = new WP_Error();
$woo->validate_classic_checkout(
	array(
		'billing_email'     => 'another@example.com',
		'billing_address_1' => 'str exemplu 10 ap 3',
		'billing_postcode'  => '010101',
	),
	$errors
);
$check( 'address velocity blocks despite punctuation changes', in_array( 'adc_security_order_limit_address', $errors->get_error_codes(), true ) );

// Failed orders (card testing signature).
$reset( array( 'woo_failed_order_limit' => 1, 'woo_order_phone_limit' => 0, 'woo_order_address_limit' => 0 ) );
$failed        = new WC_Order();
$failed->email = 'buyer@example.com';
$woo->handle_failed_order( 55, $failed );

$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'failed orders block the next attempt', in_array( 'adc_security_failed_orders_ip', $errors->get_error_codes(), true ) );

// Back-office status changes and stale failures must not count.
$reset( array( 'woo_failed_order_limit' => 1, 'woo_order_phone_limit' => 0, 'woo_order_address_limit' => 0 ) );
$GLOBALS['test_state']['is_admin'] = true;
$woo->handle_failed_order( 56, $failed );
$GLOBALS['test_state']['is_admin'] = false;

$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'wp-admin status changes do not count as failures', array() === $errors->errors );

$reset( array( 'woo_failed_order_limit' => 1, 'woo_order_phone_limit' => 0, 'woo_order_address_limit' => 0 ) );
$stale          = new WC_Order();
$stale->email   = 'buyer@example.com';
$stale->created = new DateTime( '-2 hours' );
$woo->handle_failed_order( 57, $stale );

$errors = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'buyer@example.com' ), $errors );
$check( 'late failures on old orders do not count', array() === $errors->errors );

// Cart write throttle (classic + Store API) and session stamping.
$reset( array( 'woo_cart_write_limit' => 2 ) );
$GLOBALS['test_state']['notices'] = array();
$first_pass                       = $woo->validate_classic_add_to_cart( true, 42 );
$second_pass                      = $woo->validate_classic_add_to_cart( true, 42 );
$third_pass                       = $woo->validate_classic_add_to_cart( true, 42 );
$check( 'classic add-to-cart throttles above the limit', true === $first_pass && true === $second_pass && false === $third_pass );
$check( 'cart limit tells the shopper why', ! empty( $GLOBALS['test_state']['notices'] ) );
$check( 'cart activity stamps the session start', (int) WC()->session->get( ADC_Security_Woocommerce::SESSION_STARTED_KEY ) > 0 );

$reset( array( 'woo_cart_write_limit' => 1 ) );
$cart_request = new WP_REST_Request( 'POST' );
$cart_request->set_route( '/wc/store/v1/cart/add-item' );
$first_cart_result  = $woo->guard_store_api_cart( null, null, $cart_request );
$second_cart_result = $woo->guard_store_api_cart( null, null, $cart_request );
$check( 'the first store API cart write passes', null === $first_cart_result );
$check(
	'store API cart writes return 429 when throttled',
	$second_cart_result instanceof WP_Error
		&& 'adc_security_cart_limit' === $second_cart_result->get_error_code()
		&& isset( $second_cart_result->get_error_data()['status'] )
		&& 429 === $second_cart_result->get_error_data()['status']
);

$reset( array( 'woo_cart_write_limit' => 1 ) );
$read_request = new WP_REST_Request( 'GET' );
$read_request->set_route( '/wc/store/v1/cart' );
$check( 'read-only cart requests are never throttled', null === $woo->guard_store_api_cart( null, null, $read_request ) );

$checkout_request = new WP_REST_Request( 'POST' );
$checkout_request->set_route( '/wc/store/v1/checkout' );
$check( 'non-cart routes are left alone', null === $woo->guard_store_api_cart( null, null, $checkout_request ) );

// Monitor mode flags the order that was allowed through, and the order screen shows it.
$reset( array( 'woo_monitor_mode' => 1, 'woo_order_phone_limit' => 0, 'woo_order_address_limit' => 0 ) );
$_POST['adc_woo_hp'] = 'filled-by-a-bot';
$errors              = new WP_Error();
$woo->validate_classic_checkout( array( 'billing_email' => 'bot@mailinator.com' ), $errors );

$flagged        = new WC_Order();
$flagged->email = 'bot@mailinator.com';
$woo->record_order( $flagged );
$check( 'monitor mode flags the allowed order', isset( $flagged->meta['_adc_security_review'] ) && 1 === $flagged->meta['_adc_security_review'] );
$check( 'monitor mode records the reasons', isset( $flagged->meta['_adc_security_review_reasons'] ) && false !== strpos( $flagged->meta['_adc_security_review_reasons'], 'honeypot' ) );

$ob_started = ob_start();
$woo->render_order_security_info( $flagged );
$order_html = (string) ob_get_clean();
$check( 'order screen shows the connection IP', false !== strpos( $order_html, '203.0.113.10' ) );
$check( 'order screen shows the flag reasons', false !== strpos( $order_html, 'honeypot' ) );

$clean_order = new WC_Order();
$ob_started  = ob_start();
$woo->render_order_security_info( $clean_order );
$empty_html = (string) ob_get_clean();
$check( 'order screen stays quiet without security data', '' === $empty_html );

// ---------------------------------------------------------------------------
// Store API (Checkout block) rules
// ---------------------------------------------------------------------------

$reset();
$customer        = new WC_Customer();
$customer->email = 'bot@yopmail.com';
$blocked         = false;

try {
	$woo->validate_store_api_checkout( $customer, new WP_REST_Request( 'POST', array( 'create_account' => true ) ) );
} catch ( Exception $e ) {
	$blocked = $e instanceof Automattic\WooCommerce\StoreApi\Exceptions\RouteException
		&& 'adc_security_email_domain' === $e->getErrorCode()
		&& 400 === $e->getCode();
}
$check( 'store API checkout blocks disposable email', $blocked );

$blocked = false;
try {
	$woo->validate_store_api_checkout( $customer, new WP_REST_Request( 'PATCH' ) );
} catch ( Exception $e ) {
	$blocked = true;
}
$check( 'store API PATCH requests are never blocked', ! $blocked );

// ---------------------------------------------------------------------------
// Account creation rules
// ---------------------------------------------------------------------------

$reset();
$errors = $woo->validate_woo_registration( new WP_Error(), 'user', 'pass', 'spam@guerrillamail.com' );
$check( 'registration blocks disposable email', in_array( 'adc_security_registration_blocked', $errors->get_error_codes(), true ) );

$reset();
$errors = $woo->validate_woo_registration( new WP_Error(), 'user', 'pass', 'ok@example.com' );
$check( 'clean registration passes', array() === $errors->errors );

$reset( array( 'woo_registration_rate_limit' => 1 ) );
$woo->validate_woo_registration( new WP_Error(), 'user', 'pass', 'ok@example.com' );
$errors = $woo->validate_woo_registration( new WP_Error(), 'user', 'pass', 'ok@example.com' );
$check( 'registration throttle per IP blocks', in_array( 'adc_security_registration_blocked', $errors->get_error_codes(), true ) );

$reset( array( 'woo_registration_disable_myaccount_form' => 1 ) );
$errors = $woo->validate_woo_registration( new WP_Error(), 'user', 'pass', 'ok@example.com' );
$check( 'disabled My Account form rejects direct POSTs', in_array( 'adc_security_registration_blocked', $errors->get_error_codes(), true ) );
$check( 'My Account form option hidden on the frontend', 'no' === $woo->hide_myaccount_registration_option( 'yes' ) );

$GLOBALS['test_state']['is_admin'] = true;
$check( 'My Account form option left alone in wp-admin', 'yes' === $woo->hide_myaccount_registration_option( 'yes' ) );
$GLOBALS['test_state']['is_admin'] = false;

$reset( array( 'woo_registration_disable_checkout_accounts' => 1 ) );
$check( 'checkout account creation disabled', false === $woo->disable_checkout_registration( true ) );
$GLOBALS['test_state']['is_admin'] = true;
$check( 'checkout account creation left alone in wp-admin', true === $woo->disable_checkout_registration( true ) );
$GLOBALS['test_state']['is_admin'] = false;

// ---------------------------------------------------------------------------
// Users screen columns
// ---------------------------------------------------------------------------

$GLOBALS['test_state']['meta']     = array();
$GLOBALS['test_state']['is_admin'] = true;
$columns                           = new ADC_Security_Users_Columns();

$headings = $columns->add_columns( array( 'username' => 'Username' ) );
$check( 'account created column added', isset( $headings['account_created'] ) );
$check( 'last login column added', isset( $headings['last_login'] ) );

$sortable = array(
	'account_created' => 'account_created',
	'last_login'      => 'last_login',
);
$check( 'both columns are sortable', $sortable === $columns->sortable_columns( array() ) );

$GLOBALS['test_state']['user'] = new WP_User();
$check( 'account created renders the registration date', '2026-01-02 03:04' === $columns->render_column( '', 'account_created', 7 ) );
$check( 'missing last login renders a dash', '&mdash;' === $columns->render_column( '', 'last_login', 7 ) );
$check( 'foreign columns pass through', 'passthrough' === $columns->render_column( 'passthrough', 'username', 7 ) );

$GLOBALS['test_state']['meta'][7]['_admin_last_login'] = gmmktime( 12, 30, 0, 6, 1, 2026 );
$check( 'last login renders the stored timestamp', '2026-06-01 12:30' === $columns->render_column( '', 'last_login', 7 ) );

$columns->record_last_login( 'admin', new WP_User() );
$check( 'successful login is recorded', is_int( $GLOBALS['test_state']['meta'][7]['_admin_last_login'] ) );

$query = new WP_User_Query( array( 'orderby' => 'account_created' ) );
$columns->sort_users( $query );
$check( 'account created sorting maps to registered', 'registered' === $query->get( 'orderby' ) );

$query = new WP_User_Query(
	array(
		'orderby' => 'last_login',
		'order'   => 'desc',
	)
);
$columns->sort_users( $query );
$meta_query = $query->get( 'meta_query' );
$orderby    = $query->get( 'orderby' );
$check( 'last login sorting keeps users without the meta key', is_array( $meta_query ) && 'OR' === $meta_query['relation'] );
$check( 'last login sorting orders by the meta clause', is_array( $orderby ) && 'DESC' === $orderby['adc_last_login'] );

$GLOBALS['test_state']['is_admin'] = false;

// ---------------------------------------------------------------------------

if ( $failures > 0 ) {
	fwrite( STDERR, $failures . " check(s) failed.\n" );
	exit( 1 );
}

fwrite( STDOUT, "WooCommerce guard tests passed.\n" );
