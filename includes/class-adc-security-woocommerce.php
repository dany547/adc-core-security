<?php
/**
 * ADC Security WooCommerce Guard
 *
 * Abuse prevention for WooCommerce stores. It throttles checkout attempts per
 * IP, limits order velocity per IP and billing email, rejects disposable email
 * domains, offers a classic-checkout honeypot plus an optional Cloudflare
 * Turnstile challenge, and filters account creation on the My Account form,
 * the checkout "create an account" option, and the WordPress registration form.
 *
 * Every rule is enforced server-side, covers both the classic (shortcode)
 * checkout and the Checkout block (Store API), records an audit-log event, and
 * can run in "monitor mode" (log only, never block) while thresholds are tuned.
 *
 * The module does nothing at all when WooCommerce is not active.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Woocommerce {

	/**
	 * Checkout attempts are counted over this many seconds.
	 */
	const CHECKOUT_WINDOW = 600;

	/**
	 * New accounts are counted over this many seconds.
	 */
	const REGISTRATION_WINDOW = 3600;

	/**
	 * Name of the invisible honeypot field shared by the protected forms.
	 */
	const HONEYPOT_FIELD = 'adc_woo_hp';

	/**
	 * Session key holding the moment this session started interacting with the
	 * cart or the checkout pages.
	 */
	const SESSION_STARTED_KEY = 'adc_woo_session_started';

	/**
	 * Plugin options.
	 *
	 * @var array
	 */
	private $options = array();

	/**
	 * Rules that matched while monitor mode was active, used to flag the order
	 * that was allowed through.
	 *
	 * @var array
	 */
	private $review_reasons = array();

	/**
	 * Captcha module, reused for the optional Turnstile challenge.
	 *
	 * @var ADC_Security_Captcha|null
	 */
	private $captcha;

	/**
	 * Constructor.
	 *
	 * @param mixed                     $login   Deprecated and ignored; the IP allowlist is read via ADC_Security_Ip.
	 * @param ADC_Security_Captcha|null $captcha Captcha helper (Turnstile).
	 */
	public function __construct( $login = null, $captcha = null ) {
		$this->captcha = $captcha instanceof ADC_Security_Captcha ? $captcha : null;

		// WooCommerce may load after this plugin; wait until every plugin is loaded.
		if ( did_action( 'plugins_loaded' ) ) {
			$this->init();
		} else {
			add_action( 'plugins_loaded', array( $this, 'init' ), 20 );
		}
	}

	/**
	 * Register the enabled rules. Runs once WooCommerce (and its classes) are loaded.
	 */
	public function init() {
		if ( ! class_exists( 'WooCommerce' ) ) {
			return;
		}

		$this->options = get_option( ADC_Security_Settings::OPTION_NAME, array() );

		if ( ! $this->is_enabled( 'woo_checkout_protection' ) && ! $this->is_enabled( 'woo_registration_protection' ) ) {
			return;
		}

		$this->init_checkout_hooks();

		if ( $this->is_enabled( 'woo_registration_protection' ) ) {
			$this->init_registration_hooks();
		}
	}

	// -------------------------------------------------------------------------
	// Checkout hooks
	// -------------------------------------------------------------------------

	/**
	 * Register the checkout-side hooks.
	 */
	private function init_checkout_hooks() {
		// Classic checkout validation (order is only created when no error notice is left).
		add_action( 'woocommerce_after_checkout_validation', array( $this, 'validate_classic_checkout' ), 10, 2 );

		// Checkout block / Store API: runs before the draft order and any account is created.
		add_action( 'woocommerce_store_api_checkout_update_customer_from_request', array( $this, 'validate_store_api_checkout' ), 10, 2 );

		if ( $this->is_enabled( 'woo_checkout_protection' ) ) {
			add_action( 'woocommerce_checkout_order_created', array( $this, 'record_order' ), 10, 1 );
			add_action( 'woocommerce_store_api_checkout_order_processed', array( $this, 'record_order' ), 10, 1 );
			add_action( 'template_redirect', array( $this, 'mark_session_started' ) );
			add_action( 'woocommerce_order_status_failed', array( $this, 'handle_failed_order' ), 10, 2 );
			// Official HPOS recipe: add_meta_box on shop_order or wc_get_page_screen_id( 'shop-order' ).
			add_action( 'add_meta_boxes', array( $this, 'register_order_metabox' ) );

			add_filter( 'manage_edit-shop_order_columns', array( $this, 'add_orders_column' ) );
			add_action( 'manage_shop_order_posts_custom_column', array( $this, 'render_orders_column_legacy' ), 10, 2 );
			add_filter( 'woocommerce_shop_order_list_table_columns', array( $this, 'add_orders_column' ) );
			add_action( 'woocommerce_shop_order_list_table_custom_column', array( $this, 'render_orders_column_hpos' ), 10, 2 );
			add_filter( 'views_edit-shop_order', array( $this, 'add_flagged_orders_view' ) );
			add_filter( 'views_woocommerce_page_wc-orders', array( $this, 'add_flagged_orders_view' ) );
			add_filter( 'woocommerce_order_query_args', array( $this, 'filter_flagged_orders_query_args' ) );
			add_action( 'pre_get_posts', array( $this, 'filter_flagged_orders_legacy_query' ) );

			// Classic shortcode cart still uses this core filter. Store API / Checkout
			// block docs mark it deprecated because it relies on wc_add_notice; those
			// requests are handled below via rest_pre_dispatch (429) and
			// woocommerce_store_api_validate_add_to_cart.
			add_filter( 'woocommerce_add_to_cart_validation', array( $this, 'validate_classic_add_to_cart' ), 10, 2 );
			add_action( 'woocommerce_store_api_validate_add_to_cart', array( $this, 'stamp_store_api_add_to_cart' ), 10, 2 );
			add_filter( 'rest_pre_dispatch', array( $this, 'guard_store_api_cart' ), 20, 3 );

			if ( $this->is_enabled( 'woo_checkout_honeypot' ) ) {
				add_action( 'woocommerce_checkout_before_customer_details', array( $this, 'render_honeypot' ) );
			}

			if ( $this->is_turnstile_enabled() ) {
				add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_turnstile' ) );
				add_action( 'woocommerce_review_order_before_submit', array( $this, 'render_turnstile' ) );
			}
		}
	}

	/**
	 * Validate a classic (shortcode) checkout submission.
	 *
	 * @param array    $data   Posted checkout data, sanitized by WooCommerce.
	 * @param WP_Error $errors Validation errors collector.
	 */
	public function validate_classic_checkout( $data, $errors ) {
		if ( ! $errors instanceof WP_Error ) {
			return;
		}

		$email = is_array( $data ) && isset( $data['billing_email'] ) ? $data['billing_email'] : '';

		if ( $this->is_enabled( 'woo_checkout_protection' ) ) {
			$reason = $this->evaluate_checkout( $this->identity_from_checkout_data( $data ), 'classic' );
			if ( is_array( $reason ) ) {
				$errors->add( 'adc_security_' . $reason['code'], $reason['message'] );
				return;
			}
		}

		if ( $this->is_enabled( 'woo_registration_protection' ) && $this->classic_checkout_creates_account( $data ) ) {
			$reason = $this->evaluate_registration( $email, 'checkout' );
			if ( is_array( $reason ) ) {
				$errors->add( 'adc_security_' . $reason['code'], $reason['message'] );
			}
		}
	}

	/**
	 * Validate a Checkout block / Store API place-order request.
	 *
	 * Only POST (place order) requests are inspected: PATCH requests merely
	 * update the draft order while the shopper types and must never be blocked.
	 *
	 * @param mixed           $customer WC_Customer built from the request.
	 * @param WP_REST_Request $request  Current request.
	 * @throws Exception RouteException (Store API) when a rule blocks the order.
	 */
	public function validate_store_api_checkout( $customer, $request ) {
		if ( ! $request instanceof WP_REST_Request || 'POST' !== $request->get_method() ) {
			return;
		}

		$email = ( $customer instanceof WC_Customer ) ? (string) $customer->get_billing_email() : '';

		if ( $this->is_enabled( 'woo_checkout_protection' ) ) {
			$reason = $this->evaluate_checkout( $this->identity_from_customer( $customer ), 'store-api' );
			if ( is_array( $reason ) ) {
				$this->abort_store_api_checkout( $reason );
			}
		}

		if ( $this->is_enabled( 'woo_registration_protection' ) && $this->store_api_checkout_creates_account( $request ) ) {
			$reason = $this->evaluate_registration( $email, 'checkout' );
			if ( is_array( $reason ) ) {
				$this->abort_store_api_checkout( $reason );
			}
		}
	}

	/**
	 * Throw the Store API exception that turns a blocked checkout into a
	 * checkout-block error message instead of a placed order.
	 *
	 * @param array $reason Result of evaluate_checkout()/evaluate_registration().
	 * @throws Exception RouteException when the Store API is present.
	 */
	private function abort_store_api_checkout( array $reason ) {
		$exception_class = 'Automattic\WooCommerce\StoreApi\Exceptions\RouteException';

		if ( class_exists( $exception_class ) ) {
			throw new $exception_class( 'adc_security_' . $reason['code'], $reason['message'], 400 );
		}

		// Defensive fallback: the hook only fires from the Store API, so this
		// should be unreachable. Never let a missing class allow the order.
		$this->log( 'woo_checkout_blocked', ADC_Security_Ip::get_client_ip(), 'store-api', array( 'reason' => $reason['code'] ) );
		throw new Exception( $reason['message'] ); // phpcs:ignore WordPress.Security.EscapeOutput.ExceptionNotEscaped
	}

	/**
	 * Stamp the session the first time it touches the cart or the checkout pages.
	 *
	 * Set once per session on purpose: page reloads, extra tabs and cart updates
	 * must not push the clock forward, otherwise the "submitted too fast" check
	 * would punish normal shoppers.
	 */
	public function mark_session_started( $force = false ) {
		if ( $this->checkout_min_seconds() <= 0 ) {
			return;
		}

		// Cart and checkout pages stamp on template_redirect. Add-to-cart and
		// Store API writes pass $force so a product-page or REST add still counts
		// as the first interaction (is_checkout()/is_cart() are false there).
		if ( ! $force && function_exists( 'is_checkout' ) && ! is_checkout() && ( ! function_exists( 'is_cart' ) || ! is_cart() ) ) {
			return;
		}

		$session = $this->wc_session();

		if ( ! $session || $session->get( self::SESSION_STARTED_KEY ) ) {
			return;
		}

		$session->set( self::SESSION_STARTED_KEY, time() );
	}

	/**
	 * Throttle classic add-to-cart requests and stamp the session.
	 *
	 * @param bool $passed     Whether the product passed WooCommerce validation so far.
	 * @param int  $product_id Product being added.
	 * @return bool
	 */
	public function validate_classic_add_to_cart( $passed, $product_id = 0 ) {
		$this->mark_session_started( true );

		if ( ! $passed ) {
			return $passed;
		}

		$decision = $this->enforce_cart_limit( 'classic-cart' );

		if ( ! is_array( $decision ) ) {
			return $passed;
		}

		if ( function_exists( 'wc_add_notice' ) ) {
			wc_add_notice( $decision['message'], 'error' );
		}

		return false;
	}

	/**
	 * Stamp the session when the Store API adds an item to the cart.
	 *
	 * Rate limiting stays on rest_pre_dispatch (HTTP 429 for every cart write).
	 * This hook is the documented Store API add-to-cart validation point; it
	 * must not consume the throttle again or a single add would count twice.
	 *
	 * @param mixed $product Product being added (unused).
	 * @param array $request Add-to-cart request params (unused).
	 */
	public function stamp_store_api_add_to_cart( $product = null, $request = array() ) {
		$this->mark_session_started( true );
	}

	/**
	 * Guard Store API cart writes (add/update/remove item, coupons, shipping).
	 *
	 * @param mixed           $result Short-circuit result, passed through unchanged.
	 * @param WP_REST_Server  $server REST server instance (unused).
	 * @param WP_REST_Request $request Current request.
	 * @return mixed WP_Error when the cart write limit is exceeded, $result otherwise.
	 */
	public function guard_store_api_cart( $result, $server = null, $request = null ) {
		if ( ! $request instanceof WP_REST_Request ) {
			return $result;
		}

		if ( ! in_array( $request->get_method(), array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
			return $result;
		}

		$route = (string) $request->get_route();

		if ( 0 !== strpos( $route, '/wc/store/' ) || false === strpos( $route, '/cart' ) ) {
			return $result;
		}

		$this->mark_session_started( true );

		$decision = $this->enforce_cart_limit( 'store-api-cart', $route );

		if ( ! is_array( $decision ) ) {
			return $result;
		}

		return new WP_Error(
			'adc_security_cart_limit',
			$decision['message'],
			array( 'status' => 429 )
		);
	}

	/**
	 * Bump the failed-order counters used by the card-testing rule.
	 *
	 * Back-office status changes and failures reported long after the order was
	 * placed (webhooks, manual edits) are ignored, so only a real checkout
	 * failure burst counts.
	 *
	 * @param int          $order_id Order ID.
	 * @param WC_Order|null $order   Order object.
	 */
	public function handle_failed_order( $order_id, $order = null ) {
		if ( ! $order instanceof WC_Order || is_admin() ) {
			return;
		}

		$created = $order->get_date_created();

		if ( $created && ( time() - (int) $created->getTimestamp() ) > 10 * MINUTE_IN_SECONDS ) {
			return;
		}

		$ip = ADC_Security_Ip::get_client_ip();

		if ( '' === $ip ) {
			return;
		}

		$now    = microtime( true );
		$window = $this->order_window_seconds();
		$email  = (string) $order->get_billing_email();

		$this->bump_counter( 'adc_woo_fail_ip_' . md5( $ip ), $now, $window );

		if ( '' !== $email ) {
			$this->bump_counter( 'adc_woo_fail_mail_' . md5( strtolower( trim( $email ) ) ), $now, $window );
		}
	}

	/**
	 * Register the Security meta box on the legacy and HPOS order screens.
	 *
	 * Follows the official WooCommerce HPOS recipe-book: pick the screen id
	 * from CustomOrdersTableController, then add_meta_box().
	 */
	public function register_order_metabox() {
		if ( ! function_exists( 'add_meta_box' ) ) {
			return;
		}

		add_meta_box(
			'adc-security-order',
			__( 'Security', 'adc-security' ),
			array( $this, 'render_order_security_metabox' ),
			$this->order_admin_screen(),
			'side',
			'default'
		);
	}

	/**
	 * Meta box callback. Accepts WP_Post (legacy) or WC_Order (HPOS).
	 *
	 * @param mixed $post_or_order_object Post or order passed by WooCommerce.
	 */
	public function render_order_security_metabox( $post_or_order_object ) {
		$order = $this->order_from_metabox_object( $post_or_order_object );

		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$this->render_order_security_info( $order );
	}

	/**
	 * Show the connection IP and any monitor-mode flags on the order edit screen.
	 *
	 * @param mixed $order Order being edited.
	 */
	public function render_order_security_info( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$ip      = (string) $order->get_meta( '_adc_security_order_ip' );
		$reasons = (string) $order->get_meta( '_adc_security_review_reasons' );

		if ( '' === $ip && '' === $reasons ) {
			return;
		}

		echo '<div class="adc-order-security">';
		echo '<p class="adc-order-security-title"><strong>' . esc_html__( 'Security', 'adc-security' ) . '</strong></p>';

		if ( '' !== $ip ) {
			echo '<p><strong>' . esc_html__( 'Order IP:', 'adc-security' ) . '</strong> ' . esc_html( $ip ) . '</p>';
		}

		if ( '' !== $reasons ) {
			echo '<p><strong>' . esc_html__( 'Flagged (monitor mode):', 'adc-security' ) . '</strong> ' . esc_html( $reasons ) . '</p>';
		}

		echo '</div>';
	}

	/**
	 * Add the Security column on the legacy and HPOS orders lists.
	 *
	 * @param array $columns Existing columns.
	 * @return array
	 */
	public function add_orders_column( $columns ) {
		if ( ! is_array( $columns ) ) {
			return $columns;
		}

		$columns['adc_security'] = __( 'Security', 'adc-security' );

		return $columns;
	}

	/**
	 * Render the Security column on the legacy (CPT) orders list.
	 *
	 * @param string $column  Column id.
	 * @param int    $post_id Order post ID.
	 */
	public function render_orders_column_legacy( $column, $post_id ) {
		if ( 'adc_security' !== $column ) {
			return;
		}

		$order = function_exists( 'wc_get_order' ) ? wc_get_order( $post_id ) : null;
		$this->print_order_flag_column( $order );
	}

	/**
	 * Render the Security column on the HPOS orders list.
	 *
	 * @param string $column Column id.
	 * @param mixed  $order  WC_Order.
	 */
	public function render_orders_column_hpos( $column, $order ) {
		if ( 'adc_security' !== $column ) {
			return;
		}

		$this->print_order_flag_column( $order );
	}

	/**
	 * Print Flagged + reason codes, or an em dash.
	 *
	 * @param mixed $order Order object.
	 */
	public function print_order_flag_column( $order ) {
		if ( ! $order instanceof WC_Order ) {
			echo '&mdash;';
			return;
		}

		$reasons = (string) $order->get_meta( '_adc_security_review_reasons' );

		if ( '' === $reasons ) {
			echo '&mdash;';
			return;
		}

		echo '<span class="adc-order-flagged">' . esc_html__( 'Flagged', 'adc-security' ) . '</span>';
		echo ' <span class="description">' . esc_html( $reasons ) . '</span>';
	}

	/**
	 * Add a "Flagged" view on the orders list.
	 *
	 * @param array $views Existing views.
	 * @return array
	 */
	public function add_flagged_orders_view( $views ) {
		if ( ! is_array( $views ) ) {
			return $views;
		}

		$url   = add_query_arg( 'adc_security_review', '1' );
		$class = ! empty( $_GET['adc_security_review'] ) ? 'current' : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$views['adc_security_review'] = '<a href="' . esc_url( $url ) . '" class="' . esc_attr( $class ) . '">' . esc_html__( 'Flagged', 'adc-security' ) . '</a>';

		return $views;
	}

	/**
	 * Restrict HPOS / wc_get_orders queries to flagged orders when the view is active.
	 *
	 * @param array $args Query args.
	 * @return array
	 */
	public function filter_flagged_orders_query_args( $args ) {
		if ( ! is_admin() || empty( $_GET['adc_security_review'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return $args;
		}

		if ( ! is_array( $args ) ) {
			return $args;
		}

		if ( ! isset( $args['meta_query'] ) || ! is_array( $args['meta_query'] ) ) {
			$args['meta_query'] = array();
		}

		$args['meta_query'][] = array(
			'key'   => '_adc_security_review',
			'value' => '1',
		);

		return $args;
	}

	/**
	 * Restrict the legacy shop_order list to flagged orders when the view is active.
	 *
	 * @param WP_Query $query Current query.
	 */
	public function filter_flagged_orders_legacy_query( $query ) {
		if ( ! $query instanceof WP_Query || ! is_admin() || ! $query->is_main_query() ) {
			return;
		}

		if ( 'shop_order' !== $query->get( 'post_type' ) ) {
			return;
		}

		if ( empty( $_GET['adc_security_review'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$meta = $query->get( 'meta_query' );
		if ( ! is_array( $meta ) ) {
			$meta = array();
		}

		$meta[] = array(
			'key'   => '_adc_security_review',
			'value' => '1',
		);

		$query->set( 'meta_query', $meta );
	}

	/**
	 * Record the buyer IP, identity counters and any monitor-mode flags on a new order.
	 *
	 * @param mixed $order WC_Order that was just created.
	 */
	public function record_order( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return;
		}

		$ip = ADC_Security_Ip::get_client_ip();

		if ( '' === $ip || $this->is_allowlisted_ip( $ip ) ) {
			return;
		}

		$now    = microtime( true );
		$window = $this->order_window_seconds();
		$email  = (string) $order->get_billing_email();

		$this->bump_counter( 'adc_woo_ord_ip_' . md5( $ip ), $now, $window );

		if ( '' !== $email ) {
			$this->bump_counter( 'adc_woo_ord_mail_' . md5( strtolower( trim( $email ) ) ), $now, $window, $email );
		}

		$this->bump_identity_counters( $this->identity_from_order( $order ), $now, $window, $email );

		// Keep the connecting IP on the order for manual fraud review (underscore-prefixed meta).
		$order->update_meta_data( '_adc_security_order_ip', $ip );

		if ( ! empty( $this->review_reasons ) ) {
			$order->update_meta_data( '_adc_security_review', 1 );
			$order->update_meta_data( '_adc_security_review_reasons', implode( ', ', $this->review_reasons ) );
		}

		$order->save_meta_data();
	}

	// -------------------------------------------------------------------------
	// Registration hooks
	// -------------------------------------------------------------------------

	/**
	 * Register the account-creation hooks.
	 */
	private function init_registration_hooks() {
		// WooCommerce My Account registration: current and legacy validation entry points.
		add_filter( 'woocommerce_process_registration_errors', array( $this, 'validate_woo_registration' ), 10, 4 );
		add_action( 'woocommerce_register_post', array( $this, 'validate_woo_registration_action' ), 10, 3 );

		if ( $this->is_enabled( 'woo_registration_honeypot' ) ) {
			add_action( 'woocommerce_register_form', array( $this, 'render_honeypot' ) );
			add_action( 'woocommerce_lostpassword_form', array( $this, 'render_honeypot' ) );

			if ( $this->is_enabled( 'woo_registration_protect_wp_form' ) ) {
				add_action( 'register_form', array( $this, 'render_honeypot' ) );
			}
		}

		if ( $this->is_enabled( 'woo_registration_protect_wp_form' ) ) {
			add_filter( 'registration_errors', array( $this, 'validate_wp_registration' ), 10, 3 );
		}

		add_action( 'woocommerce_save_account_details_errors', array( $this, 'validate_account_details' ), 10, 2 );
		add_action( 'lostpassword_post', array( $this, 'validate_woo_lost_password' ), 10, 2 );

		if ( $this->is_enabled( 'woo_registration_disable_checkout_accounts' ) ) {
			add_filter( 'woocommerce_checkout_registration_enabled', array( $this, 'disable_checkout_registration' ) );
		}

		if ( $this->is_enabled( 'woo_registration_disable_myaccount_form' ) ) {
			add_filter( 'option_woocommerce_enable_myaccount_registration', array( $this, 'hide_myaccount_registration_option' ) );
		}
	}

	/**
	 * Validate the WooCommerce My Account registration form (current hook).
	 *
	 * @param WP_Error $errors   Validation errors collector.
	 * @param string   $username Submitted username (unused).
	 * @param string   $password Submitted password (unused).
	 * @param string   $email    Submitted email.
	 * @return WP_Error
	 */
	public function validate_woo_registration( $errors, $username = '', $password = '', $email = '' ) {
		return $this->add_registration_error( $errors, $email, 'my-account' );
	}

	/**
	 * Validate the WooCommerce My Account registration form (legacy hook).
	 *
	 * @param string   $username Submitted username (unused).
	 * @param string   $email    Submitted email.
	 * @param WP_Error $errors   Validation errors collector.
	 * @return WP_Error
	 */
	public function validate_woo_registration_action( $username, $email, $errors ) {
		return $this->add_registration_error( $errors, $email, 'my-account' );
	}

	/**
	 * Validate the WordPress core registration form.
	 *
	 * @param WP_Error $errors Validation errors collector.
	 * @param string   $login  Submitted username (unused).
	 * @param string   $email  Submitted email.
	 * @return WP_Error
	 */
	public function validate_wp_registration( $errors, $login = '', $email = '' ) {
		return $this->add_registration_error( $errors, $email, 'wp-register' );
	}

	/**
	 * Reject a disposable email when a logged-in customer changes it on My Account.
	 *
	 * Action: the WP_Error is mutated in place (WooCommerce Form Handler).
	 *
	 * @param WP_Error $errors Errors collector.
	 * @param mixed    $user   Current user object (unused).
	 */
	public function validate_account_details( $errors, $user = null ) {
		if ( ! $errors instanceof WP_Error ) {
			return;
		}

		if ( ! $this->is_enabled( 'woo_block_disposable_emails' ) ) {
			return;
		}

		$email = isset( $_POST['account_email'] ) ? sanitize_email( wp_unslash( $_POST['account_email'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( '' === $email || ! $this->is_blocked_email( $email ) ) {
			return;
		}

		$reason = $this->flag_or_block(
			'woo_registration',
			'email_domain',
			$this->registration_message(),
			$email,
			ADC_Security_Ip::get_client_ip(),
			array( 'source' => 'account-details' )
		);

		if ( is_array( $reason ) ) {
			$errors->add( 'adc_security_registration_blocked', $reason['message'] );
		}
	}

	/**
	 * Throttle and honeypot the WooCommerce My Account lost-password form.
	 *
	 * WordPress wp-login.php lost-password POSTs are already covered by the
	 * login rate limiter. This callback only runs when the Woo form posted
	 * `wc_reset_password` (see form-lost-password.php).
	 *
	 * @param WP_Error $errors    Errors collector from retrieve_password().
	 * @param mixed    $user_data User row or false.
	 */
	public function validate_woo_lost_password( $errors, $user_data = null ) {
		if ( ! $errors instanceof WP_Error ) {
			return;
		}

		if ( empty( $_POST['wc_reset_password'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			return;
		}

		$email = '';
		if ( is_object( $user_data ) && ! empty( $user_data->user_email ) ) {
			$email = (string) $user_data->user_email;
		} elseif ( isset( $_POST['user_login'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
			$email = sanitize_text_field( wp_unslash( $_POST['user_login'] ) );
		}

		$reason = $this->evaluate_lost_password( $email );

		if ( is_array( $reason ) ) {
			$errors->add( 'adc_security_lost_password_blocked', $reason['message'] );
		}
	}

	/**
	 * Evaluate the registration rules and add their error to the collector.
	 *
	 * @param WP_Error $errors Validation errors collector.
	 * @param string   $email  Submitted email.
	 * @param string   $source 'my-account', 'wp-register' or 'checkout'.
	 * @return WP_Error
	 */
	private function add_registration_error( $errors, $email, $source ) {
		if ( ! $errors instanceof WP_Error ) {
			return $errors;
		}

		// WooCommerce exposes two validation entry points in some versions; never stack duplicates.
		if ( in_array( 'adc_security_registration_blocked', $errors->get_error_codes(), true ) ) {
			return $errors;
		}

		$reason = $this->evaluate_registration( $email, $source );

		if ( is_array( $reason ) ) {
			$errors->add( 'adc_security_registration_blocked', $reason['message'] );
		}

		return $errors;
	}

	/**
	 * Hide the My Account registration form, while leaving the WooCommerce
	 * settings screen (and logged-in users) untouched.
	 *
	 * @param string $value Stored option value.
	 * @return string
	 */
	public function hide_myaccount_registration_option( $value ) {
		if ( is_admin() || is_user_logged_in() ) {
			return $value;
		}

		return 'no';
	}

	/**
	 * Disable account creation during checkout (classic and block).
	 *
	 * @param bool $enabled Original value.
	 * @return bool
	 */
	public function disable_checkout_registration( $enabled ) {
		if ( is_admin() ) {
			return $enabled;
		}

		return false;
	}

	// -------------------------------------------------------------------------
	// Form output
	// -------------------------------------------------------------------------

	/**
	 * Render the invisible honeypot field. Bots that fill every field are rejected.
	 */
	public function render_honeypot() {
		echo '<p class="adc-woo-honeypot" style="display:none !important;position:absolute;left:-9999px;" aria-hidden="true">';
		echo '<label for="' . esc_attr( self::HONEYPOT_FIELD ) . '">Leave this field blank</label>';
		echo '<input type="text" name="' . esc_attr( self::HONEYPOT_FIELD ) . '" id="' . esc_attr( self::HONEYPOT_FIELD ) . '" value="" tabindex="-1" autocomplete="off" />';
		echo '</p>';
	}

	/**
	 * Load the Turnstile script on the classic checkout page.
	 */
	public function enqueue_turnstile() {
		if ( ! function_exists( 'is_checkout' ) || ! is_checkout() ) {
			return;
		}

		wp_enqueue_script( 'adc-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true );
	}

	/**
	 * Render the Turnstile widget on the classic checkout page.
	 */
	public function render_turnstile() {
		$site_key = (string) $this->option( 'turnstile_site_key', '' );

		if ( '' === $site_key ) {
			return;
		}

		echo '<div class="cf-turnstile adc-checkout-turnstile" data-sitekey="' . esc_attr( $site_key ) . '" data-theme="light"></div>';
	}

	// -------------------------------------------------------------------------
	// Rule evaluation
	// -------------------------------------------------------------------------

	/**
	 * Evaluate every checkout rule for the current request.
	 *
	 * @param array  $identity Identity keys: email, phone, address, postcode.
	 * @param string $source   'classic', 'store-api' or 'checkout'.
	 * @return array|null array( 'code' => string, 'message' => string ) when the
	 *                    order must be blocked, null otherwise.
	 */
	private function evaluate_checkout( array $identity, $source ) {
		if ( $this->is_exempt_request() ) {
			return null;
		}

		$email    = $this->identity_value( $identity, 'email' );
		$ip       = ADC_Security_Ip::get_client_ip();
		$now      = microtime( true );
		$context  = array( 'source' => $source );
		$decision = null;

		// 1. Cross-site or API-only submissions (opt-in, see the setting description).
		$referrer = $this->referrer_decision();

		if ( null !== $referrer ) {
			$decision = $this->flag_or_block( 'woo_checkout', $referrer, $this->checkout_message(), $email, $ip, $context );
		}

		// 2. Honeypot (classic checkout only: the Checkout block has no rendered form).
		if ( null === $decision && $this->is_enabled( 'woo_checkout_honeypot' ) && $this->honeypot_filled() ) {
			$decision = $this->flag_or_block( 'woo_checkout', 'honeypot', $this->checkout_message(), $email, $ip, $context );
		}

		// 3. Minimum time since the session started interacting with the cart.
		if ( null === $decision && $this->checkout_too_fast() ) {
			$decision = $this->flag_or_block( 'woo_checkout', 'too_fast', $this->checkout_message(), $email, $ip, $context );
		}

		// 4. Per-IP checkout attempt throttle.
		$limit = (int) $this->option( 'woo_checkout_rate_limit', 30 );
		if ( null === $decision && $limit > 0 ) {
			$attempt = $this->consume_attempt( 'adc_woo_try_' . md5( $ip ), $now, self::CHECKOUT_WINDOW, $limit );

			if ( $attempt['exceeded'] ) {
				$context['count'] = $attempt['count'];
				$context['limit'] = $limit;
				$decision = $this->flag_or_block( 'woo_checkout', 'rate_limit', $this->checkout_message(), $email, $ip, $context );
			}
		}

		// 5. Order velocity per IP, email, phone and billing address.
		if ( null === $decision ) {
			$velocity = $this->check_order_velocity( $identity, $ip, $now );

			if ( is_array( $velocity ) ) {
				$context['count'] = $velocity['count'];
				$context['limit'] = $velocity['limit'];

				if ( ! empty( $velocity['context'] ) ) {
					$context = array_merge( $context, $velocity['context'] );
				}

				$decision = $this->flag_or_block( 'woo_checkout', $velocity['code'], $this->checkout_message(), $email, $ip, $context );
			}
		}

		// 6. Recent failed orders (card testing signature).
		if ( null === $decision ) {
			$failed = $this->check_failed_orders( $identity, $ip, $now );

			if ( is_array( $failed ) ) {
				$context['count'] = $failed['count'];
				$context['limit'] = $failed['limit'];
				$decision = $this->flag_or_block( 'woo_checkout', $failed['code'], $this->checkout_message(), $email, $ip, $context );
			}
		}

		// 7. Disposable / blocked email domains.
		if ( null === $decision && $this->is_enabled( 'woo_block_disposable_emails' ) && $this->is_blocked_email( $email ) ) {
			$decision = $this->flag_or_block( 'woo_checkout', 'email_domain', $this->checkout_message(), $email, $ip, $context );
		}

		// 8. Optional Turnstile challenge (classic checkout only).
		if ( null === $decision && 'classic' === $source && $this->is_turnstile_enabled() ) {
			$token = isset( $_POST['cf-turnstile-response'] ) ? wp_unslash( $_POST['cf-turnstile-response'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

			if ( is_wp_error( $this->captcha->verify_turnstile_response( $token ) ) ) {
				$decision = $this->flag_or_block( 'woo_checkout', 'turnstile', $this->checkout_message(), $email, $ip, $context );
			}
		}

		return $decision;
	}

	// -------------------------------------------------------------------------
	// Request identity
	// -------------------------------------------------------------------------

	/**
	 * Build the checkout identity from classic checkout data.
	 *
	 * @param mixed $data Posted checkout data.
	 * @return array
	 */
	private function identity_from_checkout_data( $data ) {
		return array(
			'email'    => is_array( $data ) && isset( $data['billing_email'] ) ? $data['billing_email'] : '',
			'phone'    => is_array( $data ) && isset( $data['billing_phone'] ) ? $data['billing_phone'] : '',
			'address'  => is_array( $data ) && isset( $data['billing_address_1'] ) ? $data['billing_address_1'] : '',
			'postcode' => is_array( $data ) && isset( $data['billing_postcode'] ) ? $data['billing_postcode'] : '',
		);
	}

	/**
	 * Build the checkout identity from a Store API customer object.
	 *
	 * @param mixed $customer WC_Customer built from the request.
	 * @return array
	 */
	private function identity_from_customer( $customer ) {
		if ( ! $customer instanceof WC_Customer ) {
			return array();
		}

		return array(
			'email'    => (string) $customer->get_billing_email(),
			'phone'    => method_exists( $customer, 'get_billing_phone' ) ? (string) $customer->get_billing_phone() : '',
			'address'  => method_exists( $customer, 'get_billing_address_1' ) ? (string) $customer->get_billing_address_1() : '',
			'postcode' => method_exists( $customer, 'get_billing_postcode' ) ? (string) $customer->get_billing_postcode() : '',
		);
	}

	/**
	 * Build the checkout identity from a stored order.
	 *
	 * @param mixed $order WC_Order.
	 * @return array
	 */
	private function identity_from_order( $order ) {
		if ( ! $order instanceof WC_Order ) {
			return array();
		}

		return array(
			'email'    => (string) $order->get_billing_email(),
			'phone'    => method_exists( $order, 'get_billing_phone' ) ? (string) $order->get_billing_phone() : '',
			'address'  => method_exists( $order, 'get_billing_address_1' ) ? (string) $order->get_billing_address_1() : '',
			'postcode' => method_exists( $order, 'get_billing_postcode' ) ? (string) $order->get_billing_postcode() : '',
		);
	}

	/**
	 * Read one identity key as a trimmed string.
	 *
	 * @param array  $identity Identity array.
	 * @param string $key      Key name.
	 * @return string
	 */
	private function identity_value( array $identity, $key ) {
		return isset( $identity[ $key ] ) ? trim( (string) $identity[ $key ] ) : '';
	}

	/**
	 * Decide whether the request may proceed based on its Origin/Referer.
	 *
	 * @return string|null Rule code to block on, null to continue.
	 */
	private function referrer_decision() {
		$mode = (string) $this->option( 'woo_checkout_referrer_check', 'off' );

		if ( 'off' === $mode ) {
			return null;
		}

		$value = '';

		if ( ! empty( $_SERVER['HTTP_ORIGIN'] ) ) {
			$value = wp_unslash( (string) $_SERVER['HTTP_ORIGIN'] );
		} elseif ( ! empty( $_SERVER['HTTP_REFERER'] ) ) {
			$value = wp_unslash( (string) $_SERVER['HTTP_REFERER'] );
		}

		$host = ADC_Security_Woo_Rules::host_from_url( $value );

		if ( '' === $host ) {
			return ( 'required' === $mode ) ? 'referrer_missing' : null;
		}

		return $this->is_allowed_request_host( $host ) ? null : 'referrer_mismatch';
	}

	/**
	 * Whether a hostname belongs to this site.
	 *
	 * @param string $host Hostname from the Origin/Referer header.
	 * @return bool
	 */
	private function is_allowed_request_host( $host ) {
		$request_host = isset( $_SERVER['HTTP_HOST'] ) ? wp_unslash( (string) $_SERVER['HTTP_HOST'] ) : '';

		$allowed = array(
			ADC_Security_Woo_Rules::host_from_url( home_url() ),
			ADC_Security_Woo_Rules::host_from_url( site_url() ),
			ADC_Security_Woo_Rules::host_from_url( '//' . $request_host ),
		);

		$allowed = array_values( array_unique( array_filter( $allowed ) ) );

		/**
		 * Filter the hostnames accepted as "same site" by the checkout referrer check.
		 *
		 * @param array  $allowed Allowed hostnames.
		 * @param string $host    Hostname being tested.
		 */
		$allowed = apply_filters( 'adc_security_checkout_allowed_hosts', $allowed, $host );

		foreach ( (array) $allowed as $candidate ) {
			if ( ADC_Security_Woo_Rules::is_same_host( $host, (string) $candidate ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check the billing email against the blocked/disposable domain list.
	 *
	 * @param string $email Billing or registration email.
	 * @return bool
	 */
	private function is_blocked_email( $email ) {
		$domain = ADC_Security_Woo_Rules::email_domain( $email );

		if ( '' === $domain ) {
			return false;
		}

		$domains = ADC_Security_Woo_Rules::get_blocked_domains( $this->option( 'woo_blocked_email_domains', '' ) );

		/**
		 * Filter the blocked email domain list used for checkout and registration.
		 *
		 * @param array $domains Lowercase domain names.
		 */
		$domains = apply_filters( 'adc_security_blocked_email_domains', $domains );

		return ADC_Security_Woo_Rules::is_blocked_domain( $domain, is_array( $domains ) ? $domains : array() );
	}

	/**
	 * Whether the shared honeypot field was filled in the current request.
	 *
	 * @return bool
	 */
	private function honeypot_filled() {
		return ! empty( $_POST[ self::HONEYPOT_FIELD ] ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
	}

	/**
	 * Evaluate every account-creation rule for the current request.
	 *
	 * @param string $email  Submitted email, when known.
	 * @param string $source 'my-account', 'wp-register' or 'checkout'.
	 * @return array|null array( 'code' => string, 'message' => string ) when the
	 *                    account must not be created, null otherwise.
	 */
	private function evaluate_registration( $email, $source ) {
		$ip      = ADC_Security_Ip::get_client_ip();
		$context = array( 'source' => $source );

		// The My Account form toggle also closes the direct POST bypass.
		if ( 'my-account' === $source && $this->is_enabled( 'woo_registration_disable_myaccount_form' ) ) {
			return $this->flag_or_block( 'woo_registration', 'form_disabled', $this->registration_message(), $email, $ip, $context );
		}

		if ( $this->is_exempt_request() ) {
			return null;
		}

		$decision = null;

		// 1. Honeypot.
		if ( $this->is_enabled( 'woo_registration_honeypot' ) && $this->honeypot_filled() ) {
			$decision = $this->flag_or_block( 'woo_registration', 'honeypot', $this->registration_message(), $email, $ip, $context );
		}

		// 2. Per-IP registration throttle.
		$limit = (int) $this->option( 'woo_registration_rate_limit', 10 );
		if ( null === $decision && $limit > 0 ) {
			$attempt = $this->consume_attempt( 'adc_woo_reg_' . md5( $ip ), microtime( true ), self::REGISTRATION_WINDOW, $limit );

			if ( $attempt['exceeded'] ) {
				$context['count'] = $attempt['count'];
				$context['limit'] = $limit;
				$decision = $this->flag_or_block( 'woo_registration', 'rate_limit', $this->registration_message(), $email, $ip, $context );
			}
		}

		// 3. Disposable / blocked email domains.
		if ( null === $decision && $this->is_enabled( 'woo_block_disposable_emails' ) && $this->is_blocked_email( $email ) ) {
			$decision = $this->flag_or_block( 'woo_registration', 'email_domain', $this->registration_message(), $email, $ip, $context );
		}

		return $decision;
	}

	/**
	 * Evaluate lost-password rules for the WooCommerce My Account form.
	 *
	 * @param string $email Email or login submitted.
	 * @return array|null Block decision, or null to allow.
	 */
	private function evaluate_lost_password( $email ) {
		$ip      = ADC_Security_Ip::get_client_ip();
		$context = array( 'source' => 'lost-password' );

		if ( $this->is_exempt_request() ) {
			return null;
		}

		$decision = null;

		if ( $this->is_enabled( 'woo_registration_honeypot' ) && $this->honeypot_filled() ) {
			$decision = $this->flag_or_block( 'woo_lost_password', 'honeypot', $this->lost_password_message(), $email, $ip, $context );
		}

		$limit = (int) $this->option( 'woo_registration_rate_limit', 10 );
		if ( null === $decision && $limit > 0 ) {
			$attempt = $this->consume_attempt( 'adc_woo_lost_' . md5( $ip ), microtime( true ), self::REGISTRATION_WINDOW, $limit );

			if ( $attempt['exceeded'] ) {
				$context['count'] = $attempt['count'];
				$context['limit'] = $limit;
				$decision         = $this->flag_or_block( 'woo_lost_password', 'rate_limit', $this->lost_password_message(), $email, $ip, $context );
			}
		}

		return $decision;
	}

	/**
	 * Check the order-velocity counters for the current checkout identity.
	 *
	 * @param array  $identity Identity keys: email, phone, address, postcode.
	 * @param string $ip       Connecting IP.
	 * @param float  $now      Current timestamp.
	 * @return array|null array( 'code', 'count', 'limit', 'context' ) when limited, null otherwise.
	 */
	private function check_order_velocity( array $identity, $ip, $now ) {
		$window = $this->order_window_seconds();
		$email  = isset( $identity['email'] ) ? (string) $identity['email'] : '';

		$ip_limit = (int) $this->option( 'woo_order_ip_limit', 10 );
		if ( $ip_limit > 0 ) {
			$count = ADC_Security_Woo_Rules::window_count( get_transient( 'adc_woo_ord_ip_' . md5( $ip ) ), $now, $window );

			if ( ADC_Security_Woo_Rules::is_over_limit( $count, $ip_limit ) ) {
				return array(
					'code'  => 'order_limit_ip',
					'count' => $count,
					'limit' => $ip_limit,
				);
			}
		}

		if ( '' !== trim( $email ) ) {
			$email_limit = (int) $this->option( 'woo_order_email_limit', 20 );

			if ( $email_limit > 0 ) {
				$state = get_transient( 'adc_woo_ord_mail_' . md5( strtolower( trim( $email ) ) ) );
				$count = ADC_Security_Woo_Rules::window_count( $state, $now, $window );

				if ( ADC_Security_Woo_Rules::is_over_limit( $count, $email_limit ) ) {
					return array(
						'code'    => 'order_limit_email',
						'count'   => $count,
						'limit'   => $email_limit,
						'context' => array( 'distinct' => ADC_Security_Woo_Rules::window_distinct( $state ) ),
					);
				}
			}
		}

		$phone     = $this->identity_value( $identity, 'phone' );
		$phone_key = ADC_Security_Woo_Rules::normalize_phone( $phone );

		if ( '' !== $phone_key ) {
			$phone_limit = (int) $this->option( 'woo_order_phone_limit', 5 );

			if ( $phone_limit > 0 ) {
				$state = get_transient( 'adc_woo_ord_phone_' . md5( $phone_key ) );
				$count = ADC_Security_Woo_Rules::window_count( $state, $now, $window );

				if ( ADC_Security_Woo_Rules::is_over_limit( $count, $phone_limit ) ) {
					return array(
						'code'    => 'order_limit_phone',
						'count'   => $count,
						'limit'   => $phone_limit,
						'context' => array( 'distinct' => ADC_Security_Woo_Rules::window_distinct( $state ) ),
					);
				}
			}
		}

		$address_key = ADC_Security_Woo_Rules::normalize_address(
			$this->identity_value( $identity, 'address' ),
			$this->identity_value( $identity, 'postcode' )
		);

		if ( '' !== $address_key ) {
			$address_limit = (int) $this->option( 'woo_order_address_limit', 5 );

			if ( $address_limit > 0 ) {
				$state = get_transient( 'adc_woo_ord_addr_' . md5( $address_key ) );
				$count = ADC_Security_Woo_Rules::window_count( $state, $now, $window );

				if ( ADC_Security_Woo_Rules::is_over_limit( $count, $address_limit ) ) {
					return array(
						'code'    => 'order_limit_address',
						'count'   => $count,
						'limit'   => $address_limit,
						'context' => array( 'distinct' => ADC_Security_Woo_Rules::window_distinct( $state ) ),
					);
				}
			}
		}

		return null;
	}

	/**
	 * Check whether recent failed orders already reached the configured limit.
	 *
	 * A burst of failed orders from one IP or email is the classic signature of
	 * card testing, where an attacker keeps trying until one attempt succeeds.
	 *
	 * @param array  $identity Identity keys: email, phone, address, postcode.
	 * @param string $ip       Connecting IP.
	 * @param float  $now      Current timestamp.
	 * @return array|null array( 'code', 'count', 'limit' ) when limited, null otherwise.
	 */
	private function check_failed_orders( array $identity, $ip, $now ) {
		$limit = (int) $this->option( 'woo_failed_order_limit', 5 );

		if ( $limit <= 0 ) {
			return null;
		}

		$window = $this->order_window_seconds();

		$count = ADC_Security_Woo_Rules::window_count( get_transient( 'adc_woo_fail_ip_' . md5( $ip ) ), $now, $window );

		if ( ADC_Security_Woo_Rules::is_over_limit( $count, $limit ) ) {
			return array(
				'code'  => 'failed_orders_ip',
				'count' => $count,
				'limit' => $limit,
			);
		}

		$email = $this->identity_value( $identity, 'email' );

		if ( '' !== $email ) {
			$count = ADC_Security_Woo_Rules::window_count( get_transient( 'adc_woo_fail_mail_' . md5( strtolower( trim( $email ) ) ) ), $now, $window );

			if ( ADC_Security_Woo_Rules::is_over_limit( $count, $limit ) ) {
				return array(
					'code'  => 'failed_orders_email',
					'count' => $count,
					'limit' => $limit,
				);
			}
		}

		return null;
	}

	/**
	 * Bump the phone and address velocity counters for a completed order.
	 *
	 * @param array  $identity Identity keys: email, phone, address, postcode.
	 * @param float  $now      Current timestamp.
	 * @param int    $window   Window length in seconds.
	 * @param string $email    Billing email, tracked as the identity of the order.
	 */
	private function bump_identity_counters( array $identity, $now, $window, $email ) {
		$phone_key = ADC_Security_Woo_Rules::normalize_phone( $this->identity_value( $identity, 'phone' ) );

		if ( '' !== $phone_key ) {
			$this->bump_counter( 'adc_woo_ord_phone_' . md5( $phone_key ), $now, $window, $email );
		}

		$address_key = ADC_Security_Woo_Rules::normalize_address(
			$this->identity_value( $identity, 'address' ),
			$this->identity_value( $identity, 'postcode' )
		);

		if ( '' !== $address_key ) {
			$this->bump_counter( 'adc_woo_ord_addr_' . md5( $address_key ), $now, $window, $email );
		}
	}

	/**
	 * Enforce the per-IP cart write limit.
	 *
	 * @param string $source 'classic-cart' or 'store-api-cart'.
	 * @param string $route  REST route, when applicable.
	 * @return array|null Block decision when the limit is exceeded and blocking is enabled.
	 */
	private function enforce_cart_limit( $source, $route = '' ) {
		$limit = $this->cart_write_limit();

		if ( $this->is_exempt_request() || $limit <= 0 ) {
			return null;
		}

		$ip      = ADC_Security_Ip::get_client_ip();
		$attempt = $this->consume_attempt( 'adc_woo_cart_' . md5( $ip ), microtime( true ), self::CHECKOUT_WINDOW, $limit );

		if ( ! $attempt['exceeded'] ) {
			return null;
		}

		return $this->flag_or_block(
			'woo_checkout',
			'cart_limit',
			$this->cart_message(),
			'',
			$ip,
			array(
				'source' => $source,
				'route'  => $route,
				'count'  => $attempt['count'],
				'limit'  => $limit,
			)
		);
	}

	/**
	 * Whether the checkout form was submitted fewer seconds after the session
	 * started interacting with the cart than the configured minimum.
	 *
	 * @return bool
	 */
	private function checkout_too_fast() {
		$minimum = $this->checkout_min_seconds();

		if ( $minimum <= 0 ) {
			return false;
		}

		$session = $this->wc_session();

		if ( ! $session ) {
			return false;
		}

		$started = (int) $session->get( self::SESSION_STARTED_KEY );

		return ADC_Security_Woo_Rules::is_too_fast( $started, time(), $minimum );
	}

	/**
	 * Whether the current request should bypass every rule (CLI, cron, empty or
	 * allowlisted IP).
	 *
	 * @return bool
	 */
	private function is_exempt_request() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return true;
		}

		if ( function_exists( 'wp_doing_cron' ) && wp_doing_cron() ) {
			return true;
		}

		$ip = ADC_Security_Ip::get_client_ip();

		if ( '' === $ip ) {
			return true;
		}

		return $this->is_allowlisted_ip( $ip );
	}

	/**
	 * Whether an IP is in the plugin's IP allowlist.
	 *
	 * @param string $ip Client IP.
	 * @return bool
	 */
	private function is_allowlisted_ip( $ip ) {
		return ADC_Security_Ip::is_allowlisted( $ip );
	}

	/**
	 * Whether a classic checkout submission will create a customer account.
	 *
	 * @param array $data Posted checkout data.
	 * @return bool
	 */
	private function classic_checkout_creates_account( $data ) {
		if ( is_user_logged_in() || ! $this->checkout_object() ) {
			return false;
		}

		if ( $this->checkout_object()->is_registration_required() ) {
			return true;
		}

		return is_array( $data ) && ! empty( $data['createaccount'] );
	}

	/**
	 * Whether a Store API place-order request will create a customer account.
	 *
	 * @param WP_REST_Request $request Current request.
	 * @return bool
	 */
	private function store_api_checkout_creates_account( $request ) {
		if ( is_user_logged_in() || ! $this->checkout_object() ) {
			return false;
		}

		if ( $this->checkout_object()->is_registration_required() ) {
			return true;
		}

		return filter_var( isset( $request['create_account'] ) ? $request['create_account'] : false, FILTER_VALIDATE_BOOLEAN );
	}

	// -------------------------------------------------------------------------
	// Logging / decisions
	// -------------------------------------------------------------------------

	/**
	 * Log the violation and, unless monitor mode is active, tell the caller to
	 * block the request. In monitor mode the next rule is still evaluated, so a
	 * single attempt can surface every configured rule it breaks.
	 *
	 * @param string $event_type Base event type, e.g. 'woo_checkout'.
	 * @param string $code       Violated rule.
	 * @param string $message    Customer facing message.
	 * @param string $email      Email involved, when known (only its domain is logged).
	 * @param string $ip         Client IP.
	 * @param array  $context    Extra log context.
	 * @return array|null Block decision, or null in monitor mode.
	 */
	private function flag_or_block( $event_type, $code, $message, $email, $ip, array $context ) {
		$blocking            = ! $this->is_monitor_mode();
		$context['reason']   = $code;
		$context['domain']   = ADC_Security_Woo_Rules::email_domain( $email );
		$context['mode']     = $blocking ? 'block' : 'monitor';

		$this->log( $event_type . ( $blocking ? '_blocked' : '_flagged' ), $ip, isset( $context['source'] ) ? $context['source'] : '', $context );

		if ( ! $blocking ) {
			// The order (if any) is allowed through; flag it so it can be reviewed
			// and excluded from conversion reporting.
			$this->review_reasons[ $code ] = $code;

			return null;
		}

		return array(
			'code'    => $code,
			'message' => $message,
		);
	}

	/**
	 * Write an entry to the audit log.
	 *
	 * @param string $type   Event type.
	 * @param string $ip     Client IP.
	 * @param string $object Short object description (the request source).
	 * @param array  $context Structured context.
	 */
	private function log( $type, $ip, $object, array $context ) {
		if ( ! class_exists( 'ADC_Security_Events' ) ) {
			return;
		}

		ADC_Security_Events::log(
			$type,
			ADC_Security_Events::SEVERITY_WARNING,
			array(
				'ip'      => $ip,
				'object'  => $object,
				'context' => $context,
			)
		);
	}

	/**
	 * Customer facing block message for checkout rules.
	 *
	 * @return string
	 */
	private function checkout_message() {
		return __( 'We were unable to place this order. If you think this is a mistake, please contact the store.', 'adc-security' );
	}

	/**
	 * Customer facing block message for cart volume rules.
	 *
	 * @return string
	 */
	private function cart_message() {
		return __( 'Too many cart updates from this connection. Please wait a moment and try again.', 'adc-security' );
	}

	/**
	 * Customer facing block message for account-creation rules.
	 *
	 * @return string
	 */
	private function registration_message() {
		return __( 'We could not create this account. If you believe this is a mistake, please contact us.', 'adc-security' );
	}

	/**
	 * Customer facing block message for lost-password rules.
	 *
	 * @return string
	 */
	private function lost_password_message() {
		return __( 'We could not process this request. Please wait a moment and try again.', 'adc-security' );
	}

	// -------------------------------------------------------------------------
	// Small helpers
	// -------------------------------------------------------------------------

	/**
	 * Read a plugin option.
	 *
	 * @param string $key     Option key.
	 * @param mixed  $default Fallback value.
	 * @return mixed
	 */
	private function option( $key, $default = '' ) {
		return isset( $this->options[ $key ] ) ? $this->options[ $key ] : $default;
	}

	/**
	 * Whether an option toggle is enabled.
	 *
	 * @param string $key Option key.
	 * @return bool
	 */
	private function is_enabled( $key ) {
		return ! empty( $this->options[ $key ] );
	}

	/**
	 * Whether violations are logged without blocking.
	 *
	 * Missing key (upgrade before migrate_defaults has run) is treated as on,
	 * so checkout is never blocked by an absent option.
	 *
	 * @return bool
	 */
	private function is_monitor_mode() {
		if ( ! array_key_exists( 'woo_monitor_mode', $this->options ) ) {
			return true;
		}

		return ! empty( $this->options['woo_monitor_mode'] );
	}

	/**
	 * Configured minimum checkout delay, in seconds.
	 *
	 * @return int
	 */
	private function checkout_min_seconds() {
		return max( 0, (int) $this->option( 'woo_checkout_min_seconds', 0 ) );
	}

	/**
	 * Order velocity window, in seconds.
	 *
	 * @return int
	 */
	private function order_window_seconds() {
		return max( 1, (int) $this->option( 'woo_order_window_minutes', 60 ) ) * MINUTE_IN_SECONDS;
	}

	/**
	 * Bump a fixed-window counter stored in a transient.
	 *
	 * @param string $key            Transient key.
	 * @param float  $now            Current timestamp.
	 * @param int    $window_seconds Window length in seconds.
	 * @param string $identity       Optional identity to track inside the window.
	 * @return array Fresh counter state.
	 */
	private function bump_counter( $key, $now, $window_seconds, $identity = '' ) {
		$state = ADC_Security_Woo_Rules::bump_window( get_transient( $key ), $now, $window_seconds, $identity );

		set_transient( $key, $state, $window_seconds );

		return $state;
	}

	/**
	 * Consume one slot from an attempt counter (checkout submissions, cart writes,
	 * registrations). The limit is the number of requests allowed in the window;
	 * the next one is rejected and not counted again, so a blocked client stays
	 * blocked for the rest of the window instead of pushing the counter forever.
	 *
	 * @param string $key            Transient key.
	 * @param float  $now            Current timestamp.
	 * @param int    $window_seconds Window length in seconds.
	 * @param int    $limit          Allowed requests per window.
	 * @return array{exceeded:bool,count:int} Result plus the previous attempt count.
	 */
	private function consume_attempt( $key, $now, $window_seconds, $limit ) {
		$state = get_transient( $key );
		$count = ADC_Security_Woo_Rules::window_count( $state, $now, $window_seconds );

		if ( ADC_Security_Woo_Rules::is_over_limit( $count, $limit ) ) {
			return array(
				'exceeded' => true,
				'count'    => $count,
			);
		}

		$this->bump_counter( $key, $now, $window_seconds );

		return array(
			'exceeded' => false,
			'count'    => $count + 1,
		);
	}

	/**
	 * Configured cart-write limit (per IP, over CHECKOUT_WINDOW).
	 *
	 * @return int
	 */
	private function cart_write_limit() {
		return max( 0, (int) $this->option( 'woo_cart_write_limit', 60 ) );
	}

	/**
	 * WooCommerce checkout object, when available.
	 *
	 * @return WC_Checkout|null
	 */
	private function checkout_object() {
		if ( ! function_exists( 'WC' ) ) {
			return null;
		}

		$wc = WC();

		return ( $wc && isset( $wc->checkout ) && $wc->checkout instanceof WC_Checkout ) ? $wc->checkout : null;
	}

	/**
	 * WooCommerce session object, when available.
	 *
	 * @return WC_Session|null
	 */
	private function wc_session() {
		if ( ! function_exists( 'WC' ) ) {
			return null;
		}

		$wc = WC();

		return ( $wc && isset( $wc->session ) && is_object( $wc->session ) ) ? $wc->session : null;
	}

	/**
	 * Admin screen id for the order editor (legacy CPT vs HPOS).
	 *
	 * @return string
	 */
	private function order_admin_screen() {
		$hpos_controller = '\Automattic\WooCommerce\Internal\DataStores\Orders\CustomOrdersTableController';

		if ( class_exists( $hpos_controller ) && function_exists( 'wc_get_container' ) && function_exists( 'wc_get_page_screen_id' ) ) {
			try {
				$container  = wc_get_container();
				$controller = ( is_object( $container ) && method_exists( $container, 'get' ) ) ? $container->get( $hpos_controller ) : null;

				if ( is_object( $controller ) && method_exists( $controller, 'custom_orders_table_usage_is_enabled' ) && $controller->custom_orders_table_usage_is_enabled() ) {
					return wc_get_page_screen_id( 'shop-order' );
				}
			} catch ( Exception $e ) {
				// Fall back to the legacy screen id.
			}
		}

		return 'shop_order';
	}

	/**
	 * Normalise the object WooCommerce passes into a meta box callback.
	 *
	 * @param mixed $post_or_order_object WP_Post or WC_Order.
	 * @return WC_Order|null
	 */
	private function order_from_metabox_object( $post_or_order_object ) {
		if ( $post_or_order_object instanceof WC_Order ) {
			return $post_or_order_object;
		}

		if ( $post_or_order_object instanceof WP_Post && function_exists( 'wc_get_order' ) ) {
			$order = wc_get_order( $post_or_order_object->ID );

			return $order instanceof WC_Order ? $order : null;
		}

		return null;
	}

	/**
	 * Whether the optional Turnstile challenge is usable and enabled.
	 *
	 * @return bool
	 */
	private function is_turnstile_enabled() {
		if ( ! $this->is_enabled( 'woo_checkout_turnstile' ) || ! $this->captcha ) {
			return false;
		}

		if ( 'turnstile' !== $this->option( 'captcha_type', 'none' ) ) {
			return false;
		}

		return '' !== trim( (string) $this->option( 'turnstile_site_key', '' ) )
			&& '' !== trim( (string) $this->option( 'turnstile_secret_key', '' ) );
	}
}
