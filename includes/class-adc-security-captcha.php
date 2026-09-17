<?php
/**
 * ADC Security Captcha Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Captcha {

	/**
	 * Options
	 * 
	 * @var array
	 */
	private $options;

	/**
	 * Constructor.
	 */
	public function __construct() {
		$this->options = get_option( 'adc_security_options' );
        
        $captcha_type = isset( $this->options['captcha_type'] ) ? $this->options['captcha_type'] : 'none';

        if ( 'math' === $captcha_type ) {
            $this->init_math_captcha();
        } elseif ( 'turnstile' === $captcha_type ) {
            $this->init_turnstile();
        }

        // Honeypot (Always init if enabled, independent of Captcha type)
        if ( ! empty( $this->options['login_honeypot'] ) ) {
            $this->init_honeypot();
        }
	}

    // --- Honeypot ---

    private function init_honeypot() {
        add_action( 'login_form', array( $this, 'render_honeypot' ) );
        add_action( 'lostpassword_form', array( $this, 'render_honeypot' ) );
        add_action( 'woocommerce_lostpassword_form', array( $this, 'render_honeypot' ) );
        add_filter( 'authenticate', array( $this, 'validate_honeypot' ), 20, 3 );
        add_action( 'lostpassword_post', array( $this, 'validate_honeypot_lostpassword' ), 10, 1 );
    }

    public function render_honeypot() {
        // Hidden field that should be left empty
        // Use a generic name that sounds plausible to bots but is not a WP default
        echo '<p style="display:none !important;">
            <label for="adc_hp_check">If you are human, leave this field blank.</label>
            <input type="text" name="adc_hp_check" id="adc_hp_check" value="" tabindex="-1" autocomplete="off" />
        </p>';
    }

    public function validate_honeypot( $user, $username, $password ) {
        if ( ! empty( $_POST['adc_hp_check'] ) ) {
            // Field was filled => Bot
            return new WP_Error( 'honeypot_fail', '<strong>Error</strong>: Bot detected.' );
        }
        return $user;
    }

    // --- Math Captcha ---

    private function init_math_captcha() {
        add_action( 'login_form', array( $this, 'render_math_captcha' ) );
        add_action( 'lostpassword_form', array( $this, 'render_math_captcha' ) );
        add_action( 'woocommerce_lostpassword_form', array( $this, 'render_math_captcha' ) );
        add_filter( 'authenticate', array( $this, 'validate_math_captcha' ), 20, 3 );
        add_action( 'lostpassword_post', array( $this, 'validate_math_lostpassword' ), 10, 1 );
    }

    public function render_math_captcha() {
        $num1 = rand( 1, 9 );
        $num2 = rand( 1, 9 );
        $sum  = $num1 + $num2;

        // Store the answer server-side in a transient keyed by a random token.
        // The client only receives the token, never the answer or a derivable hash.
        $token = wp_generate_password( 32, false );
        set_transient( 'adc_math_captcha_' . $token, $sum, 5 * MINUTE_IN_SECONDS );

        echo '<p class="adc-math-captcha">
            <label for="adc_math_captcha">Security Question: ' . $num1 . ' + ' . $num2 . ' = ?</label>
            <input type="number" name="adc_math_captcha" id="adc_math_captcha" class="input" value="" size="20" required />
            <input type="hidden" name="adc_math_token" value="' . esc_attr( $token ) . '" />
        </p>';
    }

    public function validate_math_captcha( $user, $username, $password ) {
        if ( isset( $_POST['adc_math_captcha'] ) && isset( $_POST['adc_math_token'] ) ) {
            $token  = sanitize_text_field( wp_unslash( $_POST['adc_math_token'] ) );
            $answer = (int) $_POST['adc_math_captcha'];
            $transient_key = 'adc_math_captcha_' . $token;

            $expected = get_transient( $transient_key );

            // Delete the transient regardless of outcome (one-time use).
            delete_transient( $transient_key );

            if ( false === $expected || $answer !== (int) $expected ) {
                return new WP_Error( 'captcha_error', '<strong>Error</strong>: Incorrect CAPTCHA answer.' );
            }
        } else {
             if ( isset( $_POST['log'] ) ) {
                return new WP_Error( 'captcha_error', '<strong>Error</strong>: Please solve the CAPTCHA.' );
             }
        }

        return $user;
    }

    // --- Turnstile ---

    private function init_turnstile() {
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_turnstile_script' ) );
        add_action( 'wp_enqueue_scripts', array( $this, 'maybe_enqueue_turnstile_lostpassword' ) );
        add_action( 'login_form', array( $this, 'render_turnstile' ) );
        add_action( 'lostpassword_form', array( $this, 'render_turnstile' ) );
        add_action( 'woocommerce_lostpassword_form', array( $this, 'render_turnstile' ) );
        add_filter( 'authenticate', array( $this, 'validate_turnstile' ), 20, 3 );
        add_action( 'lostpassword_post', array( $this, 'validate_turnstile_lostpassword' ), 10, 1 );
    }

    public function enqueue_turnstile_script() {
        wp_enqueue_script( 'adc-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), null, true );
    }

    public function render_turnstile() {
        $site_key = isset( $this->options['turnstile_site_key'] ) ? $this->options['turnstile_site_key'] : '';
        if ( empty( $site_key ) ) {
            return;
        }
        echo '<div class="cf-turnstile" data-sitekey="' . esc_attr( $site_key ) . '" data-theme="light"></div>';
    }

    public function validate_turnstile( $user, $username, $password ) {
        if ( ! isset( $_POST['cf-turnstile-response'] ) ) {
             if ( isset( $_POST['log'] ) ) {
                return new WP_Error( 'turnstile_error', '<strong>Error</strong>: Please verify you are human (Turnstile).' );
             }
             return $user;
        }

        $result = $this->verify_turnstile_response( $_POST['cf-turnstile-response'] );

        if ( is_wp_error( $result ) ) {
            return $result;
        }

        return $user;
    }

    /**
     * Load Turnstile on the WooCommerce My Account lost-password endpoint.
     */
    public function maybe_enqueue_turnstile_lostpassword() {
        if ( ! function_exists( 'is_account_page' ) || ! is_account_page() ) {
            return;
        }

        if ( function_exists( 'is_wc_endpoint_url' ) && ! is_wc_endpoint_url( 'lost-password' ) ) {
            return;
        }

        $this->enqueue_turnstile_script();
    }

    /**
     * Honeypot check on lost-password POST (wp-login and Woo My Account).
     *
     * @param WP_Error $errors Errors collector from retrieve_password().
     */
    public function validate_honeypot_lostpassword( $errors ) {
        if ( ! $errors instanceof WP_Error ) {
            return;
        }

        if ( ! empty( $_POST['adc_hp_check'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $errors->add( 'honeypot_fail', '<strong>Error</strong>: Bot detected.' );
        }
    }

    /**
     * Math captcha check on lost-password POST.
     *
     * @param WP_Error $errors Errors collector from retrieve_password().
     */
    public function validate_math_lostpassword( $errors ) {
        if ( ! $errors instanceof WP_Error ) {
            return;
        }

        if ( isset( $_POST['adc_math_captcha'] ) && isset( $_POST['adc_math_token'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $token         = sanitize_text_field( wp_unslash( $_POST['adc_math_token'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
            $answer        = (int) $_POST['adc_math_captcha']; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
            $transient_key = 'adc_math_captcha_' . $token;
            $expected      = get_transient( $transient_key );
            delete_transient( $transient_key );

            if ( false === $expected || $answer !== (int) $expected ) {
                $errors->add( 'captcha_error', '<strong>Error</strong>: Incorrect CAPTCHA answer.' );
            }

            return;
        }

        $errors->add( 'captcha_error', '<strong>Error</strong>: Please solve the CAPTCHA.' );
    }

    /**
     * Turnstile check on lost-password POST.
     *
     * @param WP_Error $errors Errors collector from retrieve_password().
     */
    public function validate_turnstile_lostpassword( $errors ) {
        if ( ! $errors instanceof WP_Error ) {
            return;
        }

        $token  = isset( $_POST['cf-turnstile-response'] ) ? wp_unslash( $_POST['cf-turnstile-response'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
        $result = $this->verify_turnstile_response( $token );

        if ( is_wp_error( $result ) ) {
            $errors->add( $result->get_error_code(), $result->get_error_message() );
        }
    }

    /**
     * Verify a Turnstile token against the Cloudflare siteverify endpoint.
     *
     * Shared by the login form and the optional classic-checkout challenge so
     * both surfaces use identical fail-closed behavior.
     *
     * @param string $response Token from the cf-turnstile-response field.
     * @return true|WP_Error True when verified, WP_Error otherwise.
     */
    public function verify_turnstile_response( $response ) {
        $response = (string) $response;
        $secret   = isset( $this->options['turnstile_secret_key'] ) ? $this->options['turnstile_secret_key'] : '';

        // Fail closed: an incomplete Turnstile configuration must never let
        // authentication through unverified. A visible admin-facing error is
        // safer than silently accepting any client-supplied response value.
        if ( empty( $secret ) ) {
            return new WP_Error( 'turnstile_misconfigured', '<strong>Error</strong>: CAPTCHA is misconfigured. Please contact the site administrator.' );
        }

        if ( '' === trim( $response ) ) {
            return new WP_Error( 'turnstile_fail', '<strong>Error</strong>: CAPTCHA verification failed.' );
        }

        $verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $data = array(
            'secret'   => $secret,
            'response' => $response,
            'remoteip' => ADC_Security_Ip::get_client_ip(),
        );

        $verify = wp_remote_post( $verify_url, array(
            'body' => $data,
        ) );

        if ( is_wp_error( $verify ) ) {
            return new WP_Error( 'turnstile_api_error', '<strong>Error</strong>: Unable to verify CAPTCHA.' );
        }

        $body = wp_remote_retrieve_body( $verify );
        $result = json_decode( $body );

        if ( empty( $result->success ) ) {
            return new WP_Error( 'turnstile_fail', '<strong>Error</strong>: CAPTCHA verification failed.' );
        }

        return true;
    }
}
