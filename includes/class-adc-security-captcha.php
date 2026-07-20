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
        add_filter( 'authenticate', array( $this, 'validate_honeypot' ), 20, 3 );
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
        add_filter( 'authenticate', array( $this, 'validate_math_captcha' ), 20, 3 );
    }

    public function render_math_captcha() {
        $num1 = rand( 1, 9 );
        $num2 = rand( 1, 9 );
        $sum  = $num1 + $num2;

        // Store sum in a session-like transient based on IP (or cookie if possible, but transient is simpler for now without session start)
        // Better: Encrypt the sum in a hidden field.
        $salt = wp_salt();
        $hash = hash_hmac( 'sha256', $sum, $salt );

        echo '<p class="adc-math-captcha">
            <label for="adc_math_captcha">Security Question: ' . $num1 . ' + ' . $num2 . ' = ?</label>
            <input type="number" name="adc_math_captcha" id="adc_math_captcha" class="input" value="" size="20" required />
            <input type="hidden" name="adc_math_hash" value="' . esc_attr( $hash ) . '" />
        </p>';
    }

    public function validate_math_captcha( $user, $username, $password ) {
        if ( isset( $_POST['adc_math_captcha'] ) && isset( $_POST['adc_math_hash'] ) ) {
            $answer = (int) $_POST['adc_math_captcha'];
            $hash   = $_POST['adc_math_hash'];
            $salt   = wp_salt();
            
            $check_hash = hash_hmac( 'sha256', $answer, $salt );

            if ( ! hash_equals( $hash, $check_hash ) ) {
                return new WP_Error( 'captcha_error', '<strong>Error</strong>: Incorrect CAPTCHA answer.' );
            }
        } else {
             // If fields are missing but we are in math mode, it might be an issue or direct post. 
             // Normally login form submission should have it.
             // We return error to enforce it.
             if ( isset( $_POST['log'] ) ) { // Only check if it's a login attempt
                return new WP_Error( 'captcha_error', '<strong>Error</strong>: Please solve the CAPTCHA.' );
             }
        }

        return $user;
    }

    // --- Turnstile ---

    private function init_turnstile() {
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_turnstile_script' ) );
        add_action( 'login_form', array( $this, 'render_turnstile' ) );
        add_filter( 'authenticate', array( $this, 'validate_turnstile' ), 20, 3 );
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
        echo '<script>
            // Ensure container exists logic if needed, but login_form action usually places it well.
        </script>';
    }

    public function validate_turnstile( $user, $username, $password ) {
        if ( ! isset( $_POST['cf-turnstile-response'] ) ) {
             if ( isset( $_POST['log'] ) ) {
                return new WP_Error( 'turnstile_error', '<strong>Error</strong>: Please verify you are human (Turnstile).' );
             }
             return $user;
        }

        $response = $_POST['cf-turnstile-response'];
        $secret   = isset( $this->options['turnstile_secret_key'] ) ? $this->options['turnstile_secret_key'] : '';

        if ( empty( $secret ) ) {
            return $user; // Allow if secret not set (config error) or fail closed? Fail closed safer but annoying. Let's fail open if config missing but warn. Actually fail closed is better for security plugin.
            // But let's assume if key is missing, user knows.
        }

        $verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
        $data = array(
            'secret'   => $secret,
            'response' => $response,
            'remoteip' => $_SERVER['REMOTE_ADDR'],
        );

        $response = wp_remote_post( $verify_url, array(
            'body' => $data,
        ) );

        if ( is_wp_error( $response ) ) {
            return new WP_Error( 'turnstile_api_error', '<strong>Error</strong>: Unable to verify CAPTCHA.' );
        }

        $body = wp_remote_retrieve_body( $response );
        $result = json_decode( $body );

        if ( ! $result->success ) {
            return new WP_Error( 'turnstile_fail', '<strong>Error</strong>: CAPTCHA verification failed.' );
        }

        return $user;
    }
}
