<?php
/**
 * ADC Security Login Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Login {

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
        
        // Init Login Features
        if ( ! empty( $this->options['custom_login_slug'] ) ) {
            $this->init_custom_login();
        }
        
        if ( ! empty( $this->options['brute_force_protection'] ) ) {
            $this->init_brute_force_protection();
        }
	}

    /**
     * Init Custom Login URL
     */
    private function init_custom_login() {
        // Add rewrite rule
        add_action( 'init', array( $this, 'add_login_rewrite_rule' ) );
        add_filter( 'query_vars', array( $this, 'add_login_query_var' ) );
        add_action( 'template_include', array( $this, 'load_login_template' ) );
        
        // URLs
        add_filter( 'site_url', array( $this, 'filter_site_url' ), 10, 4 );
        add_filter( 'network_site_url', array( $this, 'filter_site_url' ), 10, 3 );
        add_filter( 'wp_redirect', array( $this, 'filter_wp_redirect' ), 10, 2 );

        // Block wp-login.php
        add_action( 'init', array( $this, 'block_wp_login' ) );
        
        // Block wp-admin
        add_action( 'init', array( $this, 'block_wp_admin' ) );

        // Flush Rules Check - Late to ensure rules are added
        add_action( 'init', array( $this, 'maybe_flush_rewrite_rules' ), 999 );

        // Fallback: Parse Request Manual Check
        add_action( 'parse_request', array( $this, 'check_custom_login_request' ) );
    }

    /**
     * Fallback to detect custom login slug if rewrite rules fail
     * 
     * @param WP $wp Current WordPress environment instance.
     */
    public function check_custom_login_request( $wp ) {
        if ( isset( $wp->query_vars['adc_login'] ) ) {
            return;
        }

        $slug = isset( $this->options['custom_login_slug'] ) ? $this->options['custom_login_slug'] : '';
        if ( empty( $slug ) ) {
            return;
        }

        // Get requested path relative to home root
        $request_uri = $_SERVER['REQUEST_URI'];
        $home_path = parse_url( home_url(), PHP_URL_PATH );
        
        if ( $home_path && '/' !== $home_path ) {
            // Remove installation subdirectory from path
             $request_uri = preg_replace( '#^' . preg_quote( $home_path, '#' ) . '#', '', $request_uri );
        }
        
        // Remove query strings
        $request_path = strtok( $request_uri, '?' );
        $request_path = trim( $request_path, '/' );

        if ( $request_path === $slug ) {
            $wp->query_vars['adc_login'] = 1;
        }
    }

    /**
     * Maybe Flush Rewrite Rules
     */
    public function maybe_flush_rewrite_rules() {
        if ( get_transient( 'adc_security_flush_rewrite_rules' ) ) {
            delete_transient( 'adc_security_flush_rewrite_rules' );
            flush_rewrite_rules();
        }
    }

    /**
     * Init Brute Force Protection
     */
    private function init_brute_force_protection() {
        add_action( 'wp_login_failed', array( $this, 'handle_failed_login' ) );
        add_filter( 'authenticate', array( $this, 'check_login_attempts' ), 30, 3 );
    }
    
    // --- Custom Login Methods ---

    public function add_login_rewrite_rule() {
        $slug = $this->options['custom_login_slug'];
        add_rewrite_rule( '^' . $slug . '/?$', 'index.php?adc_login=1', 'top' );
    }

    public function add_login_query_var( $vars ) {
        $vars[] = 'adc_login';
        return $vars;
    }

    public function load_login_template( $template ) {
        if ( get_query_var( 'adc_login' ) ) {
            // We need to allow wp-login.php to run, but context is different.
            $file = ABSPATH . 'wp-login.php';
            if ( file_exists( $file ) ) {
                // Initialize globals expected by wp-login.php to avoid warnings
                if ( ! isset( $user_login ) ) { $user_login = ''; }
                if ( ! isset( $error ) ) { $error = ''; }
                
                // Ensure globally available logic works if needed (though wp-login.php usually sets them)
                // The issue is likely that when we include it inside a function, scope is local.
                // We need to make sure variables used in wp-login.php are global or available.
                // wp-login.php relies on globals.
                
                global $user_login, $user_identity, $error, $action;
                
                // Define some defaults if undefined
                if ( ! isset( $user_login ) ) $user_login = '';
                if ( ! isset( $error ) ) $error = '';

                // Force 200 OK header (in case we hijacked a 404)
                status_header( 200 );

                include $file;
                exit;
            }
        }
        return $template;
    }

    public function filter_site_url( $url, $path, $scheme, $blog_id = null ) {
        return $this->replace_login_url( $url, $scheme );
    }

    public function filter_wp_redirect( $location, $status ) {
        return $this->replace_login_url( $location );
    }

    private function replace_login_url( $url, $scheme = null ) {
        // Don't rewrite if it's a logout action or logout confirmation.
        if ( strpos( $url, 'action=logout' ) !== false || strpos( $url, 'loggedout=true' ) !== false ) {
            return $url;
        }

        if ( strpos( $url, 'wp-login.php' ) !== false && ! empty( $this->options['custom_login_slug'] ) ) {
            $slug = $this->options['custom_login_slug'];
            // Handle query args
            $parsed_url = parse_url( $url );
            $query = isset( $parsed_url['query'] ) ? '?' . $parsed_url['query'] : '';
            
            // If action=logout is present, we might want to keep it or just let the rewrite handle it.
            // But usually, we redirect to the custom slug with the query args.
            // Example: /custom-login/?action=logout&_wpnonce=...
            
            $new_url = home_url( '/' . $slug . '/' . $query, $scheme );
            return $new_url;
        }
        return $url;
    }

    public function block_wp_login() {
        // If accessing wp-login.php directly and not via our internal include or CLI
        if ( strpos( $_SERVER['REQUEST_URI'], 'wp-login.php' ) !== false && ! isset( $_REQUEST['adc_login'] ) ) {
            // Allow logout action
            if ( isset( $_REQUEST['action'] ) && 'logout' === $_REQUEST['action'] ) {
                return;
            }

            // Check if it's not an XML-RPC request or something else valid
            // Redirect to Home to hide the custom slug
            wp_safe_redirect( home_url() );
            exit;
        }
    }

    public function block_wp_admin() {
        // Block access to wp-admin for non-logged-in users
        // Allow AJAX and admin-post.php
        if ( is_admin() && ! is_user_logged_in() && ! defined( 'DOING_AJAX' ) ) {
            // Check for admin-post.php explicitly as some plugins use it for guest form submissions
            if ( strpos( $_SERVER['REQUEST_URI'], 'admin-post.php' ) !== false ) {
                return;
            }
            
            wp_safe_redirect( home_url() );
            exit;
        }
    }

    // --- Brute Force Methods ---

    public function handle_failed_login( $username ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $transient_name = 'adc_bf_' . md5( $ip );
        $attempts = get_transient( $transient_name );
        
        if ( ! $attempts ) {
            $attempts = 0;
        }
        $attempts++;
        
        // Settings
        $max_attempts = ! empty( $this->options['bf_max_attempts'] ) ? (int) $this->options['bf_max_attempts'] : 5;
        $lockout_duration = ! empty( $this->options['bf_lockout_duration'] ) ? (int) $this->options['bf_lockout_duration'] : 60;
        $expiration = $lockout_duration * MINUTE_IN_SECONDS;

        // Expiration: Custom duration
        set_transient( $transient_name, $attempts, $expiration );

        // Send Notification if enabled and threshold reached
        if ( $attempts === $max_attempts ) {
            // Add to locked list for UI display
            $locked_ips = get_option( 'adc_locked_ips', array() );
            $locked_ips[ $ip ] = time() + $expiration;
            update_option( 'adc_locked_ips', $locked_ips );

            if ( ! empty( $this->options['login_notification'] ) ) {
                $admin_email = get_option( 'admin_email' );
                $subject = 'ADC Security: Failed Login Alert';
                $message = sprintf( 
                    'Too many failed login attempts detected from IP: %s' . "\r\n" . 
                    'Username tried: %s' . "\r\n" . 
                    'Time: %s', 
                    $ip, 
                    $username, 
                    current_time( 'mysql' ) 
                );
                wp_mail( $admin_email, $subject, $message );
            }
        }
    }

    public function check_login_attempts( $user, $username, $password ) {
        $ip = $_SERVER['REMOTE_ADDR'];
        $transient_name = 'adc_bf_' . md5( $ip );
        $attempts = get_transient( $transient_name );

        $max_attempts = ! empty( $this->options['bf_max_attempts'] ) ? (int) $this->options['bf_max_attempts'] : 5;
        $lockout_duration = ! empty( $this->options['bf_lockout_duration'] ) ? (int) $this->options['bf_lockout_duration'] : 60;

        // Threshold
        if ( $attempts && $attempts >= $max_attempts ) {
             return new WP_Error( 'too_many_attempts', sprintf( 'Too many failed login attempts. Please try again in %d minutes.', $lockout_duration ) );
        }
        
        return $user;
    }

    /**
     * Unblock an IP address.
     * 
     * @param string $ip IP Address.
     */
    public function unblock_ip( $ip ) {
        $transient_name = 'adc_bf_' . md5( $ip );
        delete_transient( $transient_name );
        
        $locked_ips = get_option( 'adc_locked_ips', array() );
        if ( isset( $locked_ips[ $ip ] ) ) {
            unset( $locked_ips[ $ip ] );
            update_option( 'adc_locked_ips', $locked_ips );
        }
    }

}
