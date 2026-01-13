<?php
/**
 * ADC Security Hardening Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Hardening {

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

        if ( ! empty( $this->options['hide_wp_version'] ) ) {
            $this->init_hide_version();
        }

        if ( ! empty( $this->options['disable_xmlrpc'] ) ) {
            $this->init_disable_xmlrpc();
        }

        if ( ! empty( $this->options['disable_file_editor'] ) ) {
            $this->init_disable_file_editor();
        }

        if ( ! empty( $this->options['disable_rest_api'] ) ) {
            $this->init_disable_rest_api();
        }

        if ( ! empty( $this->options['security_headers'] ) ) {
            $this->init_security_headers();
        }

        // Auto Updates
        $this->init_auto_updates();
	}

    /**
     * Auto Updates Logic
     */
    private function init_auto_updates() {
        // Plugins
        if ( isset( $this->options['auto_update_plugins'] ) ) {
            switch ( $this->options['auto_update_plugins'] ) {
                case 'enable':
                    add_filter( 'auto_update_plugin', '__return_true' );
                    break;
                case 'disable':
                    add_filter( 'auto_update_plugin', '__return_false' );
                    break;
            }
        }

        // Themes
        if ( isset( $this->options['auto_update_themes'] ) ) {
             switch ( $this->options['auto_update_themes'] ) {
                case 'enable':
                    add_filter( 'auto_update_theme', '__return_true' );
                    break;
                case 'disable':
                    add_filter( 'auto_update_theme', '__return_false' );
                    break;
            }
        }

        // Core
        if ( isset( $this->options['auto_update_core'] ) ) {
             switch ( $this->options['auto_update_core'] ) {
                case 'major':
                    add_filter( 'allow_major_auto_core_updates', '__return_true' );
                    add_filter( 'allow_minor_auto_core_updates', '__return_true' );
                    break;
                case 'disable':
                    add_filter( 'auto_update_core', '__return_false' );
                    break;
                // 'minor' is default, so no action needed usually, but we could enforce it.
                // Keeping it default lets WP decide.
            }
        }
    }

    /**
     * Hide WP Version
     */
    private function init_hide_version() {
        remove_action( 'wp_head', 'wp_generator' );
        add_filter( 'the_generator', '__return_empty_string' );
    }

    /**
     * Disable XML-RPC
     */
    private function init_disable_xmlrpc() {
        add_filter( 'xmlrpc_enabled', '__return_false' );
    }

    /**
     * Disable File Editor
     */
    private function init_disable_file_editor() {
        if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
            define( 'DISALLOW_FILE_EDIT', true );
        }
    }

    /**
     * Disable REST API for non-authenticated users
     */
    private function init_disable_rest_api() {
        add_filter( 'rest_authentication_errors', function( $result ) {
            if ( ! empty( $result ) ) {
                return $result;
            }
            if ( ! is_user_logged_in() ) {
                return new WP_Error( 'rest_not_logged_in', 'You are not currently logged in.', array( 'status' => 401 ) );
            }
            return $result;
        });
    }

    /**
     * Add Security Headers
     */
    private function init_security_headers() {
        add_action( 'send_headers', function() {
            header( 'X-Content-Type-Options: nosniff' );
            header( 'X-Frame-Options: SAMEORIGIN' );
            header( 'X-XSS-Protection: 1; mode=block' );
            header( 'Referrer-Policy: strict-origin-when-cross-origin' );
            
            // Content Security Policy - "Safe" Default (Permissive but enables CSP structure)
            // Allows self, https (external CDNs), data, inline scripts/styles (required by WP core/themes)
            header( "Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';" );
            
            // Permissions Policy - Disable common sensitive features by default
            header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()' );
            
            // Strict-Transport-Security (HSTS) - Enforce HTTPS
            header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
        });
    }
}

