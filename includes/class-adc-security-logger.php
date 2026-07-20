<?php
/**
 * ADC Security Logger Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Logger {

    /**
     * Option Name
     */
    const OPTION_NAME = 'adc_security_error_log';

    /**
     * Max entries to keep
     */
    const MAX_ENTRIES = 50;

    /**
     * Previous error handler, if any.
     *
     * @var callable|false
     */
    private $previous_error_handler = false;

    /**
     * Constructor.
     */
	public function __construct() {
        // Chain to any previously registered error handler instead of replacing it.
        $this->previous_error_handler = set_error_handler( array( $this, 'handle_error' ) );

        set_exception_handler( array( $this, 'handle_exception' ) );

        // Only register the shutdown function once per process.
        static $shutdown_registered = false;
        if ( ! $shutdown_registered ) {
            register_shutdown_function( array( $this, 'handle_fatal' ) );
            $shutdown_registered = true;
        }
	}

    /**
     * Handle PHP Errors
     */
    public function handle_error( $errno, $errstr, $errfile, $errline ) {
        if ( strpos( $errfile, 'adc-security' ) !== false ) {
            $this->log( sprintf( 'PHP Error [%d]: %s in %s on line %d', $errno, $errstr, $errfile, $errline ), 'ERROR' );
        }
        
        // Chain to the previously registered error handler if one exists.
        if ( $this->previous_error_handler && is_callable( $this->previous_error_handler ) ) {
            return call_user_func( $this->previous_error_handler, $errno, $errstr, $errfile, $errline );
        }

        return false;
    }

    /**
     * Handle Uncaught Exceptions
     */
    public function handle_exception( $exception ) {
        if ( strpos( $exception->getFile(), 'adc-security' ) !== false ) {
            $this->log( sprintf( 'Uncaught Exception: %s in %s on line %d', $exception->getMessage(), $exception->getFile(), $exception->getLine() ), 'CRITICAL' );
        }
    }

    /**
     * Handle Fatal Errors on Shutdown
     */
    public function handle_fatal() {
        $error = error_get_last();
        if ( $error && ( $error['type'] === E_ERROR || $error['type'] === E_PARSE || $error['type'] === E_COMPILE_ERROR ) ) {
            if ( strpos( $error['file'], 'adc-security' ) !== false ) {
                $this->log( sprintf( 'Fatal Error: %s in %s on line %d', $error['message'], $error['file'], $error['line'] ), 'FATAL' );
            }
        }
    }

    /**
     * Log a message
     * 
     * @param string $message The message to log.
     * @param string $level   Log level (INFO, ERROR, etc).
     */
    public function log( $message, $level = 'INFO' ) {
        $logs = get_option( self::OPTION_NAME, array() );
        
        $entry = array(
            'timestamp' => current_time( 'mysql' ),
            'level'     => $level,
            'message'   => $message,
            'url'       => isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : 'CLI',
        );

        array_unshift( $logs, $entry );

        // Keep only the last X entries
        if ( count( $logs ) > self::MAX_ENTRIES ) {
            $logs = array_slice( $logs, 0, self::MAX_ENTRIES );
        }

        update_option( self::OPTION_NAME, $logs, false );
    }

    /**
     * Get all logs
     * 
     * @return array
     */
    public static function get_logs() {
        return get_option( self::OPTION_NAME, array() );
    }

    /**
     * Clear all logs
     */
    public static function clear_logs() {
        delete_option( self::OPTION_NAME );
    }
}
