<?php
/**
 * ADC Security Updater Class
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Updater {

	/**
	 * Constructor.
	 */
	public function __construct() {
        // Hook into the transient for updates
        add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_update' ) );
        
        // Hook into plugin details popup
        add_filter( 'plugins_api', array( $this, 'check_info' ), 10, 3 );
	}

    /**
     * Check for Updates
     * 
     * @param object $transient Plugin update transient.
     * @return object
     */
    public function check_update( $transient ) {
        if ( empty( $transient->checked ) ) {
            return $transient;
        }

        // Get remote version
        $remote_version = $this->get_remote_version();

        if ( $remote_version && version_compare( ADC_SECURITY_VERSION, $remote_version->version, '<' ) ) {
            $res = new stdClass();
            $res->slug = 'adc-security';
            $res->plugin = plugin_basename( ADC_SECURITY_FILE );
            $res->new_version = $remote_version->version;
            $res->package = $remote_version->download_url;
            $res->tested = isset( $remote_version->tested ) ? $remote_version->tested : '';
            $res->requires = isset( $remote_version->requires ) ? $remote_version->requires : '';
            $res->requires_php = isset( $remote_version->requires_php ) ? $remote_version->requires_php : '';
            
            $transient->response[ $res->plugin ] = $res;
        }

        return $transient;
    }

    /**
     * Plugin Information Popup
     * 
     * @param false|object $result The result object or false.
     * @param string       $action The API action.
     * @param object       $args   The API arguments.
     * @return false|object
     */
    public function check_info( $result, $action, $args ) {
        if ( 'plugin_information' !== $action ) {
            return $result;
        }

        if ( 'adc-security' !== $args->slug ) {
            return $result;
        }

        $remote_version = $this->get_remote_version();

        if ( $remote_version ) {
            $res = new stdClass();
            $res->name = 'ADcelerum Core Security';
            $res->slug = 'adc-security';
            $res->version = $remote_version->version;
            $res->tested = isset( $remote_version->tested ) ? $remote_version->tested : '';
            $res->requires = isset( $remote_version->requires ) ? $remote_version->requires : '';
            $res->author = 'Dan Mutu - adcelerum.ro';
            $res->author_profile = 'https://adcelerum.ro';
            $res->download_link = $remote_version->download_url;
            $res->trunk = $remote_version->download_url;
            $res->requires_php = isset( $remote_version->requires_php ) ? $remote_version->requires_php : '';
            $res->last_updated = isset( $remote_version->last_updated ) ? $remote_version->last_updated : '';
            
            if ( isset( $remote_version->sections ) ) {
                $res->sections = (array) $remote_version->sections;
            }

            return $res;
        }

        return $result;
    }

    /**
     * Get Remote Version
     * 
     * @return object|bool
     */
    private function get_remote_version() {
        if ( ! defined( 'ADC_SECURITY_UPDATE_URL' ) ) {
            return false;
        }

        $request = wp_remote_get( ADC_SECURITY_UPDATE_URL, array(
            'timeout' => 15,
            'sslverify' => true
        ) );

        if ( is_wp_error( $request ) || wp_remote_retrieve_response_code( $request ) !== 200 ) {
            return false;
        }

        $body = wp_remote_retrieve_body( $request );
        $data = json_decode( $body );

        if ( ! is_object( $data ) || ! isset( $data->version ) || ! isset( $data->download_url ) ) {
            return false;
        }

        return $data;
    }
}
