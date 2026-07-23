<?php
/**
 * ADC Security Updater Class
 *
 * Pulls update information from GitHub Releases.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Updater {

	/**
	 * GitHub API response cache.
	 *
	 * @var object|false
	 */
	private $release = false;

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_update' ) );
		add_filter( 'plugins_api', array( $this, 'check_info' ), 10, 3 );
	}

	/**
	 * Inject update data into the plugins transient.
	 *
	 * @param object $transient Plugin update transient.
	 * @return object
	 */
	public function check_update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$release = $this->get_latest_release();

		if ( ! $release ) {
			return $transient;
		}

		$remote_version = $this->parse_version( $release->tag_name );

		if ( ! $remote_version ) {
			return $transient;
		}

		if ( version_compare( ADC_SECURITY_VERSION, $remote_version, '<' ) ) {
			$download_url = $this->find_zip_asset( $release );

			if ( ! $download_url ) {
				return $transient;
			}

			$res                = new stdClass();
			$res->slug          = 'adc-security';
			$res->plugin        = plugin_basename( ADC_SECURITY_FILE );
			$res->new_version   = $remote_version;
			$res->package       = $download_url;
			$res->tested        = $this->get_wp_tested_version( $release );
			$res->requires      = '5.8';
			$res->requires_php  = '7.4';
			$res->icons         = $this->get_plugin_icons();
			$res->icon          = $res->icons['svg'];

			$transient->response[ $res->plugin ] = $res;
		}

		return $transient;
	}

	/**
	 * Provide plugin info for the "View version details" popup.
	 *
	 * @param false|object $result Existing result or false.
	 * @param string       $action API action.
	 * @param object       $args   API arguments.
	 * @return false|object
	 */
	public function check_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}

		if ( 'adc-security' !== $args->slug ) {
			return $result;
		}

		$release = $this->get_latest_release();

		if ( ! $release ) {
			return $result;
		}

		$remote_version = $this->parse_version( $release->tag_name );
		$download_url   = $this->find_zip_asset( $release );

		if ( ! $remote_version || ! $download_url ) {
			return $result;
		}

		$res                 = new stdClass();
		$res->name           = 'ADcelerum Core Security';
		$res->slug           = 'adc-security';
		$res->version        = $remote_version;
		$res->author         = 'Dan Mutu - adcelerum.ro';
		$res->author_profile = 'https://adcelerum.ro';
		$res->requires       = '5.8';
		$res->requires_php   = '7.4';
		$res->download_link  = $download_url;
		$res->trunk          = $download_url;
		$res->last_updated   = isset( $release->published_at ) ? $release->published_at : '';
		$res->tested         = $this->get_wp_tested_version( $release );
		$res->icons          = $this->get_plugin_icons();

		$res->sections = array(
			'description'  => $this->get_release_body_html( $release ),
			'changelog'    => $this->get_release_body_html( $release ),
		);

		return $res;
	}

	/**
	 * Fetch and cache the latest GitHub release.
	 *
	 * @return object|false
	 */
	private function get_latest_release() {
		if ( false !== $this->release ) {
			return $this->release;
		}

		if ( ! defined( 'ADC_SECURITY_UPDATE_URL' ) ) {
			$this->release = false;
			return false;
		}

		$request = wp_remote_get( ADC_SECURITY_UPDATE_URL, array(
			'timeout'    => 15,
			'sslverify'  => true,
			'user-agent' => 'ADC-Security-Plugin/' . ADC_SECURITY_VERSION,
			'headers'    => array(
				'Accept' => 'application/vnd.github.v3+json',
			),
		) );

		if ( is_wp_error( $request ) || wp_remote_retrieve_response_code( $request ) !== 200 ) {
			$this->release = false;
			return false;
		}

		$body  = wp_remote_retrieve_body( $request );
		$release = json_decode( $body );

		if ( ! is_object( $release ) || ! isset( $release->tag_name ) ) {
			$this->release = false;
			return false;
		}

		$this->release = $release;
		return $this->release;
	}

	/**
	 * Strip a leading "v" from a tag name and return the semver string.
	 *
	 * @param string $tag_name e.g. "v1.4.0".
	 * @return string|false
	 */
	private function parse_version( $tag_name ) {
		$version = preg_replace( '/^v/i', '', trim( $tag_name ) );

		if ( preg_match( '/^\d+\.\d+\.\d+/', $version ) ) {
			return $version;
		}

		return false;
	}

	/**
	 * Get the WordPress plugin archive from a release.
	 *
	 * GitHub's generated source archives use a repository-and-tag directory
	 * name, which does not match this plugin's installed directory. Releases
	 * must therefore include an adc-security.zip asset rooted at adc-security/.
	 *
	 * @param object $release GitHub release object.
	 * @return string|false
	 */
	private function find_zip_asset( $release ) {
		if ( empty( $release->assets ) || ! is_array( $release->assets ) ) {
			return false;
		}

		foreach ( $release->assets as $asset ) {
			if ( isset( $asset->name, $asset->browser_download_url ) && 'adc-security.zip' === $asset->name ) {
				return $asset->browser_download_url;
			}
		}

		return false;
	}

	/**
	 * Extract the WP "Tested up to" version from the release body.
	 *
	 * Looks for patterns like "Tested up to: 6.7" or "Tested: 6.7".
	 *
	 * @param object $release GitHub release object.
	 * @return string
	 */
	private function get_wp_tested_version( $release ) {
		$body = isset( $release->body ) ? $release->body : '';

		if ( preg_match( '/Tested\s+(?:up\s+to)?\s*:?\s*(\d+\.\d+(?:\.\d+)?)/i', $body, $m ) ) {
			return $m[1];
		}

		return '';
	}

	/**
	 * Convert Markdown release body to basic HTML for the details popup.
	 *
	 * @param object $release GitHub release object.
	 * @return string
	 */
	private function get_release_body_html( $release ) {
		$body = isset( $release->body ) ? $release->body : '';

		if ( '' === $body ) {
			return '<p>No release notes available.</p>';
		}

		$html = wp_kses_post( nl2br( esc_html( $body ) ) );
		return $html;
	}

	/**
	 * Return icon metadata for WordPress update and plugin-information views.
	 *
	 * @return array<string,string>
	 */
	private function get_plugin_icons() {
		$icon_url = ADC_SECURITY_URL . 'assets/svg/icon-menu.svg';

		return array(
			'1x'  => $icon_url,
			'2x'  => $icon_url,
			'svg' => $icon_url,
		);
	}
}
