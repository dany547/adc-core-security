<?php
/**
 * Security key (salt) regeneration for wp-config.php.
 *
 * Fetches fresh values from the official WordPress.org secret-key API and
 * replaces the existing AUTH_KEY/SALT defines in place. Never accepts
 * administrator-provided key values and never inserts new defines into an
 * unrecognized wp-config.php structure.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Keys {

	const SALT_API_URL  = 'https://api.wordpress.org/secret-key/1.1/salt/';
	const MAX_FILE_SIZE = 1048576;
	const BACKUP_OPTION = 'adc_security_keys_backup';

	/**
	 * The eight standard WordPress authentication key/salt constants.
	 *
	 * @return string[]
	 */
	public static function get_key_names() {
		return array(
			'AUTH_KEY',
			'SECURE_AUTH_KEY',
			'LOGGED_IN_KEY',
			'NONCE_KEY',
			'AUTH_SALT',
			'SECURE_AUTH_SALT',
			'LOGGED_IN_SALT',
			'NONCE_SALT',
		);
	}

	/**
	 * Locate wp-config.php without accepting a path from input.
	 *
	 * @return string|WP_Error
	 */
	public function get_wp_config_path() {
		if ( file_exists( ABSPATH . 'wp-config.php' ) ) {
			$path = ABSPATH . 'wp-config.php';
		} elseif ( file_exists( dirname( ABSPATH ) . '/wp-config.php' ) && ! file_exists( dirname( ABSPATH ) . '/wp-settings.php' ) ) {
			$path = dirname( ABSPATH ) . '/wp-config.php';
		} else {
			return new WP_Error( 'adc_keys_missing_config', 'wp-config.php could not be located.' );
		}

		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_keys_symlink', 'wp-config.php is a symlink and will not be modified.' );
		}

		$real = realpath( $path );
		if ( false === $real ) {
			return new WP_Error( 'adc_keys_invalid_path', 'wp-config.php could not be resolved.' );
		}

		return $real;
	}

	/**
	 * Return current manager state for the admin UI.
	 *
	 * @return array<string,mixed>
	 */
	public function get_status() {
		$path = $this->get_wp_config_path();
		$status = array(
			'path'       => $path,
			'writable'   => false,
			'has_backup' => false,
			'backed_up_at' => '',
		);

		if ( is_wp_error( $path ) ) {
			$status['error'] = $path->get_error_message();
			return $status;
		}

		$status['writable'] = is_writable( $path );

		$backup = self::scrub_legacy_backup();
		if ( ! empty( $backup['lines'] ) ) {
			$status['has_backup']   = true;
			$status['backed_up_at'] = isset( $backup['created_at'] ) ? $backup['created_at'] : '';
		}

		return $status;
	}

	/**
	 * Fetch new keys from the WordPress.org API and apply them in place.
	 *
	 * @return true|WP_Error
	 */
	public function regenerate() {
		$path = $this->get_wp_config_path();
		if ( is_wp_error( $path ) ) {
			return $path;
		}

		if ( ! is_writable( $path ) ) {
			return new WP_Error( 'adc_keys_not_writable', 'wp-config.php is not writable.' );
		}

		$new_lines = $this->fetch_new_key_lines();
		if ( is_wp_error( $new_lines ) ) {
			return $new_lines;
		}

		$contents = $this->read_file( $path );
		if ( is_wp_error( $contents ) ) {
			return $contents;
		}

		$updated = $contents;
		foreach ( $new_lines as $key_name => $new_line ) {
			// Anchored to (optional leading whitespace +) "define(" so commented-out
			// lines such as "// define('AUTH_KEY', ...)" are never matched.
			$pattern = '/^[ \t]*define\(\s*[\'"]' . preg_quote( $key_name, '/' ) . '[\'"]\s*,.*\);.*$/m';
			if ( ! preg_match( $pattern, $updated ) ) {
				return new WP_Error(
					'adc_keys_definition_not_found',
					sprintf( 'The %s definition could not be found in wp-config.php. No changes were made.', $key_name )
				);
			}
			$updated = preg_replace_callback(
				$pattern,
				static function () use ( $new_line ) {
					return $new_line;
				},
				$updated,
				1
			);
		}

		if ( $updated === $contents ) {
			return new WP_Error( 'adc_keys_no_change', 'No key definitions were changed.' );
		}

		// Only keep the true pre-regeneration backup; a later regenerate() must
		// not overwrite it with an already-rotated set of keys, or "Restore"
		// would silently stop being able to recover the original values.
		// Only the key/salt define() lines are stored, never the whole file, so the
		// database never holds DB credentials from wp-config.php.
		$existing_backup = self::scrub_legacy_backup();
		if ( ! is_array( $existing_backup ) || empty( $existing_backup ) ) {
			update_option(
				self::BACKUP_OPTION,
				array(
					'path'       => $path,
					'lines'      => self::extract_key_lines( $contents ),
					'created_at' => current_time( 'mysql', true ),
				),
				false
			);
		}

		$result = $this->write_file( $path, $updated );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		return true;
	}

	/**
	 * Restore wp-config.php from the last backup taken by this manager.
	 *
	 * @return true|WP_Error
	 */
	public function restore() {
		$path = $this->get_wp_config_path();
		if ( is_wp_error( $path ) ) {
			return $path;
		}

		$backup = self::scrub_legacy_backup();
		if ( ! is_array( $backup ) || empty( $backup['lines'] ) || ! isset( $backup['path'] ) || $backup['path'] !== $path ) {
			return new WP_Error( 'adc_keys_no_backup', 'No matching security key backup is available.' );
		}

		$contents = $this->read_file( $path );
		if ( is_wp_error( $contents ) ) {
			return $contents;
		}

		$restored = $contents;
		foreach ( $backup['lines'] as $key_name => $line ) {
			$pattern = '/^[ \t]*define\(\s*[\'"]' . preg_quote( $key_name, '/' ) . '[\'"]\s*,.*\);.*$/m';
			if ( ! preg_match( $pattern, $restored ) ) {
				return new WP_Error( 'adc_keys_definition_not_found', sprintf( 'The %s definition could not be found in wp-config.php. No changes were made.', $key_name ) );
			}
			$restored = preg_replace_callback(
				$pattern,
				static function () use ( $line ) {
					return $line;
				},
				$restored,
				1
			);
		}

		$result = $this->write_file( $path, $restored );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		delete_option( self::BACKUP_OPTION );
		return true;
	}

	/**
	 * Pull only the eight key/salt define() lines out of a wp-config.php body.
	 *
	 * @param string $contents wp-config.php contents.
	 * @return array<string,string> Key name => full original line.
	 */
	private static function extract_key_lines( $contents ) {
		$lines = array();
		foreach ( self::get_key_names() as $key_name ) {
			$pattern = '/^[ \t]*define\(\s*[\'"]' . preg_quote( $key_name, '/' ) . '[\'"]\s*,.*\);.*$/m';
			if ( preg_match( $pattern, (string) $contents, $match ) ) {
				$lines[ $key_name ] = rtrim( $match[0], "\r\n" );
			}
		}
		return $lines;
	}

	/**
	 * Convert a pre-1.12.1 backup (which stored the whole wp-config.php, including
	 * database credentials) to the lines-only format and drop the full copy.
	 *
	 * @return array The stored backup, or an empty array.
	 */
	public static function scrub_legacy_backup() {
		$backup = get_option( self::BACKUP_OPTION, array() );
		if ( ! is_array( $backup ) ) {
			return array();
		}

		if ( isset( $backup['content'] ) ) {
			$backup['lines'] = self::extract_key_lines( (string) $backup['content'] );
			unset( $backup['content'] );
			if ( empty( $backup['lines'] ) ) {
				delete_option( self::BACKUP_OPTION );
				return array();
			}
			update_option( self::BACKUP_OPTION, $backup, false );
		}

		return $backup;
	}

	/**
	 * Fetch and validate new key definitions from the official salt API.
	 *
	 * @return array<string,string>|WP_Error
	 */
	private function fetch_new_key_lines() {
		$response = wp_remote_get(
			self::SALT_API_URL,
			array(
				'timeout' => 15,
			)
		);

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'adc_keys_fetch_failed', 'The WordPress.org secret-key service could not be reached.' );
		}

		if ( 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'adc_keys_fetch_failed', 'The WordPress.org secret-key service returned an unexpected response.' );
		}

		$body = wp_remote_retrieve_body( $response );
		$key_names = self::get_key_names();
		$found = array();

		foreach ( explode( "\n", $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || 0 !== strpos( $line, 'define(' ) ) {
				continue;
			}
			foreach ( $key_names as $key_name ) {
				if ( isset( $found[ $key_name ] ) ) {
					continue;
				}
				if ( preg_match( '/^define\(\s*[\'"]' . preg_quote( $key_name, '/' ) . '[\'"]\s*,.*\);\s*$/', $line ) ) {
					$found[ $key_name ] = $line;
				}
			}
		}

		if ( count( $found ) !== count( $key_names ) ) {
			return new WP_Error( 'adc_keys_incomplete_response', 'The secret-key service response did not contain all expected keys.' );
		}

		return $found;
	}

	/**
	 * Read a bounded file without following a symlink.
	 *
	 * @param string $path Trusted path from get_wp_config_path().
	 * @return string|WP_Error
	 */
	private function read_file( $path ) {
		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_keys_symlink', 'wp-config.php is a symlink and will not be modified.' );
		}

		$size = filesize( $path );
		if ( false === $size || $size > self::MAX_FILE_SIZE ) {
			return new WP_Error( 'adc_keys_too_large', 'wp-config.php is larger than the safe processing limit.' );
		}

		$contents = file_get_contents( $path );
		if ( false === $contents ) {
			return new WP_Error( 'adc_keys_unreadable', 'wp-config.php could not be read.' );
		}

		return $contents;
	}

	/**
	 * Write atomically in the existing directory, preserving permissions.
	 *
	 * @param string $path Trusted path from get_wp_config_path().
	 * @param string $contents File contents.
	 * @return true|WP_Error
	 */
	private function write_file( $path, $contents ) {
		$directory = dirname( $path );
		if ( ! is_dir( $directory ) || ! is_writable( $directory ) ) {
			return new WP_Error( 'adc_keys_dir_not_writable', 'The wp-config.php directory is not writable.' );
		}

		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_keys_symlink', 'wp-config.php is a symlink and will not be modified.' );
		}

		$temp_path = tempnam( $directory, '.adc-security-keys-' );
		if ( false === $temp_path ) {
			return new WP_Error( 'adc_keys_temp_failed', 'A temporary wp-config.php file could not be created.' );
		}

		$bytes = file_put_contents( $temp_path, $contents, LOCK_EX );
		if ( false === $bytes || $bytes !== strlen( $contents ) ) {
			unlink( $temp_path );
			return new WP_Error( 'adc_keys_write_failed', 'The temporary wp-config.php file could not be written completely.' );
		}

		$permissions = fileperms( $path );
		if ( false !== $permissions ) {
			chmod( $temp_path, $permissions & 0777 );
		}

		if ( ! rename( $temp_path, $path ) ) {
			unlink( $temp_path );
			return new WP_Error( 'adc_keys_rename_failed', 'The updated wp-config.php file could not replace the existing file.' );
		}

		return true;
	}
}
