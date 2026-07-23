<?php
/**
 * Safe, fixed-rule .htaccess manager.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Htaccess {

	const BEGIN_MARKER = '# BEGIN ADC Security';
	const END_MARKER   = '# END ADC Security';
	const MAX_FILE_SIZE = 1048576;
	const BACKUP_OPTION  = 'adc_security_htaccess_backup';
	const STATE_OPTION   = 'adc_security_htaccess_state';

	/**
	 * Return the only rules this manager can write.
	 *
	 * No administrator-provided directive text is accepted.
	 *
	 * @return array<string,array<string,mixed>>
	 */
	public static function get_rule_definitions() {
		return array(
			'block_xmlrpc_endpoint' => array(
				'label'       => 'Block direct XML-RPC access',
				'description' => 'Blocks requests to xmlrpc.php. Do not enable if you use Jetpack, the WordPress mobile app, or XML-RPC integrations.',
				'lines'       => array(
					'<FilesMatch "^xmlrpc\\.php$">',
					'    <IfModule mod_authz_core.c>',
					'        Require all denied',
					'    </IfModule>',
					'    <IfModule !mod_authz_core.c>',
					'        Order Allow,Deny',
					'        Deny from all',
					'    </IfModule>',
					'</FilesMatch>',
				),
			),
			'block_sensitive_files' => array(
				'label'       => 'Block common sensitive files',
				'description' => 'Blocks direct access to wp-config.php, .env, .htaccess, and .htpasswd.',
				'lines'       => array(
					'<FilesMatch "^(wp-config\\.php|\\.env|\\.htaccess|\\.htpasswd)$">',
					'    <IfModule mod_authz_core.c>',
					'        Require all denied',
					'    </IfModule>',
					'    <IfModule !mod_authz_core.c>',
					'        Order Allow,Deny',
					'        Deny from all',
					'    </IfModule>',
					'</FilesMatch>',
				),
			),
			'disable_upload_php' => array(
				'label'       => 'Disable PHP execution in uploads',
				'description' => 'Rejects PHP-like files under wp-content/uploads while leaving normal media files available.',
				'lines'       => array(
					'<IfModule mod_rewrite.c>',
					'    RewriteEngine On',
					'    RewriteRule ^wp-content/uploads/.*\\.(?:php[0-9]?|phtml|phar)$ - [F,L,NC]',
					'</IfModule>',
				),
			),
		);
	}

	/**
	 * Return rule keys accepted by the manager.
	 *
	 * @return string[]
	 */
	public static function get_rule_keys() {
		return array_keys( self::get_rule_definitions() );
	}

	/**
	 * Return the detected web server family.
	 *
	 * @return string
	 */
	public function get_server_type() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) && is_string( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) ) : '';

		if ( false !== strpos( $server, 'litespeed' ) ) {
			return 'litespeed';
		}

		if ( false !== strpos( $server, 'apache' ) ) {
			return 'apache';
		}

		if ( false !== strpos( $server, 'nginx' ) ) {
			return 'nginx';
		}

		if ( false !== strpos( $server, 'microsoft-iis' ) || false !== strpos( $server, 'iis' ) ) {
			return 'iis';
		}

		return 'unknown';
	}

	/**
	 * Return whether this server can use .htaccess.
	 *
	 * @return bool
	 */
	public function is_supported_server() {
		return in_array( $this->get_server_type(), array( 'apache', 'litespeed' ), true );
	}

	/**
	 * Return the site .htaccess path without accepting a path from input.
	 *
	 * @return string|WP_Error
	 */
	public function get_htaccess_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}

		$home_path = function_exists( 'get_home_path' ) ? get_home_path() : ABSPATH;
		$home_path = rtrim( $home_path, '/\\' );

		if ( is_link( $home_path ) ) {
			return new WP_Error( 'adc_htaccess_symlink', 'The WordPress home directory is a symlink and will not be modified.' );
		}

		$directory = realpath( $home_path );

		if ( false === $directory || ! is_dir( $directory ) ) {
			return new WP_Error( 'adc_htaccess_invalid_path', 'The WordPress home directory could not be resolved.' );
		}

		$path = trailingslashit( $directory ) . '.htaccess';

		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_htaccess_symlink', 'The .htaccess file is a symlink and will not be modified.' );
		}

		return $path;
	}

	/**
	 * Return current manager state for the admin UI.
	 *
	 * @return array<string,mixed>
	 */
	public function get_status() {
		$path = $this->get_htaccess_path();
		$status = array(
			'server'     => $this->get_server_type(),
			'supported'  => $this->is_supported_server(),
			'path'       => $path,
			'exists'     => false,
			'managed'    => false,
			'drift'      => false,
			'has_backup' => (bool) get_option( self::BACKUP_OPTION, array() ),
		);

		if ( is_wp_error( $path ) ) {
			$status['error'] = $path->get_error_message();
			return $status;
		}

		if ( ! file_exists( $path ) ) {
			return $status;
		}

		$status['exists'] = true;
		$contents = $this->read_file( $path );
		if ( is_wp_error( $contents ) ) {
			$status['error'] = $contents->get_error_message();
			return $status;
		}

		$status['managed'] = $this->has_valid_marker_block( $contents );
		$state = get_option( self::STATE_OPTION, array() );
		if ( $status['managed'] && is_array( $state ) && ! empty( $state['hash'] ) ) {
			$status['drift'] = ! hash_equals( (string) $state['hash'], hash( 'sha256', $contents ) );
		}
		return $status;
	}

	/**
	 * Apply fixed rules selected in the admin UI.
	 *
	 * @param mixed $rule_keys Selected fixed rule keys.
	 * @return true|WP_Error
	 */
	public function apply( $rule_keys ) {
		if ( ! $this->is_supported_server() ) {
			return new WP_Error( 'adc_htaccess_unsupported_server', 'Automatic .htaccess changes are supported only on Apache and LiteSpeed.' );
		}

		$rule_keys = $this->validate_rule_keys( $rule_keys );
		if ( is_wp_error( $rule_keys ) ) {
			return $rule_keys;
		}

		if ( empty( $rule_keys ) ) {
			return new WP_Error( 'adc_htaccess_no_rules', 'Select at least one fixed rule before applying the .htaccess changes.' );
		}

		$path = $this->get_htaccess_path();
		if ( is_wp_error( $path ) ) {
			return $path;
		}

		$contents = file_exists( $path ) ? $this->read_file( $path ) : '';
		if ( is_wp_error( $contents ) ) {
			return $contents;
		}

		if ( ! $this->has_valid_marker_structure( $contents ) ) {
			return new WP_Error( 'adc_htaccess_invalid_markers', 'The ADC Security .htaccess marker block is missing or malformed. No changes were made.' );
		}

		if ( ! get_option( self::BACKUP_OPTION, array() ) ) {
			$backup = array(
				'path'       => $path,
				'hash'       => hash( 'sha256', $contents ),
				'content'    => $contents,
				'created_at' => current_time( 'mysql', true ),
			);
			update_option( self::BACKUP_OPTION, $backup, false );
		}

		$updated = $this->replace_marker_block( $contents, $this->build_block( $rule_keys ) );
		if ( is_wp_error( $updated ) ) {
			return $updated;
		}

		if ( $updated !== $contents ) {
			$result = $this->write_file( $path, $updated );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
		}

		update_option(
			self::STATE_OPTION,
			array(
				'path'       => $path,
				'hash'       => hash( 'sha256', $updated ),
				'rules'      => $rule_keys,
				'applied_at' => current_time( 'mysql', true ),
			),
			false
		);

		return true;
	}

	/**
	 * Remove only the managed ADC Security block.
	 *
	 * @return true|WP_Error
	 */
	public function revert() {
		$path = $this->get_htaccess_path();
		if ( is_wp_error( $path ) ) {
			return $path;
		}

		if ( ! file_exists( $path ) ) {
			delete_option( self::STATE_OPTION );
			return true;
		}

		$contents = $this->read_file( $path );
		if ( is_wp_error( $contents ) ) {
			return $contents;
		}

		if ( ! $this->has_valid_marker_structure( $contents ) ) {
			return new WP_Error( 'adc_htaccess_invalid_markers', 'The ADC Security .htaccess marker block is missing or malformed. No changes were made.' );
		}

		if ( ! $this->has_valid_marker_block( $contents ) ) {
			delete_option( self::STATE_OPTION );
			return true;
		}

		$state  = get_option( self::STATE_OPTION, array() );
		$backup = get_option( self::BACKUP_OPTION, array() );
		$current_hash = hash( 'sha256', $contents );

		// Restore the exact pre-ADC file only when no external change occurred.
		// Otherwise remove only our block and preserve the external edit.
		if (
			is_array( $state ) && is_array( $backup ) &&
			isset( $state['hash'], $state['path'], $backup['path'] ) &&
			array_key_exists( 'content', $backup ) &&
			$path === $state['path'] && $path === $backup['path'] &&
			hash_equals( (string) $state['hash'], $current_hash )
		) {
			$updated = (string) $backup['content'];
		} else {
			$pattern = '/' . preg_quote( self::BEGIN_MARKER, '/' ) . '\\r?\\n.*?' . preg_quote( self::END_MARKER, '/' ) . '\\r?\\n?/s';
			$updated = preg_replace( $pattern, '', $contents, 1, $count );
			if ( 1 !== $count || null === $updated ) {
				return new WP_Error( 'adc_htaccess_revert_failed', 'The managed .htaccess block could not be removed safely.' );
			}
		}

		$result = $this->write_file( $path, $updated );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		delete_option( self::STATE_OPTION );
		return true;
	}

	/**
	 * Build a deterministic managed block from fixed rule definitions.
	 *
	 * @param string[] $rule_keys Validated keys.
	 * @return string
	 */
	public function build_block( $rule_keys ) {
		$definitions = self::get_rule_definitions();
		$lines = array( self::BEGIN_MARKER, '# Rules are generated by ADC Security. Do not edit this block.' );

		foreach ( $rule_keys as $rule_key ) {
			if ( ! isset( $definitions[ $rule_key ] ) ) {
				continue;
			}

			$lines[] = '';
			$lines = array_merge( $lines, $definitions[ $rule_key ]['lines'] );
		}

		$lines[] = self::END_MARKER;
		return implode( "\n", $lines ) . "\n";
	}

	/**
	 * Validate selected keys against the fixed allowlist.
	 *
	 * @param mixed $rule_keys Raw selected keys.
	 * @return string[]|WP_Error
	 */
	private function validate_rule_keys( $rule_keys ) {
		if ( ! is_array( $rule_keys ) ) {
			return new WP_Error( 'adc_htaccess_invalid_rules', 'Invalid .htaccess rule selection.' );
		}

		$rule_keys = array_values( array_unique( array_filter( array_map( 'sanitize_key', array_filter( $rule_keys, 'is_string' ) ) ) ) );
		$allowed = self::get_rule_keys();

		if ( count( array_diff( $rule_keys, $allowed ) ) > 0 ) {
			return new WP_Error( 'adc_htaccess_unknown_rule', 'An unknown .htaccess rule was rejected.' );
		}

		return array_values( array_intersect( $allowed, $rule_keys ) );
	}

	/**
	 * Read a bounded file without following a symlink.
	 *
	 * @param string $path Trusted path generated by get_htaccess_path().
	 * @return string|WP_Error
	 */
	private function read_file( $path ) {
		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_htaccess_symlink', 'The .htaccess file is a symlink and will not be modified.' );
		}

		if ( file_exists( $path ) ) {
			$size = filesize( $path );
			if ( false === $size || $size > self::MAX_FILE_SIZE ) {
				return new WP_Error( 'adc_htaccess_too_large', 'The .htaccess file is missing or larger than the safe processing limit.' );
			}
		}

		$contents = file_exists( $path ) ? file_get_contents( $path ) : '';
		if ( false === $contents ) {
			return new WP_Error( 'adc_htaccess_unreadable', 'The .htaccess file could not be read.' );
		}

		return $contents;
	}

	/**
	 * Write atomically in the existing directory.
	 *
	 * @param string $path Trusted path generated by get_htaccess_path().
	 * @param string $contents File contents.
	 * @return true|WP_Error
	 */
	private function write_file( $path, $contents ) {
		$directory = dirname( $path );
		if ( ! is_dir( $directory ) || ! is_writable( $directory ) ) {
			return new WP_Error( 'adc_htaccess_not_writable', 'The WordPress home directory is not writable.' );
		}

		if ( is_link( $path ) ) {
			return new WP_Error( 'adc_htaccess_symlink', 'The .htaccess file is a symlink and will not be modified.' );
		}

		$temp_path = tempnam( $directory, '.adc-security-' );
		if ( false === $temp_path ) {
			return new WP_Error( 'adc_htaccess_temp_failed', 'A temporary .htaccess file could not be created.' );
		}

		$bytes = file_put_contents( $temp_path, $contents, LOCK_EX );
		if ( false === $bytes || $bytes !== strlen( $contents ) ) {
			unlink( $temp_path );
			return new WP_Error( 'adc_htaccess_write_failed', 'The temporary .htaccess file could not be written completely.' );
		}

		if ( file_exists( $path ) ) {
			$permissions = fileperms( $path );
			if ( false !== $permissions ) {
				chmod( $temp_path, $permissions & 0777 );
			}
		}

		if ( ! rename( $temp_path, $path ) ) {
			unlink( $temp_path );
			return new WP_Error( 'adc_htaccess_rename_failed', 'The updated .htaccess file could not replace the existing file.' );
		}

		return true;
	}

	/**
	 * Check marker count and ordering without modifying the file.
	 *
	 * @param string $contents File contents.
	 * @return bool
	 */
	private function has_valid_marker_structure( $contents ) {
		$begin_count = substr_count( $contents, self::BEGIN_MARKER );
		$end_count   = substr_count( $contents, self::END_MARKER );

		if ( 0 === $begin_count && 0 === $end_count ) {
			return true;
		}

		return 1 === $begin_count && 1 === $end_count && strpos( $contents, self::BEGIN_MARKER ) < strpos( $contents, self::END_MARKER );
	}

	/**
	 * Check whether a complete managed block exists.
	 *
	 * @param string $contents File contents.
	 * @return bool
	 */
	private function has_valid_marker_block( $contents ) {
		return 1 === substr_count( $contents, self::BEGIN_MARKER ) && 1 === substr_count( $contents, self::END_MARKER ) && strpos( $contents, self::BEGIN_MARKER ) < strpos( $contents, self::END_MARKER );
	}

	/**
	 * Insert or replace the managed block.
	 *
	 * @param string $contents Existing contents.
	 * @param string $block Generated block.
	 * @return string|WP_Error
	 */
	private function replace_marker_block( $contents, $block ) {
		$pattern = '/' . preg_quote( self::BEGIN_MARKER, '/' ) . '\\r?\\n.*?' . preg_quote( self::END_MARKER, '/' ) . '\\r?\\n?/s';

		if ( $this->has_valid_marker_block( $contents ) ) {
			$updated = preg_replace( $pattern, $block, $contents, 1, $count );
			if ( 1 !== $count || null === $updated ) {
				return new WP_Error( 'adc_htaccess_replace_failed', 'The managed .htaccess block could not be replaced safely.' );
			}
			return $updated;
		}

		// The generated block already ends with a newline, so the original file
		// can be appended unchanged and revert can restore its exact contents.
		return $block . $contents;
	}
}
