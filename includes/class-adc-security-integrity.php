<?php
/**
 * ADC Security Integrity Class
 *
 * Integrity checks, all budgeted so they don't time out on shared hosting:
 *  1. Core file checksums, compared against api.wordpress.org's official
 *     list for the running WP version.
 *  2. Per-plugin and per-theme file checksums, compared against
 *     downloads.wordpress.org's official checksums for installed plugins/
 *     themes that are hosted on WordPress.org (skipped for premium/custom
 *     ones, same as they'd be skipped by any checksum-based check). This
 *     matters more than the core check in practice: most compromises land
 *     in plugin code, not core.
 *  3. A scan of wp-content/uploads for .php files and common webshell /
 *     obfuscation patterns (uploads should never contain executable PHP).
 *
 * A full pass is kicked off weekly and processes a bounded batch of files
 * per invocation, rescheduling itself via wp_schedule_single_event() until
 * the whole tree has been covered.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Integrity {

	const WEEKLY_HOOK    = 'adc_security_integrity_scan';
	const TICK_HOOK       = 'adc_security_integrity_tick';
	const STATE_OPTION    = 'adc_security_integrity_state';
	const RESULT_OPTION   = 'adc_security_integrity_result';
	const FILES_PER_TICK   = 150;
	const PACKAGES_PER_TICK = 5;
	const TIME_BUDGET_SEC  = 4;
	const CHECKSUM_CACHE_TTL = DAY_IN_SECONDS;

	/**
	 * Regexes flagging common webshell / obfuscation idioms. Intentionally
	 * broad; results are for a human to review, not to auto-delete.
	 *
	 * @var string[]
	 */
	private static $suspicious_patterns = array(
		'/\beval\s*\(/i',
		'/\bbase64_decode\s*\(/i',
		'/\bgzinflate\s*\(/i',
		'/\bgzuncompress\s*\(/i',
		'/\bstr_rot13\s*\(/i',
		'/\bassert\s*\(\s*\$/i',
		'/\bcreate_function\s*\(/i',
		'/\bpreg_replace\s*\([^)]*\/e[\'"]/i',
	);

	public function __construct() {
		add_filter( 'cron_schedules', array( $this, 'register_weekly_schedule' ) ); // phpcs:ignore WordPress.WP.CronInterval.CronSchedulesInterval
		add_action( self::WEEKLY_HOOK, array( $this, 'start_scan' ) );
		add_action( self::TICK_HOOK, array( $this, 'run_tick' ) );

		if ( ! wp_next_scheduled( self::WEEKLY_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'weekly', self::WEEKLY_HOOK );
		}
	}

	/**
	 * Register a 'weekly' interval; WP core only ships hourly/twicedaily/daily.
	 *
	 * @param array $schedules Existing cron schedules.
	 * @return array
	 */
	public function register_weekly_schedule( $schedules ) {
		if ( ! isset( $schedules['weekly'] ) ) {
			$schedules['weekly'] = array(
				'interval' => 7 * DAY_IN_SECONDS,
				'display'  => __( 'Once Weekly', 'adc-security' ),
			);
		}
		return $schedules;
	}

	/**
	 * Kick off a fresh scan pass (called weekly, or on demand from the admin UI).
	 */
	public function start_scan() {
		$state = get_option(
			self::STATE_OPTION,
			array(
				'status' => 'idle',
			)
		);

		if ( isset( $state['status'] ) && 'running' === $state['status'] ) {
			return; // A pass is already in progress; let it finish.
		}

		update_option(
			self::STATE_OPTION,
			array(
				'status'               => 'running',
				'started_at'           => time(),
				'stage'                => 'core',
				'queue'                => array(),
				'core_findings'        => array(),
				'plugin_theme_findings' => array(),
				'upload_findings'      => array(),
			),
			false
		);

		if ( class_exists( 'ADC_Security_Cron_Health' ) ) {
			ADC_Security_Cron_Health::record( self::WEEKLY_HOOK );
		}

		$this->schedule_tick();
	}

	/**
	 * Process one bounded batch of work, then reschedule or finalize.
	 */
	public function run_tick() {
		$state = get_option( self::STATE_OPTION, array() );
		if ( empty( $state ) || 'running' !== ( isset( $state['status'] ) ? $state['status'] : '' ) ) {
			return;
		}

		$deadline = microtime( true ) + self::TIME_BUDGET_SEC;

		if ( 'core' === $state['stage'] ) {
			$state = $this->tick_core_checksums( $state, $deadline );
		} elseif ( 'plugins' === $state['stage'] ) {
			$state = $this->tick_package_checksums( $state, $deadline, 'plugin' );
		} elseif ( 'themes' === $state['stage'] ) {
			$state = $this->tick_package_checksums( $state, $deadline, 'theme' );
		} elseif ( 'uploads' === $state['stage'] ) {
			$state = $this->tick_uploads_scan( $state, $deadline );
		}

		if ( 'done' === $state['stage'] ) {
			$this->finalize( $state );
			return;
		}

		update_option( self::STATE_OPTION, $state, false );
		$this->schedule_tick();
	}

	/**
	 * @param float $when Unix timestamp with microseconds for the next tick.
	 */
	private function schedule_tick() {
		if ( ! wp_next_scheduled( self::TICK_HOOK ) ) {
			wp_schedule_single_event( time() + 60, self::TICK_HOOK );
		}
	}

	// -------------------------------------------------------------------------
	// Stage 1: core checksums
	// -------------------------------------------------------------------------

	/**
	 * @param array $state    Current scan state.
	 * @param float $deadline microtime() budget to stop by.
	 * @return array Updated state.
	 */
	private function tick_core_checksums( array $state, $deadline ) {
		if ( ! function_exists( 'get_core_checksums' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		global $wp_version, $wp_local_package;
		$locale     = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$checksums  = get_core_checksums( $wp_version, $locale );

		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			// Checksums API unreachable; skip straight to the plugins stage.
			$state['stage'] = 'plugins';
			$state['queue'] = array();
			return $state;
		}

		foreach ( $checksums as $relative_path => $expected_md5 ) {
			if ( microtime( true ) > $deadline ) {
				return $state;
			}

			if ( 0 !== strpos( $relative_path, 'wp-admin/' ) && 0 !== strpos( $relative_path, 'wp-includes/' ) ) {
				continue;
			}

			$full_path = ABSPATH . $relative_path;
			if ( ! file_exists( $full_path ) ) {
				$state['core_findings'][] = array(
					'path'   => $relative_path,
					'reason' => 'missing',
				);
				continue;
			}

			if ( md5_file( $full_path ) !== $expected_md5 ) {
				$state['core_findings'][] = array(
					'path'   => $relative_path,
					'reason' => 'modified',
				);
			}

			unset( $checksums[ $relative_path ] );
		}

		if ( empty( $checksums ) ) {
			$state['stage'] = 'plugins';
			$state['queue'] = array();
		}

		return $state;
	}

	// -------------------------------------------------------------------------
	// Stage 2: per-plugin / per-theme checksums
	// -------------------------------------------------------------------------

	/**
	 * @param array  $state    Current scan state.
	 * @param float  $deadline microtime() budget to stop by.
	 * @param string $type     'plugin' or 'theme'.
	 * @return array Updated state.
	 */
	private function tick_package_checksums( array $state, $deadline, $type ) {
		if ( empty( $state['queue'] ) && empty( $state['queue_built'] ) ) {
			$state['queue']       = 'plugin' === $type ? $this->build_plugin_queue() : $this->build_theme_queue();
			$state['queue_built'] = true;
		}

		$processed = 0;
		while ( ! empty( $state['queue'] ) ) {
			if ( microtime( true ) > $deadline || $processed >= self::PACKAGES_PER_TICK ) {
				return $state;
			}

			$item = array_shift( $state['queue'] );
			$this->check_package( $item, $state );
			++$processed;
		}

		$state['stage']       = 'plugin' === $type ? 'themes' : 'uploads';
		$state['queue_built'] = false;
		return $state;
	}

	/**
	 * @return array List of {type, slug, version, dir} for every installed plugin.
	 */
	private function build_plugin_queue() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$queue = array();
		foreach ( get_plugins() as $plugin_file => $data ) {
			if ( false === strpos( $plugin_file, '/' ) ) {
				continue; // Single-file plugin; no reliable checksum path mapping.
			}

			$slug = strtok( $plugin_file, '/' );
			$queue[] = array(
				'type'    => 'plugin',
				'slug'    => $slug,
				'version' => isset( $data['Version'] ) ? $data['Version'] : '',
				'dir'     => trailingslashit( WP_PLUGIN_DIR ) . $slug,
				'label'   => isset( $data['Name'] ) ? $data['Name'] : $slug,
			);
		}
		return $queue;
	}

	/**
	 * @return array List of {type, slug, version, dir} for every installed theme.
	 */
	private function build_theme_queue() {
		$queue = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$queue[] = array(
				'type'    => 'theme',
				'slug'    => $slug,
				'version' => (string) $theme->get( 'Version' ),
				'dir'     => $theme->get_stylesheet_directory(),
				'label'   => (string) $theme->get( 'Name' ),
			);
		}
		return $queue;
	}

	/**
	 * Fetch official checksums for one plugin/theme and compare local files.
	 * Silently skipped (no finding) if the package isn't on WordPress.org or
	 * the checksums API doesn't have data for it — premium/custom code can't
	 * be checked this way.
	 *
	 * @param array $item  {type, slug, version, dir, label}.
	 * @param array $state State array, updated by reference.
	 */
	private function check_package( array $item, array &$state ) {
		if ( '' === $item['version'] || ! is_dir( $item['dir'] ) ) {
			return;
		}

		$checksums = $this->get_package_checksums( $item['type'], $item['slug'], $item['version'] );
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return;
		}

		foreach ( $checksums as $relative_path => $hashes ) {
			$full_path = trailingslashit( $item['dir'] ) . ltrim( $relative_path, '/' );

			// A path can have more than one valid hash (e.g. readme.txt is
			// sometimes rewritten during packaging), so normalize to a list.
			$expected = isset( $hashes['md5'] ) ? (array) $hashes['md5'] : array();
			$expected = array_filter( $expected );
			if ( empty( $expected ) ) {
				continue;
			}

			if ( ! file_exists( $full_path ) ) {
				$state['plugin_theme_findings'][] = array(
					'path'   => $item['type'] . ': ' . $item['label'] . ' — ' . $relative_path,
					'reason' => 'missing',
				);
				continue;
			}

			if ( ! in_array( md5_file( $full_path ), $expected, true ) ) {
				$state['plugin_theme_findings'][] = array(
					'path'   => $item['type'] . ': ' . $item['label'] . ' — ' . $relative_path,
					'reason' => 'modified',
				);
			}
		}
	}

	/**
	 * @param string $type    'plugin' or 'theme'.
	 * @param string $slug    Plugin/theme slug.
	 * @param string $version Installed version.
	 * @return array|null Map of relative path => {md5, sha256}, or null if unavailable.
	 */
	private function get_package_checksums( $type, $slug, $version ) {
		$cache_key = 'adc_cksum_' . $type . '_' . md5( $slug . '|' . $version );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return '' === $cached ? null : $cached;
		}

		$path = 'plugin' === $type ? 'plugin-checksums' : 'theme-checksums';
		$url  = sprintf( 'https://downloads.wordpress.org/%s/%s/%s.json', $path, rawurlencode( $slug ), rawurlencode( $version ) );

		$response = wp_remote_get( $url, array( 'timeout' => 8 ) );
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			set_transient( $cache_key, '', self::CHECKSUM_CACHE_TTL );
			return null;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		$files = isset( $data['files'] ) && is_array( $data['files'] ) ? $data['files'] : null;

		set_transient( $cache_key, null === $files ? '' : $files, self::CHECKSUM_CACHE_TTL );

		return $files;
	}

	// -------------------------------------------------------------------------
	// Stage 3: uploads scan
	// -------------------------------------------------------------------------

	/**
	 * @param array $state    Current scan state.
	 * @param float $deadline microtime() budget to stop by.
	 * @return array Updated state.
	 */
	private function tick_uploads_scan( array $state, $deadline ) {
		if ( empty( $state['queue'] ) && empty( $state['queue_built'] ) ) {
			$state['queue']       = $this->find_php_files_in_uploads();
			$state['queue_built'] = true;
		}

		$processed = 0;
		while ( ! empty( $state['queue'] ) ) {
			if ( microtime( true ) > $deadline || $processed >= self::FILES_PER_TICK ) {
				return $state;
			}

			$path = array_shift( $state['queue'] );
			$this->scan_file_for_suspicious_content( $path, $state );
			++$processed;
		}

		$state['stage'] = 'done';
		return $state;
	}

	/**
	 * @return string[] Absolute paths to .php files under wp-content/uploads.
	 */
	private function find_php_files_in_uploads() {
		$upload_dir = wp_get_upload_dir();
		$base       = isset( $upload_dir['basedir'] ) ? $upload_dir['basedir'] : '';
		if ( '' === $base || ! is_dir( $base ) ) {
			return array();
		}

		$files = array();
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
			foreach ( $iterator as $file ) {
				if ( $file->isFile() && preg_match( '/\.(php|phtml|phar)$/i', $file->getFilename() ) ) {
					$files[] = $file->getPathname();
				}
			}
		} catch ( Exception $e ) {
			return $files;
		}

		return $files;
	}

	/**
	 * @param string $path  Absolute file path.
	 * @param array  $state State array, updated by reference via return value in caller.
	 */
	private function scan_file_for_suspicious_content( $path, array &$state ) {
		$contents = @file_get_contents( $path, false, null, 0, 200000 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $contents ) {
			return;
		}

		foreach ( self::$suspicious_patterns as $pattern ) {
			if ( preg_match( $pattern, $contents ) ) {
				$state['upload_findings'][] = array(
					'path'    => str_replace( ABSPATH, '', $path ),
					'pattern' => $pattern,
				);
				return;
			}
		}
	}

	// -------------------------------------------------------------------------
	// Finalization
	// -------------------------------------------------------------------------

	/**
	 * @param array $state Completed scan state.
	 */
	private function finalize( array $state ) {
		$previous = get_option( self::RESULT_OPTION, array() );

		$result = array(
			'completed_at'          => time(),
			'core_findings'         => $state['core_findings'],
			'plugin_theme_findings' => isset( $state['plugin_theme_findings'] ) ? $state['plugin_theme_findings'] : array(),
			'upload_findings'       => $state['upload_findings'],
		);

		update_option( self::RESULT_OPTION, $result, false );
		update_option( self::STATE_OPTION, array( 'status' => 'idle' ), false );

		$previous_count = ( isset( $previous['core_findings'] ) ? count( $previous['core_findings'] ) : 0 )
			+ ( isset( $previous['plugin_theme_findings'] ) ? count( $previous['plugin_theme_findings'] ) : 0 )
			+ ( isset( $previous['upload_findings'] ) ? count( $previous['upload_findings'] ) : 0 );
		$current_count = count( $result['core_findings'] ) + count( $result['plugin_theme_findings'] ) + count( $result['upload_findings'] );

		if ( $current_count > 0 && $current_count !== $previous_count ) {
			$this->send_alert( $result );
		}

		if ( $current_count > 0 && class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				'integrity_alert',
				ADC_Security_Events::SEVERITY_CRITICAL,
				array( 'context' => array( 'findings' => $current_count ) )
			);
		}
	}

	/**
	 * @param array $result Finalized scan result.
	 */
	private function send_alert( array $result ) {
		$admin_email = get_option( 'admin_email' );
		$count       = count( $result['core_findings'] ) + count( $result['plugin_theme_findings'] ) + count( $result['upload_findings'] );

		$message = sprintf(
			/* translators: %d: number of findings */
			__( 'ADC Security found %d file integrity issue(s) on your site. Review the System & Integrity dashboard card for details.', 'adc-security' ),
			$count
		);

		wp_mail( $admin_email, __( 'ADC Security: file integrity alert', 'adc-security' ), $message );
	}

	/**
	 * @return array Last completed scan result, or an empty shape if none yet.
	 */
	public static function get_last_result() {
		return get_option(
			self::RESULT_OPTION,
			array(
				'completed_at'          => 0,
				'core_findings'         => array(),
				'plugin_theme_findings' => array(),
				'upload_findings'       => array(),
			)
		);
	}

	/**
	 * @return array Current scan state (for the admin UI to show progress).
	 */
	public static function get_scan_state() {
		return get_option( self::STATE_OPTION, array( 'status' => 'idle' ) );
	}
}
