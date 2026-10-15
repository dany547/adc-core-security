<?php
/**
 * ADC Security CSP Admin
 *
 * Renders the Content-Security-Policy controls on the Hardening tab (mode
 * selector, CSP site scanner, blocked-sources list) and handles their
 * admin-post actions.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Csp_Admin {

	/**
	 * Register admin-post handlers for the CSP actions.
	 */
	public function __construct() {
		add_action( 'admin_post_adc_security_csp_allow', array( $this, 'handle_csp_allow_source' ) );
		add_action( 'admin_post_adc_security_csp_clear_reports', array( $this, 'handle_csp_clear_reports' ) );
		add_action( 'admin_post_adc_security_csp_scan', array( $this, 'handle_csp_scan' ) );
		add_action( 'admin_post_adc_security_csp_apply_scan', array( $this, 'handle_csp_apply_scan' ) );
		add_action( 'admin_post_adc_security_csp_clear_scan', array( $this, 'handle_csp_clear_scan' ) );
	}


	/**
	 * Read an array-valued option from a stored options array.
	 *
	 * @param array  $options Stored options.
	 * @param string $key     Option key.
	 * @return array
	 */
	private function get_option_array( $options, $key ) {
		return isset( $options[ $key ] ) && is_array( $options[ $key ] ) ? $options[ $key ] : array();
	}

	/**
	 * Plain-language state of the Content-Security-Policy, for the status line.
	 *
	 * @param array $options Saved options.
	 * @return array{state: string, text: string}
	 */
	private function get_csp_status( $options ) {
		$mode = ADC_Security_Hardening::get_csp_mode( $options );

		if ( 'off' === $mode ) {
			return array( 'state' => 'off', 'text' => 'CSP: off - no policy is sent.' );
		}
		if ( empty( $options['security_headers'] ) ) {
			return array( 'state' => 'not-sent', 'text' => 'CSP: not sent - turn on Enable Security Headers first.' );
		}
		if ( ! empty( $options['csp_report_only'] ) ) {
			return array( 'state' => 'test', 'text' => 'CSP: test mode - nothing is blocked, violations are only recorded (Report-Only).' );
		}
		return array( 'state' => 'active', 'text' => 'CSP: active - the policy below is enforced.' );
	}

	/**
	 * Render the Content-Security-Policy mode selector and its panels.
	 *
	 * Every panel is submitted even when hidden, so the form works without JavaScript.
	 *
	 * @param array $args Field arguments.
	 */
	public function render_csp_field( $args ) {
		$options     = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		$options     = is_array( $options ) ? $options : array();
		$mode        = ADC_Security_Hardening::get_csp_mode( $options );
		$custom      = isset( $options['security_headers_csp'] ) && is_string( $options['security_headers_csp'] ) ? $options['security_headers_csp'] : '';
		$extra       = $this->get_option_array( $options, 'csp_extra_sources' );
		$removed     = $this->get_option_array( $options, 'csp_removed_defaults' );
		$dynamic     = ! empty( $options['csp_dynamic_scripts_compatibility'] );
		// Report-Only is ticked while the mode is Off, so switching to Standard or Custom starts in test mode.
		$report_only = ! empty( $options['csp_report_only'] ) || 'off' === $mode;
		$name        = ADC_Security_Settings::OPTION_NAME . '[csp_mode]';
		$modes       = array(
			'off'      => array( 'Off', 'Do not send a Content-Security-Policy header.' ),
			'standard' => array( 'Standard (recommended)', 'Generated from the services found by the scanner and the sources under Advanced.' ),
			'custom'   => array( 'Custom', 'For experts: you write the whole policy yourself; scanner results are not applied automatically in this mode.' ),
		);
		$directives  = ADC_Security_Csp_Policy::get_directives();
		$defaults    = ADC_Security_Csp_Policy::get_default_sources();
		$warnings    = '' !== trim( $custom ) ? ADC_Security_Csp_Policy::detect_warnings( $custom ) : array();
		$status      = $this->get_csp_status( $options );
		$sent        = ! empty( $options['security_headers'] ) ? ADC_Security_Hardening::get_csp_header( $options, false, '/' ) : null;
		?>
		<p class="adc-csp-status adc-csp-status-<?php echo esc_attr( $status['state'] ); ?>" role="status" aria-live="polite"><?php echo esc_html( $status['text'] ); ?></p>

		<div class="adc-csp-steps-wrap">
			<p class="adc-block-label"><strong>How to roll out a policy</strong></p>
			<ol class="adc-csp-steps">
				<li>Scan your site, tick the services you recognise, then press Allow selected.</li>
				<li>Leave test mode (Report-Only) on for a few days.</li>
				<li>When the Blocked sources list stays empty, untick Report-Only and save.</li>
			</ol>
		</div>

		<fieldset class="adc-csp">
			<legend class="screen-reader-text"><span>Content-Security-Policy mode</span></legend>
			<label class="adc-radio-row">
				<input type="radio" name="<?php echo esc_attr( $name ); ?>" value="off" <?php checked( $mode, 'off' ); ?>>
				<strong><?php echo esc_html( $modes['off'][0] ); ?></strong>
				<span class="description adc-checkbox-description"><?php echo esc_html( $modes['off'][1] ); ?></span>
			</label>
			<label class="adc-radio-row">
				<input type="radio" name="<?php echo esc_attr( $name ); ?>" value="standard" <?php checked( $mode, 'standard' ); ?>>
				<strong><?php echo esc_html( $modes['standard'][0] ); ?></strong>
				<span class="description adc-checkbox-description"><?php echo esc_html( $modes['standard'][1] ); ?></span>
			</label>

			<div class="adc-csp-panel" data-adc-when="csp_mode" data-adc-values="standard">
				<details class="adc-csp-advanced"<?php echo $dynamic ? ' open' : ''; ?>>
					<summary>Advanced: sources per directive and script compatibility</summary>
					<p class="description">Tick <em>Remove</em> to turn off a default source. Add your own domains in the box for a directive, separated by spaces, commas or new lines.</p>
					<?php foreach ( $directives as $directive ) : ?>
						<div class="adc-csp-directive">
							<p class="adc-csp-directive-name"><code><?php echo esc_html( $directive ); ?></code></p>
							<input type="hidden" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_removed_defaults][' . $directive . '][]' ); ?>" value="">
							<?php foreach ( isset( $defaults[ $directive ] ) ? $defaults[ $directive ] : array() as $source ) : ?>
								<label class="adc-checkbox-row adc-csp-source">
									<input type="checkbox" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_removed_defaults][' . $directive . '][]' ); ?>" value="<?php echo esc_attr( $source ); ?>" <?php checked( isset( $removed[ $directive ] ) && in_array( $source, (array) $removed[ $directive ], true ) ); ?>>
									<code><?php echo esc_html( $source ); ?></code> <span class="description">Remove</span>
								</label>
							<?php endforeach; ?>
							<label class="adc-block-label" for="<?php echo esc_attr( 'adc-csp-extra-' . $directive ); ?>">Extra sources</label>
							<textarea id="<?php echo esc_attr( 'adc-csp-extra-' . $directive ); ?>" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_extra_sources][' . $directive . ']' ); ?>" rows="2" class="large-text code"><?php echo esc_textarea( implode( "\n", $this->get_option_array( $extra, $directive ) ) ); ?></textarea>
						</div>
					<?php endforeach; ?>
					<div class="adc-csp-directive adc-csp-compat">
						<p class="adc-csp-directive-name"><strong>Script compatibility</strong></p>
						<input type="hidden" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_dynamic_scripts_compatibility]' ); ?>" value="0">
						<label class="adc-checkbox-row" for="csp_dynamic_scripts_compatibility">
							<input type="checkbox" id="csp_dynamic_scripts_compatibility" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_dynamic_scripts_compatibility]' ); ?>" value="1" <?php checked( $dynamic ); ?>>
							<strong>Allow unsafe-eval on public pages - only if a WooCommerce or theme script stops working (weakens protection)</strong>
							<br><span class="description adc-checkbox-description">Adds <code>unsafe-eval</code> to script sources on frontend pages only. A custom policy below overrides this setting.</span>
						</label>
					</div>
				</details>

				<div class="adc-csp-preview-wrap">
					<p class="adc-block-label"><strong>Preview of your changes (final header is built when you save)</strong></p>
					<pre class="adc-csp-preview" id="adc-csp-preview-live"></pre>
				</div>
			</div>

			<label class="adc-radio-row">
				<input type="radio" name="<?php echo esc_attr( $name ); ?>" value="custom" <?php checked( $mode, 'custom' ); ?>>
				<strong><?php echo esc_html( $modes['custom'][0] ); ?></strong>
				<span class="description adc-checkbox-description"><?php echo esc_html( $modes['custom'][1] ); ?></span>
			</label>

			<div class="adc-csp-panel" data-adc-when="csp_mode" data-adc-values="custom">
				<label class="adc-block-label" for="adc-csp-custom">Your full policy</label>
				<textarea id="adc-csp-custom" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[security_headers_csp]' ); ?>" rows="6" class="large-text code"><?php echo esc_textarea( $custom ); ?></textarea>
				<p class="description">Directives separated by semicolons, for example <code>default-src 'self'; script-src 'self' https://example.com</code>. Sent as written, after removing invalid parts.</p>
				<?php if ( ! empty( $warnings ) ) : ?>
					<ul class="adc-csp-warnings">
						<?php foreach ( $warnings as $warning ) : ?>
							<li><?php echo esc_html( $warning ); ?></li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</div>

			<div class="adc-csp-panel" data-adc-when="csp_mode" data-adc-values="standard custom">
				<input type="hidden" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_report_only]' ); ?>" value="0">
				<label class="adc-checkbox-row">
					<input type="checkbox" name="<?php echo esc_attr( ADC_Security_Settings::OPTION_NAME . '[csp_report_only]' ); ?>" value="1" <?php checked( $report_only ); ?>>
					<strong>Report-Only (test without blocking)</strong>
					<br><span class="description adc-checkbox-description">Browsers report what the policy would block instead of blocking it, and the reports appear in the Blocked sources list above. Use this after scanning, on any new policy, then turn it off once the list is clean.</span>
				</label>
			</div>
		</fieldset>

		<div class="adc-csp-sent">
			<p class="adc-block-label"><strong>Header sent right now</strong></p>
			<?php if ( null !== $sent ) : ?>
				<pre class="adc-csp-preview"><?php echo esc_html( $sent['name'] . ': ' . $sent['value'] ); ?></pre>
			<?php else : ?>
				<p class="description">No Content-Security-Policy header is sent right now.</p>
			<?php endif; ?>
		</div>
		<p class="description"><?php echo wp_kses_post( $args['description'] ); ?></p>
		<?php
	}

	/**
	 * Render the "Blocked for your visitors" sub-section of the scanner panel and its Allow / Clear actions.
	 *
	 * Rendered outside the options form because each button posts on its own.
	 */
	private function render_csp_blocked_section() {
		$core    = ADC_Security_Core::instance();
		$reports = isset( $core->csp_reports ) && $core->csp_reports instanceof ADC_Security_Csp_Reports ? $core->csp_reports : null;
		$rows    = $reports ? $reports->get_blocked_summary( 50 ) : array();
		$action  = esc_url( admin_url( 'admin-post.php' ) );
		?>
		<div class="adc-csp-blocked" id="adc-csp-blocked">
			<h3 id="adc-csp-blocked-title">Blocked for your visitors (test mode)</h3>
			<p class="description">Sources that visitors' browsers reported in the last 30 days. Allowing a source adds it to that directive and saves the setting. Check each source first: an unexpected host can be a sign of injected script.</p>
			<?php if ( empty( $rows ) ) : ?>
				<p class="adc-csp-empty">Nothing blocked yet.</p>
			<?php else : ?>
				<table class="widefat striped adc-status-table adc-csp-table" aria-labelledby="adc-csp-blocked-title">
					<thead>
						<tr>
							<th scope="col">Directive</th>
							<th scope="col">Source</th>
							<th scope="col">Reports</th>
							<th scope="col">Last seen (UTC)</th>
							<th scope="col"><span class="screen-reader-text">Action</span></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<tr>
								<td><code><?php echo esc_html( $row['directive'] ); ?></code></td>
								<td><code><?php echo esc_html( $row['host'] ); ?></code></td>
								<td><?php echo esc_html( number_format_i18n( (int) $row['count'] ) ); ?></td>
								<td><?php echo esc_html( $row['last_seen'] ); ?></td>
								<td>
									<?php if ( '' !== $row['suggested_source'] ) : ?>
										<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-inline">
											<?php wp_nonce_field( 'adc_security_csp_allow', 'adc_security_csp_nonce' ); ?>
											<input type="hidden" name="action" value="adc_security_csp_allow">
											<input type="hidden" name="directive" value="<?php echo esc_attr( $row['directive'] ); ?>">
											<input type="hidden" name="source" value="<?php echo esc_attr( $row['suggested_source'] ); ?>">
											<button type="submit" class="button button-secondary">Allow <code><?php echo esc_html( $row['suggested_source'] ); ?></code></button>
										</form>
									<?php endif; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>
			<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-mb-10">
				<?php wp_nonce_field( 'adc_security_csp_clear_reports', 'adc_security_csp_clear_nonce' ); ?>
				<input type="hidden" name="action" value="adc_security_csp_clear_reports">
				<button type="submit" class="button button-link-delete" <?php echo empty( $rows ) ? 'disabled' : ''; ?>>Clear blocked-source list</button>
			</form>
		</div>
		<?php
	}

	/**
	 * Add a blocked source to a CSP directive (admin-post, nonce and capability checked).
	 */
	public function handle_csp_allow_source() {
		check_admin_referer( 'adc_security_csp_allow', 'adc_security_csp_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		$directive = isset( $_POST['directive'] ) && is_string( $_POST['directive'] ) ? sanitize_text_field( wp_unslash( $_POST['directive'] ) ) : '';
		$source    = isset( $_POST['source'] ) && is_string( $_POST['source'] ) ? sanitize_text_field( wp_unslash( $_POST['source'] ) ) : '';
		$clean     = ADC_Security_Csp_Policy::sanitize_source( $source );

		if ( in_array( $directive, ADC_Security_Csp_Policy::get_directives(), true ) && '' !== $clean ) {
			$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );
			if ( ! is_array( $options ) ) {
				$options = array();
			}
			list( $options ) = $this->add_csp_extra_source( $options, $directive, $clean );
			update_option( ADC_Security_Settings::OPTION_NAME, $options );

			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_allowed', esc_html( 'Allowed ' . $clean . ' for ' . $directive . '. Reports for it will stop once the new policy is in use.' ), 'updated' );
		} else {
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_allow_failed', esc_html__( 'That source could not be allowed.', 'adc-security' ), 'error' );
		}

		$this->redirect_csp_notice();
	}

	/**
	 * Clear the aggregated blocked-source list (admin-post, nonce and capability checked).
	 */
	public function handle_csp_clear_reports() {
		check_admin_referer( 'adc_security_csp_clear_reports', 'adc_security_csp_clear_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		$core = ADC_Security_Core::instance();
		if ( isset( $core->csp_reports ) && $core->csp_reports instanceof ADC_Security_Csp_Reports ) {
			$core->csp_reports->clear();
		}

		add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_cleared', 'Blocked-source list cleared.', 'updated' );
		$this->redirect_csp_notice();
	}

	/**
	 * Return to the Hardening tab and show the queued settings errors, the same way options.php does.
	 */
	private function redirect_csp_notice() {
		set_transient( 'settings_errors', get_settings_errors(), 30 );
		wp_safe_redirect( add_query_arg(
			array(
				'page'             => 'adc-security',
				'tab'              => 'hardening',
				'settings-updated' => 'true',
			),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	/**
	 * Add one source to a directive in csp_extra_sources.
	 *
	 * @param array  $options   Plugin options.
	 * @param string $directive Validated directive name.
	 * @param string $source    Sanitised source.
	 * @return array Array of [ updated options, whether the source was new ].
	 */
	private function add_csp_extra_source( array $options, $directive, $source ) {
		$all   = $this->get_option_array( $options, 'csp_extra_sources' );
		$extra = $this->get_option_array( $all, $directive );
		if ( in_array( $source, $extra, true ) || count( $extra ) >= 50 ) {
			return array( $options, false );
		}
		$extra[]                      = $source;
		$all[ $directive ]            = array_values( $extra );
		$options['csp_extra_sources'] = $all;
		return array( $options, true );
	}

	/**
	 * Plain-language labels for the directives the scanner can report.
	 *
	 * @return array<string, string>
	 */
	private function get_csp_directive_labels() {
		return array(
			'script-src'   => 'Scripts',
			'style-src'    => 'Stylesheets',
			'img-src'      => 'Images',
			'font-src'     => 'Fonts',
			'connect-src'  => 'Network requests (AJAX, analytics)',
			'frame-src'    => 'Embedded frames (maps, videos)',
			'media-src'    => 'Audio and video',
			'worker-src'   => 'Background workers',
			'manifest-src' => 'Web app manifests',
			'default-src'  => 'Everything else (default)',
			'object-src'   => 'Plugins (object, embed)',
			'form-action'  => 'Form submissions',
		);
	}

	/**
	 * Server-side guard: plain http origins are refused unless the host is local.
	 *
	 * @param string $source Sanitised source.
	 * @return bool
	 */
	private function is_csp_source_acceptable( $source ) {
		if ( 0 !== stripos( $source, 'http://' ) ) {
			return true;
		}
		$host = strtolower( (string) wp_parse_url( $source, PHP_URL_HOST ) );
		return in_array( $host, array( 'localhost', '127.0.0.1', '[::1]', '::1' ), true ) || 1 === preg_match( '/\.localhost$/', $host );
	}

	/**
	 * Run the site scan (admin-post, nonce and capability checked).
	 */
	public function handle_csp_scan() {
		check_admin_referer( 'adc_security_csp_scan', 'adc_security_csp_scan_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		if ( ! class_exists( 'ADC_Security_Csp_Scanner' ) ) {
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_scan_failed', esc_html__( 'The CSP scanner is not available.', 'adc-security' ), 'error' );
			$this->redirect_csp_notice();
		}

		// Other pages: one per line, same site only, up to MAX_EXTRA_URLS. Rejected lines are named in the notice.
		$raw        = isset( $_POST['adc_csp_scan_extra'] ) && is_string( $_POST['adc_csp_scan_extra'] ) ? wp_unslash( $_POST['adc_csp_scan_extra'] ) : '';
		$home       = home_url( '/' );
		$max        = (int) ADC_Security_Csp_Scanner::MAX_EXTRA_URLS;
		$extra_urls = array();
		$rejected   = array();

		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( $line );
			if ( '' === $line ) {
				continue;
			}
			$url = count( $extra_urls ) < $max ? ADC_Security_Csp_Scanner::normalize_extra_url( $line, $home ) : '';
			if ( '' === $url ) {
				$name       = sanitize_text_field( $line );
				$rejected[] = function_exists( 'mb_substr' ) ? mb_substr( $name, 0, 80 ) : substr( $name, 0, 80 );
				continue;
			}
			$extra_urls[] = $url;
		}

		$result = ( new ADC_Security_Csp_Scanner() )->scan( $extra_urls );

		if ( is_wp_error( $result ) ) {
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_scan_failed', esc_html( $result->get_error_message() ), 'error' );
		} else {
			$found    = isset( $result['found'] ) && is_array( $result['found'] ) ? $result['found'] : array();
			$services = count( array_unique( array_column( $found, 'source' ) ) );
			$pages    = isset( $result['urls'] ) && is_array( $result['urls'] ) ? count( $result['urls'] ) : 0;
			$message  = sprintf( 'Scan finished: %d services found on %d pages', $services, $pages );
			if ( ! empty( $rejected ) ) {
				$message .= sprintf( '. Not scanned (extra pages must be on this site, up to %d): %s', $max, implode( ', ', $rejected ) );
			}
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_scanned', esc_html( $message ), 'updated' );
		}

		$this->redirect_csp_notice();
	}

	/**
	 * Allow the sources ticked in the scan results (admin-post, nonce and capability checked).
	 */
	public function handle_csp_apply_scan() {
		check_admin_referer( 'adc_security_csp_apply_scan', 'adc_security_csp_apply_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		$posted     = isset( $_POST['adc_csp_allow'] ) && is_array( $_POST['adc_csp_allow'] ) ? wp_unslash( $_POST['adc_csp_allow'] ) : array();
		$directives = ADC_Security_Csp_Policy::get_directives();
		$options    = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		$options    = is_array( $options ) ? $options : array();
		$added      = 0;
		$skipped    = 0;
		$selected   = 0;

		foreach ( $posted as $directive => $sources ) {
			$directive = sanitize_text_field( (string) $directive );
			if ( ! in_array( $directive, $directives, true ) || ! is_array( $sources ) ) {
				// form-action and object-src are fixed by the plugin and are never accepted here.
				$skipped += is_array( $sources ) ? count( $sources ) : 1;
				continue;
			}
			foreach ( $sources as $raw ) {
				$selected++;
				$clean = is_string( $raw ) ? ADC_Security_Csp_Policy::sanitize_source( sanitize_text_field( $raw ) ) : '';
				if ( '' === $clean || ! $this->is_csp_source_acceptable( $clean ) ) {
					$skipped++;
					continue;
				}
				list( $options, $was_added ) = $this->add_csp_extra_source( $options, $directive, $clean );
				if ( $was_added ) {
					$added++;
				}
			}
		}

		if ( 0 === $selected ) {
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_apply_none', esc_html__( 'No sources were selected.', 'adc-security' ), 'error' );
		} else {
			if ( $added > 0 ) {
				update_option( ADC_Security_Settings::OPTION_NAME, $options );
			}
			$message = $added > 0 ? sprintf( '%d sources added', $added ) : 'No new sources were added.';
			if ( $skipped > 0 ) {
				$message .= sprintf( ' %d skipped: not valid, not allowed on this site, or fixed by the plugin.', $skipped );
			}
			add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_applied', esc_html( $message ), 'updated' );
		}

		$this->redirect_csp_notice();
	}

	/**
	 * Forget the last scan result (admin-post, nonce and capability checked).
	 */
	public function handle_csp_clear_scan() {
		check_admin_referer( 'adc_security_csp_clear_scan', 'adc_security_csp_clear_scan_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		if ( class_exists( 'ADC_Security_Csp_Scanner' ) ) {
			ADC_Security_Csp_Scanner::clear();
		}

		add_settings_error( ADC_Security_Settings::OPTION_NAME, 'adc_security_csp_scan_cleared', esc_html__( 'Scan results cleared.', 'adc-security' ), 'updated' );
		$this->redirect_csp_notice();
	}

	/**
	 * Render the CSP site scanner: a scan form, the results grouped by directive, and the blocked sources.
	 *
	 * Shown only when Content-Security-Policy is not Off. Rendered outside the options form because
	 * its buttons post on their own.
	 */
	public function render_csp_scanner_panel() {
		$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		$options = is_array( $options ) ? $options : array();
		$mode    = ADC_Security_Hardening::get_csp_mode( $options );

		if ( 'off' === $mode ) {
			?>
			<div class="adc-admin-panel adc-csp-scanner-off">
				<p>Turn on Content-Security-Policy (Standard mode) and save; the site scanner appears here.</p>
			</div>
			<?php
			return;
		}

		$extra     = $this->get_option_array( $options, 'csp_extra_sources' );
		$status    = $this->get_csp_status( $options );
		$headers   = ! empty( $options['security_headers'] );
		$ready     = class_exists( 'ADC_Security_Csp_Scanner' );
		$last      = $ready ? ADC_Security_Csp_Scanner::get_last_scan() : array();
		$has_scan  = ! empty( $last['time'] );
		$action    = esc_url( admin_url( 'admin-post.php' ) );
		$urls      = $has_scan && ! empty( $last['urls'] ) && is_array( $last['urls'] ) ? $last['urls'] : array();
		$errors    = $has_scan && ! empty( $last['errors'] ) && is_array( $last['errors'] ) ? $last['errors'] : array();
		$existing  = $has_scan && isset( $last['existing_csp'] ) && is_string( $last['existing_csp'] ) ? trim( $last['existing_csp'] ) : '';
		$found     = $has_scan && ! empty( $last['found'] ) && is_array( $last['found'] ) ? ADC_Security_Csp_Scanner::mark_allowed( $last['found'], $extra ) : array();
		$hints     = ! empty( $found ) ? ADC_Security_Csp_Scanner::companion_hints( $found ) : array();
		$home_host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$labels    = $this->get_csp_directive_labels();
		$fixed     = array( 'form-action', 'object-src' );
		$index     = 0;

		$groups = array();
		foreach ( $found as $row ) {
			$groups[ $row['directive'] ][] = $row;
		}
		$ordered = array();
		foreach ( array_keys( $labels ) as $directive ) {
			if ( isset( $groups[ $directive ] ) ) {
				$ordered[ $directive ] = $groups[ $directive ];
			}
		}
		foreach ( $groups as $directive => $rows ) {
			if ( ! isset( $ordered[ $directive ] ) ) {
				$ordered[ $directive ] = $rows;
			}
		}
		?>
		<div class="adc-admin-panel adc-csp-scanner" id="adc-csp-scanner">
			<h2 class="adc-no-top-margin" id="adc-csp-scanner-title">CSP site scanner</h2>
			<p class="adc-csp-status adc-csp-status-<?php echo esc_attr( $status['state'] ); ?>" role="status" aria-live="polite"><?php echo esc_html( $status['text'] ); ?></p>
			<p class="description">Scans the public pages of your site as a visitor and lists every outside service they load, so you can choose which ones your Content-Security-Policy should allow. It cannot see resources that a script loads later (for example Google Tag Manager loading other scripts) - use Report-Only mode and the Blocked for your visitors list below for those.</p>

			<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-csp-scan-form">
				<?php wp_nonce_field( 'adc_security_csp_scan', 'adc_security_csp_scan_nonce' ); ?>
				<input type="hidden" name="action" value="adc_security_csp_scan">
				<p>
					<label class="adc-block-label" for="adc-csp-scan-extra">Other pages to check (optional)</label>
					<textarea id="adc-csp-scan-extra" name="adc_csp_scan_extra" rows="3" class="large-text code" placeholder="/contact/" aria-describedby="adc-csp-scan-extra-help"></textarea>
					<span class="description" id="adc-csp-scan-extra-help">Type the page address, for example /contact/ or /shop/. One per line, up to 3. The site address is added for you.</span>
				</p>
				<p><button type="submit" class="button button-primary" <?php disabled( ! $ready ); ?>>Scan my site</button></p>
			</form>

			<?php if ( ! $has_scan ) : ?>
				<p>No scan has run yet. Scan your site to see which outside services it loads.</p>
			<?php else : ?>
				<div class="adc-csp-scan-results">
					<p><strong>Your site:</strong> <code><?php echo esc_html( $home_host ); ?></code> <span class="description">Hosts on this domain count as your own. Everything else is an outside service.</span></p>
					<p><strong>Last scan:</strong> <time datetime="<?php echo esc_attr( gmdate( 'c', (int) $last['time'] ) ); ?>"><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), (int) $last['time'] ) ); ?></time></p>

					<details class="adc-csp-pages">
						<summary>Pages scanned (<?php echo esc_html( number_format_i18n( count( $urls ) ) ); ?>)</summary>
						<ul>
							<?php foreach ( $urls as $url ) : ?>
								<li><code><?php echo esc_html( $url ); ?></code></li>
							<?php endforeach; ?>
						</ul>
					</details>

					<?php if ( ! empty( $errors ) ) : ?>
						<details class="adc-csp-errors">
							<summary><?php echo esc_html( sprintf( _n( '%d page could not be scanned', '%d pages could not be scanned', count( $errors ), 'adc-security' ), count( $errors ) ) ); ?></summary>
							<ul>
								<?php foreach ( $errors as $url => $message ) : ?>
									<li><code><?php echo esc_html( (string) $url ); ?></code>: <?php echo esc_html( (string) $message ); ?></li>
								<?php endforeach; ?>
							</ul>
						</details>
					<?php endif; ?>

					<?php if ( '' !== $existing ) : ?>
						<div class="adc-csp-existing notice notice-info inline">
							<p>This site already sends a Content-Security-Policy header from a server setting, another plugin or your theme. Browsers apply every policy they receive, so the scan may not show the whole picture.</p>
							<details>
								<summary>Show the existing header</summary>
								<pre class="adc-csp-preview"><?php echo esc_html( $existing ); ?></pre>
							</details>
						</div>
					<?php endif; ?>

					<?php if ( empty( $found ) ) : ?>
						<p>No outside services were found on the scanned pages.</p>
					<?php else : ?>
						<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-csp-apply-form" id="adc-csp-apply-form">
							<?php wp_nonce_field( 'adc_security_csp_apply_scan', 'adc_security_csp_apply_nonce' ); ?>
							<input type="hidden" name="action" value="adc_security_csp_apply_scan">

							<?php if ( ! $headers ) : ?>
								<div class="adc-csp-mode-note">
									<p><strong>Not in use yet.</strong> Allowed sources are saved, but no policy is sent until you turn on Enable Security Headers and save.</p>
								</div>
							<?php elseif ( 'standard' !== $mode ) : ?>
								<div class="adc-csp-mode-note">
									<p><strong>Not in use right now.</strong> Your Content-Security-Policy mode is <strong><?php echo esc_html( ucfirst( $mode ) ); ?></strong>, so allowed sources do not change the policy. Choose Standard in the Content-Security-Policy section and save to use them.</p>
								</div>
							<?php else : ?>
								<p class="description">Allowed sources are saved straight away and used in the policy.</p>
							<?php endif; ?>

							<p class="adc-csp-select-row" hidden>
								<button type="button" class="button-link adc-csp-select" data-adc-select="all">Select all</button>
								&middot;
								<button type="button" class="button-link adc-csp-select" data-adc-select="none">Select none</button>
							</p>

							<?php foreach ( $ordered as $directive => $rows ) :
								$dir_id = 'adc-csp-dir-' . sanitize_html_class( $directive );
								$label  = isset( $labels[ $directive ] ) ? $labels[ $directive ] : $directive;
								if ( in_array( $directive, $fixed, true ) ) :
									?>
									<h3 id="<?php echo esc_attr( $dir_id ); ?>"><?php echo esc_html( $label ); ?> <code><?php echo esc_html( $directive ); ?></code></h3>
									<p class="description">Set by the plugin and not changed here.</p>
									<?php
									continue;
								endif;

								$third = array();
								$first = array();
								foreach ( $rows as $row ) {
									if ( isset( $row['party'] ) && 'first_sub' === $row['party'] ) {
										$first[] = $row;
									} else {
										$third[] = $row;
									}
								}
								?>
								<h3 id="<?php echo esc_attr( $dir_id ); ?>"><?php echo esc_html( $label ); ?> <code><?php echo esc_html( $directive ); ?></code></h3>
								<?php if ( ! empty( $third ) ) : ?>
									<?php $this->render_csp_scan_table( $third, $directive, __( 'Outside services', 'adc-security' ), $index, $dir_id . '-third' ); ?>
								<?php endif; ?>
								<?php if ( ! empty( $first ) ) : ?>
									<h4 id="<?php echo esc_attr( $dir_id . '-first' ); ?>">Your own subdomains</h4>
									<p class="description">Hosts on your own domain. Allow the exact host shown, never a wildcard, and only if you recognise it.</p>
									<?php $this->render_csp_scan_table( $first, $directive, __( 'Your own subdomains', 'adc-security' ), $index, $dir_id . '-first-table' ); ?>
								<?php endif; ?>
							<?php endforeach; ?>

							<?php if ( ! empty( $hints ) ) : ?>
								<div class="adc-csp-companions">
									<h3>Services detected on your site</h3>
									<?php foreach ( $hints as $hint ) :
										$missing = isset( $hint['missing'] ) && is_array( $hint['missing'] ) ? $hint['missing'] : array();
										$open    = array();
										foreach ( $missing as $dir => $origins ) {
											$current = $this->get_option_array( $extra, $dir );
											foreach ( (array) $origins as $origin ) {
												if ( ! in_array( $origin, $current, true ) ) {
													$open[ $dir ][] = $origin;
												}
											}
										}
										if ( empty( $open ) ) {
											continue;
										}
										?>
										<div class="adc-csp-companion">
											<h4><?php echo esc_html( isset( $hint['label'] ) ? $hint['label'] : '' ); ?></h4>
											<?php if ( ! empty( $hint['detected'] ) && is_array( $hint['detected'] ) ) : ?>
												<p class="description">Detected: <?php echo esc_html( implode( ', ', $hint['detected'] ) ); ?></p>
											<?php endif; ?>
											<p class="description">Often needed as well, but loaded later by scripts and therefore not visible in the page HTML.</p>
											<?php foreach ( $open as $dir => $origins ) : ?>
												<?php foreach ( $origins as $origin ) : $index++; ?>
													<label class="adc-checkbox-row" for="<?php echo esc_attr( 'adc-csp-companion-' . $index ); ?>">
														<input type="checkbox" id="<?php echo esc_attr( 'adc-csp-companion-' . $index ); ?>" name="adc_csp_allow[<?php echo esc_attr( $dir ); ?>][]" value="<?php echo esc_attr( $origin ); ?>">
														<code><?php echo esc_html( $origin ); ?></code> <span class="description">for <?php echo esc_html( $dir ); ?></span>
													</label>
												<?php endforeach; ?>
											<?php endforeach; ?>
										</div>
									<?php endforeach; ?>
								</div>
							<?php endif; ?>

							<p class="description">Good practice: allow only the services you recognise and need, use Report-Only first to see what breaks, and never add a service you do not use. Each source you allow widens what scripts on your site may load.</p>
							<p><button type="submit" class="button button-primary">Allow selected</button></p>
						</form>
					<?php endif; ?>
				</div>

				<form method="post" action="<?php echo $action; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-mb-10">
					<?php wp_nonce_field( 'adc_security_csp_clear_scan', 'adc_security_csp_clear_scan_nonce' ); ?>
					<input type="hidden" name="action" value="adc_security_csp_clear_scan">
					<button type="submit" class="button button-link-delete">Clear scan results</button>
				</form>
			<?php endif; ?>

			<?php $this->render_csp_blocked_section(); ?>
		</div>
		<?php
	}

	/**
	 * Render one table of scanned sources for a directive.
	 *
	 * @param array  $rows    Scan rows for this directive and party.
	 * @param string $directive Directive name.
	 * @param string $caption   Screen-reader caption.
	 * @param int    $index     Running checkbox counter (by reference).
	 * @param string $table_id  Id used for the table's accessible name.
	 */
	private function render_csp_scan_table( array $rows, $directive, $caption, &$index, $table_id ) {
		?>
		<table class="widefat striped adc-status-table adc-csp-table" aria-labelledby="<?php echo esc_attr( $table_id ); ?>">
			<caption class="screen-reader-text" id="<?php echo esc_attr( $table_id ); ?>"><?php echo esc_html( $caption ); ?></caption>
			<thead>
				<tr>
					<th scope="col"><span class="screen-reader-text">Allow</span></th>
					<th scope="col">Source</th>
					<th scope="col">Found in</th>
					<th scope="col">Seen on</th>
				</tr>
			</thead>
			<tbody>
				<?php foreach ( $rows as $row ) :
					$index++;
					$source     = (string) $row['source'];
					$allowed    = ! empty( $row['allowed'] );
					$notes      = isset( $row['notes'] ) && is_array( $row['notes'] ) ? $row['notes'] : array();
					$insecure   = in_array( 'insecure_http', $notes, true );
					$ip_host    = in_array( 'ip_host', $notes, true );
					$inferred   = ! empty( $row['inferred'] ) || in_array( 'inferred', $notes, true );
					$pages      = isset( $row['pages'] ) && is_array( $row['pages'] ) ? $row['pages'] : array();
					$count      = isset( $row['count'] ) ? (int) $row['count'] : count( $pages );
					$party_own  = isset( $row['party'] ) && 'first_sub' === $row['party'];
					$recommend  = $party_own && $count >= 2 && ! $allowed && ! $insecure;
					$cb_id      = 'adc-csp-src-' . $index;
					?>
					<tr>
						<td>
							<input type="checkbox" id="<?php echo esc_attr( $cb_id ); ?>" name="adc_csp_allow[<?php echo esc_attr( $directive ); ?>][]" value="<?php echo esc_attr( $source ); ?>" <?php checked( $allowed ); ?> <?php disabled( $allowed || $insecure ); ?>>
							<label for="<?php echo esc_attr( $cb_id ); ?>" class="screen-reader-text">Allow <?php echo esc_html( $source ); ?> for <?php echo esc_html( $directive ); ?></label>
						</td>
						<td>
							<code><?php echo esc_html( $source ); ?></code>
							<?php if ( $allowed ) : ?>
								<br><span class="adc-csp-allowed">Already allowed</span>
							<?php endif; ?>
							<?php if ( $insecure ) : ?>
								<br><span class="adc-csp-badge adc-csp-badge-warn">Loaded over http - fix the page or allow only https</span>
							<?php endif; ?>
							<?php if ( $ip_host ) : ?>
								<br><span class="adc-csp-badge adc-csp-badge-caution">Caution: loaded from an IP address</span>
							<?php endif; ?>
							<?php if ( $recommend ) : ?>
								<br><span class="adc-csp-badge adc-csp-badge-ok">Recommended: found on several pages</span>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( isset( $row['tag'] ) && '' !== (string) $row['tag'] ) : ?>
								<code><?php echo esc_html( (string) $row['tag'] ); ?></code>
							<?php endif; ?>
							<?php if ( $inferred ) : ?>
								<br><span class="adc-csp-badge">guessed from inline script</span>
							<?php endif; ?>
						</td>
						<td>
							<?php echo esc_html( sprintf( _n( '%d page', '%d pages', $count, 'adc-security' ), $count ) ); ?>
							<?php if ( ! empty( $pages ) ) : ?>
								<details class="adc-csp-pages-seen">
									<summary>Show pages</summary>
									<ul>
										<?php foreach ( $pages as $page ) : ?>
											<li><code><?php echo esc_html( (string) $page ); ?></code></li>
										<?php endforeach; ?>
									</ul>
								</details>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Turn a textarea of sources (spaces, commas or newlines) into a clean list.
	 *
	 * @param string $raw Raw textarea value.
	 * @return string[]
	 */
	public static function sanitize_csp_source_list( $raw ) {
		$valid = array();
		foreach ( preg_split( '/[\s,]+/', (string) $raw, -1, PREG_SPLIT_NO_EMPTY ) as $token ) {
			$source = ADC_Security_Csp_Policy::sanitize_source( $token );
			if ( '' !== $source && ! in_array( $source, $valid, true ) ) {
				$valid[] = $source;
			}
			if ( count( $valid ) >= 50 ) {
				break;
			}
		}
		return $valid;
	}
}
