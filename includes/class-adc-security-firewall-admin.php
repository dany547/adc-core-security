<?php
/**
 * ADC Security Firewall Admin
 *
 * Renders the Firewall tab (at-a-glance summary, rule status, mode, per-rule
 * choices, recent matches) and handles its two admin-post actions.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Firewall_Admin {

	/**
	 * General rules whose decision depends on the visitor IP address.
	 * Their Log only mode is forced while the visitor IP cannot be trusted.
	 */
	const IP_BASED_RULES = array( 'limit_anonymous_search' );

	/**
	 * Register admin-post handlers.
	 */
	public static function init() {
		add_action( 'admin_post_adc_security_firewall_save', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_adc_security_firewall_allow', array( __CLASS__, 'handle_allow' ) );
	}

	/**
	 * Save the global switch, mode and per-rule choices.
	 */
	public static function handle_save() {
		check_admin_referer( 'adc_security_firewall_save', 'adc_security_firewall_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		$current = ADC_Security_Firewall_Rules::get_options();
		$new     = is_array( $current ) ? $current : array();

		$new['enabled'] = ! empty( $_POST['enabled'] ) ? 1 : 0;

		$mode = isset( $_POST['mode'] ) && is_string( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'monitor';
		$new['mode'] = in_array( $mode, array( 'enforce', 'monitor' ), true ) ? $mode : 'monitor';

		$posted_rules = isset( $_POST['rules'] ) && is_array( $_POST['rules'] ) ? wp_unslash( $_POST['rules'] ) : array();
		$rules        = isset( $new['rules'] ) && is_array( $new['rules'] ) ? $new['rules'] : array();

		// Validated against every registry rule, CVE and general alike.
		foreach ( array_keys( ADC_Security_Firewall_Registry::all() ) as $rule_id ) {
			// Disabled selects (not_needed rules) are not posted, so their stored value is kept.
			if ( ! isset( $posted_rules[ $rule_id ] ) || ! is_string( $posted_rules[ $rule_id ] ) ) {
				if ( ! isset( $rules[ $rule_id ] ) ) {
					$rules[ $rule_id ] = 'off';
				}
				continue;
			}
			$value               = sanitize_key( $posted_rules[ $rule_id ] );
			$rules[ $rule_id ]   = in_array( $value, array( 'off', 'on', 'monitor' ), true ) ? $value : 'off';
		}
		$new['rules'] = $rules;

		// allowlist_patterns and safe_mode are preserved from the current options.
		update_option( ADC_Security_Firewall_Rules::OPTION_NAME, $new );

		add_settings_error(
			ADC_Security_Firewall_Rules::OPTION_NAME,
			'adc_security_firewall_saved',
			esc_html__( 'Firewall settings saved.', 'adc-security' ),
			'updated'
		);

		self::redirect_notice();
	}

	/**
	 * Allow one recent match's fingerprint (admin-post, nonce and capability checked).
	 */
	public static function handle_allow() {
		check_admin_referer( 'adc_security_firewall_allow', 'adc_security_firewall_allow_nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to perform this action.', 'adc-security' ) );
		}

		$fingerprint = isset( $_POST['fingerprint'] ) && is_string( $_POST['fingerprint'] ) ? sanitize_text_field( wp_unslash( $_POST['fingerprint'] ) ) : '';

		if ( preg_match( '/^[a-f0-9]{16}$/', $fingerprint ) && ADC_Security_Firewall_Rules::allow_fingerprint( $fingerprint ) ) {
			add_settings_error(
				ADC_Security_Firewall_Rules::OPTION_NAME,
				'adc_security_firewall_allowed',
				esc_html__( 'This pattern will no longer be blocked. Matches are still recorded in the list below.', 'adc-security' ),
				'updated'
			);
		} else {
			add_settings_error(
				ADC_Security_Firewall_Rules::OPTION_NAME,
				'adc_security_firewall_allow_failed',
				esc_html__( 'That pattern could not be allowed.', 'adc-security' ),
				'error'
			);
		}

		self::redirect_notice();
	}

	/**
	 * Return to the Firewall tab and show queued notices, the same way options.php does.
	 */
	private static function redirect_notice() {
		set_transient( 'settings_errors', get_settings_errors(), 30 );
		wp_safe_redirect( add_query_arg(
			array(
				'page'             => 'adc-security',
				'tab'              => 'firewall',
				'settings-updated' => 'true',
			),
			admin_url( 'admin.php' )
		) );
		exit;
	}

	/**
	 * Render the whole Firewall tab.
	 */
	public static function render_tab() {
		$options    = ADC_Security_Firewall_Rules::get_options();
		$options    = is_array( $options ) ? $options : array();
		$enabled    = ! empty( $options['enabled'] );
		$mode       = isset( $options['mode'] ) && 'enforce' === $options['mode'] ? 'enforce' : 'monitor';
		$stored     = isset( $options['rules'] ) && is_array( $options['rules'] ) ? $options['rules'] : array();
		$wp_version = get_bloginfo( 'version' );
		$rules      = ADC_Security_Firewall_Registry::all();
		$counts     = ADC_Security_Firewall_Rules::get_block_counts_7d();
		$counts     = is_array( $counts ) ? $counts : array();
		$matches    = ADC_Security_Firewall_Rules::get_recent_matches( 20 );
		$matches    = is_array( $matches ) ? $matches : array();
		$action_url = esc_url( admin_url( 'admin-post.php' ) );
		$reliable   = ADC_Security_Ip::is_client_ip_reliable();

		$active_count     = 0;
		$not_needed_count = 0;
		$statuses         = array();
		$cve_rules        = array();
		$generic_rules    = array();
		foreach ( $rules as $rule_id => $rule ) {
			$status               = ADC_Security_Firewall_Rules::get_effective_status( $rule_id );
			$statuses[ $rule_id ] = $status;
			$state                = isset( $status['state'] ) ? $status['state'] : 'disabled';
			if ( 'active' === $state || 'monitor' === $state ) {
				++$active_count;
			} elseif ( 'not_needed' === $state ) {
				++$not_needed_count;
			}
			if ( self::is_generic_rule( $rule ) ) {
				$generic_rules[ $rule_id ] = $rule;
			} else {
				$cve_rules[ $rule_id ] = $rule;
			}
		}
		?>
		<?php self::render_at_a_glance( $options, $rules ); ?>

		<div class="adc-admin-panel adc-fw adc-fw-matches">
			<h2 class="adc-no-top-margin">Recent matches</h2>
			<p class="description">The last 20 requests that matched a rule. If a match is legitimate for your site, you can allow that pattern; it will no longer be blocked.</p>
			<?php if ( empty( $matches ) ) : ?>
				<p>No matches yet. This is normal on a healthy site.</p>
			<?php else : ?>
				<div class="adc-fw-table-wrap">
					<table class="widefat striped adc-fw-table">
						<thead>
							<tr>
								<th scope="col">Time</th>
								<th scope="col">Rule</th>
								<th scope="col">Mode</th>
								<th scope="col">IP address</th>
								<th scope="col">Where</th>
								<th scope="col">Detail</th>
								<th scope="col"><span class="screen-reader-text">Action</span></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $matches as $row ) : ?>
								<?php
								$fingerprint = isset( $row['fingerprint'] ) && is_string( $row['fingerprint'] ) ? $row['fingerprint'] : '';
								$rid         = isset( $row['rule_id'] ) ? (string) $row['rule_id'] : '';
								$rcve        = isset( $row['cve'] ) ? (string) $row['cve'] : '';
								$rtitle      = self::match_title( $rid, $rcve, $rules );
								$time_raw    = isset( $row['time'] ) ? $row['time'] : '';
								$time_text   = is_numeric( $time_raw ) ? wp_date( 'Y-m-d H:i', (int) $time_raw ) : (string) $time_raw;
								$mode_text   = isset( $row['mode'] ) && 'enforce' === $row['mode'] ? 'Blocked' : 'Logged';
								?>
								<tr>
									<td><?php echo esc_html( $time_text ); ?></td>
									<td><?php echo esc_html( $rtitle ); ?></td>
									<td><?php echo esc_html( $mode_text ); ?></td>
									<td><code><?php echo esc_html( isset( $row['ip'] ) ? (string) $row['ip'] : '' ); ?></code></td>
									<td><code><?php echo esc_html( isset( $row['target'] ) ? (string) $row['target'] : '' ); ?></code></td>
									<td><?php echo esc_html( isset( $row['detail'] ) ? (string) $row['detail'] : '' ); ?></td>
									<td>
										<?php if ( preg_match( '/^[a-f0-9]{16}$/', $fingerprint ) ) : ?>
											<form method="post" action="<?php echo $action_url; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-inline">
												<?php wp_nonce_field( 'adc_security_firewall_allow', 'adc_security_firewall_allow_nonce' ); ?>
												<input type="hidden" name="action" value="adc_security_firewall_allow">
												<input type="hidden" name="fingerprint" value="<?php echo esc_attr( $fingerprint ); ?>">
												<button type="submit" class="button button-secondary">Allow this pattern</button>
											</form>
										<?php endif; ?>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php endif; ?>
		</div>

		<div class="adc-admin-panel adc-fw">
			<details class="adc-fw-details">
				<summary><strong>Safety features</strong></summary>
				<ul class="adc-fw-list">
					<li><strong>Emergency off switch:</strong> add <code>define( 'ADC_SECURITY_DISABLE_FIREWALL', true );</code> to wp-config.php to turn the firewall off immediately, even if you cannot reach this screen.</li>
					<li><strong>Automatic safe mode:</strong> if a rule starts stopping a large number of requests in a short time, the firewall switches itself to Log only and tells you here.</li>
					<li><strong>Never blocks trusted tools:</strong> WP-CLI, scheduled tasks (cron), the block editor and logged-in users are never blocked by rules that only target logged-out visitors.</li>
				</ul>
			</details>
		</div>
		<div class="adc-admin-panel adc-fw">
			<h2 class="adc-no-top-margin">Firewall rules</h2>
			<p>These rules block specific, known attacks on WordPress before the site's own code runs. Each rule matches only attack-shaped requests, so normal visitors, editors and admins are not affected.</p>

			<form method="post" action="<?php echo $action_url; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- esc_url() above. ?>" class="adc-fw-form" data-adc-confirm-block="<?php echo esc_attr__( 'Switch to Block? Matching requests will now be stopped. Make sure the Recent matches list shows only real attacks.', 'adc-security' ); ?>">
				<?php wp_nonce_field( 'adc_security_firewall_save', 'adc_security_firewall_nonce' ); ?>
				<input type="hidden" name="action" value="adc_security_firewall_save">

				<div class="adc-fw-controls">
					<label class="adc-fw-switch" for="adc-fw-enabled">
						<input type="checkbox" id="adc-fw-enabled" name="enabled" value="1" <?php checked( $enabled ); ?>>
						<strong>Turn the firewall on</strong>
					</label>

					<fieldset class="adc-fw-mode">
						<legend><strong>Mode</strong></legend>
						<label class="adc-radio-row" for="adc-fw-mode-monitor">
							<input type="radio" id="adc-fw-mode-monitor" name="mode" value="monitor" <?php checked( 'monitor', $mode ); ?>>
							Log only - recommended first
						</label>
						<p class="description adc-fw-indent">Matching requests are recorded below but still reach the site. Use this for a few days to confirm that normal traffic never matches.</p>
						<label class="adc-radio-row" for="adc-fw-mode-enforce">
							<input type="radio" id="adc-fw-mode-enforce" name="mode" value="enforce" <?php checked( 'enforce', $mode ); ?>>
							Block
						</label>
						<p class="description adc-fw-indent">Matching requests are stopped. Switch to this once the Recent matches list shows only real attacks.</p>
					</fieldset>

					<p class="adc-fw-summary" aria-live="polite"><strong><?php echo esc_html( sprintf( '%d rules active, %d not needed', $active_count, $not_needed_count ) ); ?></strong> <span class="description">for WordPress <?php echo esc_html( $wp_version ); ?></span></p>
				</div>

				<?php
				self::render_rule_table(
					'adc-fw-cve',
					'Known WordPress vulnerabilities (switch off automatically once your WordPress includes the fix)',
					$cve_rules,
					$statuses,
					$stored,
					$counts,
					$reliable
				);
				self::render_rule_table(
					'adc-fw-generic',
					'General protection (works on any WordPress version)',
					$generic_rules,
					$statuses,
					$stored,
					$counts,
					$reliable
				);
				?>

				<?php submit_button( 'Save firewall settings' ); ?>
			</form>
		</div>

		<?php
	}

	/**
	 * "At a glance" summary at the top of the Firewall tab.
	 *
	 * @param array $options Firewall options.
	 * @param array $rules   Registry rules.
	 */
	private static function render_at_a_glance( array $options, array $rules ) {
		$enabled = ! empty( $options['enabled'] );
		$mode    = isset( $options['mode'] ) && 'enforce' === $options['mode'] ? 'enforce' : 'monitor';
		$stored  = isset( $options['rules'] ) && is_array( $options['rules'] ) ? $options['rules'] : array();
		$safe    = isset( $options['safe_mode'] ) && is_array( $options['safe_mode'] ) ? $options['safe_mode'] : array();

		if ( ! $enabled ) {
			$sentence = 'The firewall is OFF.';
		} elseif ( 'monitor' === $mode ) {
			$sentence = 'The firewall is ON in Log only mode - it records matches but blocks nothing.';
		} else {
			$sentence = 'The firewall is ON and blocking.';
		}

		$kill_switch = defined( 'ADC_SECURITY_DISABLE_FIREWALL' ) && ADC_SECURITY_DISABLE_FIREWALL;

		$safe_names = array();
		foreach ( $safe as $rid => $until ) {
			if ( isset( $rules[ $rid ] ) && (int) $until > time() ) {
				$safe_names[] = isset( $rules[ $rid ]['title'] ) ? $rules[ $rid ]['title'] : $rid;
			}
		}

		// Protection list: On/Off comes from the saved options.
		$cve_total = 0;
		$cve_on    = 0;
		$gen_total = 0;
		$gen_on    = 0;
		foreach ( $rules as $rid => $rule ) {
			$choice = isset( $stored[ $rid ] ) && in_array( $stored[ $rid ], array( 'on', 'monitor' ), true );
			if ( self::is_generic_rule( $rule ) ) {
				++$gen_total;
				$gen_on += $choice ? 1 : 0;
			} else {
				++$cve_total;
				$cve_on += $choice ? 1 : 0;
			}
		}

		$htaccess_on = isset( $options['htaccess_rules'] ) && is_array( $options['htaccess_rules'] ) && in_array( 'block_sensitive_files', $options['htaccess_rules'], true );
		$htaccess    = ( new ADC_Security_Htaccess() )->get_status();
		if ( isset( $htaccess['error'] ) ) {
			$htaccess_state = 'Could not be checked';
			$htaccess_class = 'adc-fw-badge-off';
		} elseif ( empty( $htaccess['supported'] ) ) {
			$htaccess_state = 'Not supported on this server';
			$htaccess_class = 'adc-fw-badge-off';
		} elseif ( ! empty( $htaccess['managed'] ) ) {
			$htaccess_state = 'Managed (applied)';
			$htaccess_class = 'adc-fw-badge-active';
		} else {
			$htaccess_state = 'Not applied';
			$htaccess_class = 'adc-fw-badge-off';
		}

		$opts = get_option( 'adc_security_options', array() );
		$opts = is_array( $opts ) ? $opts : array();
		$allow_count = self::count_lines( isset( $opts['ip_allowlist'] ) ? $opts['ip_allowlist'] : '' );
		$deny_count  = self::count_lines( isset( $opts['ip_denylist'] ) ? $opts['ip_denylist'] : '' );

		$protections = array(
			array(
				'label'  => 'Known WordPress vulnerabilities',
				'badge'  => $cve_on > 0 ? 'On' : 'Off',
				'class'  => $cve_on > 0 ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => sprintf( '%d of %d rules turned on', $cve_on, $cve_total ),
				'tab'    => 'firewall',
			),
			array(
				'label'  => 'General protection rules',
				'badge'  => $gen_on > 0 ? 'On' : 'Off',
				'class'  => $gen_on > 0 ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => sprintf( '%d of %d rules turned on', $gen_on, $gen_total ),
				'tab'    => 'firewall',
			),
			array(
				'label'  => 'Server rules (.htaccess)',
				'badge'  => $htaccess_state,
				'class'  => $htaccess_class,
				'detail' => 'Sensitive-file group: ' . ( $htaccess_on ? 'On' : 'Off' ),
				'tab'    => 'hardening',
			),
			array(
				'label'  => 'Rate limiting (login, XML-RPC, user lookups)',
				'badge'  => ! isset( $opts['rate_limiting_enabled'] ) || ! empty( $opts['rate_limiting_enabled'] ) ? 'On' : 'Off',
				'class'  => ! isset( $opts['rate_limiting_enabled'] ) || ! empty( $opts['rate_limiting_enabled'] ) ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => '',
				'tab'    => 'login',
			),
			array(
				'label'  => 'Blocking after wrong passwords',
				'badge'  => ! empty( $opts['brute_force_protection'] ) ? 'On' : 'Off',
				'class'  => ! empty( $opts['brute_force_protection'] ) ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => '',
				'tab'    => 'login',
			),
			array(
				'label'  => 'IP allow and deny lists',
				'badge'  => $allow_count + $deny_count > 0 ? 'On' : 'Off',
				'class'  => $allow_count + $deny_count > 0 ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => sprintf( '%d allowed IPs skip all firewall rules. %d denied IPs.', $allow_count, $deny_count ),
				'tab'    => 'login',
			),
			array(
				'label'  => 'User enumeration',
				'badge'  => ! empty( $opts['prevent_user_enumeration'] ) ? 'On' : 'Off',
				'class'  => ! empty( $opts['prevent_user_enumeration'] ) ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => '',
				'tab'    => 'hardening',
			),
			array(
				'label'  => 'XML-RPC',
				'badge'  => ! empty( $opts['disable_xmlrpc'] ) ? 'On' : 'Off',
				'class'  => ! empty( $opts['disable_xmlrpc'] ) ? 'adc-fw-badge-active' : 'adc-fw-badge-off',
				'detail' => 'On means XML-RPC is blocked.',
				'tab'    => 'hardening',
			),
		);

		$fw = ADC_Security_Stats::get_firewall_stats( 7 );
		$fw = is_array( $fw ) ? $fw : array();

		$week = array(
			'Requests stopped by firewall rules' => isset( $fw['rule_blocks'] ) ? (int) $fw['rule_blocks'] : 0,
			'Requests slowed by rate limits'     => isset( $fw['rate_limited'] ) ? (int) $fw['rate_limited'] : 0,
			'Lockouts after wrong passwords'     => isset( $fw['lockout'] ) ? (int) $fw['lockout'] : 0,
			'Visitors blocked by the IP denylist' => isset( $fw['ip_denied'] ) ? (int) $fw['ip_denied'] : 0,
		);
		?>
		<div class="adc-admin-panel adc-fw adc-fw-glance">
			<h2 class="adc-no-top-margin">At a glance</h2>

			<p class="adc-fw-status"><strong><?php echo esc_html( $sentence ); ?></strong></p>

			<?php if ( $kill_switch ) : ?>
				<div class="notice notice-error inline"><p>The emergency switch is on: <code>ADC_SECURITY_DISABLE_FIREWALL</code> is set in wp-config.php, so the firewall is off whatever is selected below.</p></div>
			<?php endif; ?>

			<?php if ( $enabled && ! empty( $safe_names ) ) : ?>
				<p>Rules in safe mode (Log only for now): <strong><?php echo esc_html( implode( ', ', $safe_names ) ); ?></strong></p>
			<?php endif; ?>

			<h3>What protects your site</h3>
			<div class="adc-fw-table-wrap">
				<table class="widefat striped adc-fw-table">
					<thead>
						<tr>
							<th scope="col">Protection</th>
							<th scope="col">Status</th>
							<th scope="col">Details</th>
							<th scope="col">Where to change it</th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $protections as $item ) : ?>
							<tr>
								<td><strong><?php echo esc_html( $item['label'] ); ?></strong></td>
								<td><span class="adc-fw-badge <?php echo esc_attr( $item['class'] ); ?>"><?php echo esc_html( $item['badge'] ); ?></span></td>
								<td><?php echo esc_html( $item['detail'] ); ?></td>
								<td><a href="<?php echo esc_url( self::tab_url( $item['tab'] ) ); ?>"><?php echo esc_html( self::tab_label( $item['tab'] ) ); ?></a></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<h3>Last 7 days</h3>
			<div class="adc-fw-table-wrap">
				<table class="widefat striped adc-fw-table">
					<tbody>
						<?php foreach ( $week as $label => $value ) : ?>
							<tr>
								<th scope="row"><?php echo esc_html( $label ); ?></th>
								<td><?php echo esc_html( number_format_i18n( $value ) ); ?></td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>

			<?php if ( ! ADC_Security_Ip::is_client_ip_reliable() ) : ?>
				<div class="notice notice-warning inline">
					<p>Your site seems to be behind a CDN or proxy (for example Cloudflare), but the trusted proxy setting is empty or does not match it. Until it is set correctly, limits and lockouts may treat all visitors as one person, so the firewall runs the IP-based rules in Log only mode. <a href="<?php echo esc_url( self::tab_url( 'login' ) ); ?>">Set the proxy header in Login Security.</a></p>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * One rules table (CVE or general) with its sub-heading.
	 *
	 * @param string $id          Element id prefix.
	 * @param string $heading     Sub-heading text.
	 * @param array  $group_rules Registry rules in this group.
	 * @param array  $statuses    Effective status per rule id.
	 * @param array  $stored      Saved per-rule choices.
	 * @param array  $counts      Blocks in the last 7 days per rule id.
	 * @param bool   $reliable    Whether the visitor IP can be trusted.
	 */
	private static function render_rule_table( $id, $heading, array $group_rules, array $statuses, array $stored, array $counts, $reliable ) {
		if ( empty( $group_rules ) ) {
			return;
		}
		$generic = self::is_generic_rule( reset( $group_rules ) );
		?>
		<h3 id="<?php echo esc_attr( $id ); ?>"><?php echo esc_html( $heading ); ?></h3>
		<div class="adc-fw-table-wrap">
			<table class="widefat striped adc-fw-table" aria-labelledby="<?php echo esc_attr( $id ); ?>">
				<thead>
					<tr>
						<th scope="col">Rule</th>
						<th scope="col">Severity</th>
						<th scope="col">Affects</th>
						<th scope="col">Fixed in</th>
						<th scope="col">Status</th>
						<th scope="col">Choice</th>
						<th scope="col">Blocks (7 days)</th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $group_rules as $rule_id => $rule ) : ?>
						<?php
						$status    = isset( $statuses[ $rule_id ] ) ? $statuses[ $rule_id ] : array( 'state' => 'disabled', 'reason' => '' );
						$state     = isset( $status['state'] ) ? $status['state'] : 'disabled';
						$reason    = isset( $status['reason'] ) ? (string) $status['reason'] : '';
						$choice    = isset( $stored[ $rule_id ] ) && in_array( $stored[ $rule_id ], array( 'off', 'on', 'monitor' ), true ) ? $stored[ $rule_id ] : 'off';
						$select_id = 'adc-fw-rule-' . sanitize_html_class( $rule_id );
						$title     = isset( $rule['title'] ) ? $rule['title'] : $rule_id;
						$cve_url   = self::first_source_url( $rule );
						$forced    = $generic && in_array( $rule_id, self::IP_BASED_RULES, true ) && ! $reliable;
						$affected  = $generic ? 'Always' : ( isset( $rule['affected'] ) && is_array( $rule['affected'] ) ? implode( ', ', array_map( 'strval', $rule['affected'] ) ) : '' );
						$fixed     = $generic ? '-' : self::format_fixed( isset( $rule['fixed'] ) ? $rule['fixed'] : array() );
						$block_cnt = isset( $counts[ $rule_id ] ) ? (int) $counts[ $rule_id ] : 0;
						?>
						<tr>
							<td>
								<strong><?php echo esc_html( $title ); ?></strong>
								<?php if ( ! empty( $rule['cve'] ) ) : ?>
									<br>
									<?php if ( '' !== $cve_url ) : ?>
										<a href="<?php echo esc_url( $cve_url ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( $rule['cve'] ); ?><span class="screen-reader-text"> (opens in a new tab)</span></a>
									<?php else : ?>
										<code><?php echo esc_html( $rule['cve'] ); ?></code>
									<?php endif; ?>
								<?php endif; ?>
								<?php if ( ! empty( $rule['summary'] ) ) : ?>
									<p class="description adc-fw-summary-text"><?php echo esc_html( $rule['summary'] ); ?></p>
								<?php endif; ?>
							</td>
							<td><?php echo self::severity_badge( isset( $rule['severity'] ) ? $rule['severity'] : 'medium' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts. ?></td>
							<td><?php echo esc_html( $affected ); ?></td>
							<td><?php echo esc_html( $fixed ); ?></td>
							<td>
								<?php echo self::status_badge( $state ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built from escaped parts. ?>
								<?php if ( '' !== $reason ) : ?>
									<br><span class="description"><?php echo esc_html( $reason ); ?></span>
								<?php endif; ?>
								<?php if ( $forced ) : ?>
									<br><span class="description">Log only (forced: visitor IP not reliable)</span>
								<?php endif; ?>
							</td>
							<td>
								<label class="screen-reader-text" for="<?php echo esc_attr( $select_id ); ?>">Choice for <?php echo esc_html( $title ); ?></label>
								<select id="<?php echo esc_attr( $select_id ); ?>" name="rules[<?php echo esc_attr( $rule_id ); ?>]" <?php disabled( 'not_needed', $state ); ?>>
									<option value="off" <?php selected( 'off', $choice ); ?>>Off</option>
									<option value="on" <?php selected( 'on', $choice ); ?>>On</option>
									<option value="monitor" <?php selected( 'monitor', $choice ); ?>>Log only</option>
								</select>
							</td>
							<td><?php echo esc_html( number_format_i18n( $block_cnt ) ); ?></td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	/**
	 * Whether a registry rule is a general (non-CVE) rule.
	 *
	 * @param array $rule Rule definition.
	 * @return bool
	 */
	private static function is_generic_rule( $rule ) {
		return is_array( $rule ) && isset( $rule['kind'] ) && 'generic' === $rule['kind'];
	}

	/**
	 * Title shown in Recent matches: the rule title, else the CVE id, else a fallback.
	 *
	 * @param string $rule_id Rule id from the match.
	 * @param string $cve     CVE id from the match.
	 * @param array  $rules   Registry rules.
	 * @return string
	 */
	private static function match_title( $rule_id, $cve, array $rules ) {
		if ( '' !== $rule_id && isset( $rules[ $rule_id ]['title'] ) ) {
			return (string) $rules[ $rule_id ]['title'];
		}
		if ( '' !== $cve ) {
			return $cve;
		}
		return __( 'Unknown rule', 'adc-security' );
	}

	/**
	 * Count non-empty lines in a saved IP list.
	 *
	 * @param string $raw Newline separated list.
	 * @return int
	 */
	private static function count_lines( $raw ) {
		$lines = preg_split( '/\R/', (string) $raw );
		return count( array_filter( array_map( 'trim', (array) $lines ), 'strlen' ) );
	}

	/**
	 * Tab URL inside the plugin settings page.
	 *
	 * @param string $tab Tab slug.
	 * @return string
	 */
	private static function tab_url( $tab ) {
		return add_query_arg(
			array(
				'page' => 'adc-security',
				'tab'  => $tab,
			),
			admin_url( 'admin.php' )
		);
	}

	/**
	 * Plain-language name of a settings tab.
	 *
	 * @param string $tab Tab slug.
	 * @return string
	 */
	private static function tab_label( $tab ) {
		$labels = array(
			'firewall'  => 'Change on Firewall tab',
			'login'     => 'Set in Login Security',
			'hardening' => 'Set in Hardening',
		);
		return isset( $labels[ $tab ] ) ? $labels[ $tab ] : 'Open settings';
	}

	/**
	 * First source URL of a rule, if any.
	 *
	 * @param array $rule Rule definition.
	 * @return string
	 */
	private static function first_source_url( $rule ) {
		if ( empty( $rule['sources'] ) || ! is_array( $rule['sources'] ) ) {
			return '';
		}
		$first = reset( $rule['sources'] );
		if ( is_array( $first ) ) {
			$first = isset( $first['url'] ) ? $first['url'] : '';
		}
		return is_string( $first ) ? esc_url_raw( $first ) : '';
	}

	/**
	 * Turn a branch => version map into plain text.
	 *
	 * @param array $fixed Branch to version map.
	 * @return string
	 */
	private static function format_fixed( $fixed ) {
		if ( ! is_array( $fixed ) || empty( $fixed ) ) {
			return '';
		}
		$parts = array();
		foreach ( $fixed as $branch => $version ) {
			$parts[] = $branch . ' ' . $version;
		}
		return implode( ', ', $parts );
	}

	/**
	 * Severity badge markup (labels are fixed strings).
	 *
	 * @param string $severity critical|high|medium.
	 * @return string
	 */
	private static function severity_badge( $severity ) {
		$map = array(
			'critical' => array( 'Critical', 'adc-fw-badge-critical' ),
			'high'     => array( 'High', 'adc-fw-badge-high' ),
			'medium'   => array( 'Medium', 'adc-fw-badge-medium' ),
		);
		$key   = isset( $map[ $severity ] ) ? $severity : 'medium';
		return '<span class="adc-fw-badge ' . esc_attr( $map[ $key ][1] ) . '">' . esc_html( $map[ $key ][0] ) . '</span>';
	}

	/**
	 * Status badge markup (labels are fixed strings).
	 *
	 * @param string $state active|monitor|disabled|not_needed.
	 * @return string
	 */
	private static function status_badge( $state ) {
		$map = array(
			'active'     => array( 'Active', 'adc-fw-badge-active' ),
			'monitor'    => array( 'Log only', 'adc-fw-badge-monitor' ),
			'disabled'   => array( 'Off', 'adc-fw-badge-off' ),
			'not_needed' => array( 'Not needed', 'adc-fw-badge-ok' ),
		);
		$key = isset( $map[ $state ] ) ? $state : 'disabled';
		return '<span class="adc-fw-badge ' . esc_attr( $map[ $key ][1] ) . '">' . esc_html( $map[ $key ][0] ) . '</span>';
	}
}
