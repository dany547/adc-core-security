<?php
/**
 * ADC Security Dashboard Class
 *
 * Renders the four dashboard cards on the plugin's Dashboard tab. Reads
 * existing plugin state (nothing new is stored here) and computes the
 * security score via ADC_Security_Score.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Dashboard {

	/**
	 * @var ADC_Security_Htaccess
	 */
	private $htaccess;

	/**
	 * @var ADC_Security_Keys
	 */
	private $keys;

	/**
	 * @param ADC_Security_Htaccess $htaccess Fixed-rule .htaccess manager.
	 * @param ADC_Security_Keys     $keys     Security key manager.
	 */
	public function __construct( ADC_Security_Htaccess $htaccess, ADC_Security_Keys $keys ) {
		$this->htaccess = $htaccess;
		$this->keys     = $keys;
	}

	/**
	 * Render all four dashboard cards.
	 */
	public function render() {
		$options         = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		$htaccess_status = $this->htaccess->get_status();
		$keys_status     = $this->keys->get_status();

		$admin_user = get_user_by( 'login', 'admin' );
		$has_default_admin = $admin_user && user_can( $admin_user, 'manage_options' );
		$admins_without_2fa = $this->count_admins_without_2fa();

		$score_extra = array(
			'default_admin_user' => $has_default_admin,
			'admins_without_2fa' => $admins_without_2fa,
		);

		if ( class_exists( 'ADC_Security_Integrity' ) ) {
			$integrity_result = ADC_Security_Integrity::get_last_result();
			if ( ! empty( $integrity_result['completed_at'] ) ) {
				$score_extra['integrity_issues'] = count( $integrity_result['core_findings'] ) + count( $integrity_result['plugin_theme_findings'] ) + count( $integrity_result['upload_findings'] );
			}
		}
		if ( class_exists( 'ADC_Security_Vulnerabilities' ) ) {
			$vuln_result = ADC_Security_Vulnerabilities::get_last_result();
			if ( ! empty( $vuln_result['scanned_at'] ) ) {
				$score_extra['vulnerability_issues'] = count( $vuln_result['findings'] );
			}
		}

		$score = ADC_Security_Score::calculate( $options, $htaccess_status, $keys_status, $score_extra );

		echo '<div class="adc-dashboard-grid">';
		$this->render_score_card( $score );
		$this->render_login_card();
		$this->render_users_card( $has_default_admin, $admins_without_2fa );
		$this->render_system_card( $htaccess_status, $keys_status );
		echo '</div>';
	}

	/**
	 * Card 1: security score & checklist.
	 *
	 * @param array $score Result of ADC_Security_Score::calculate().
	 */
	private function render_score_card( array $score ) {
		?>
		<div class="postbox adc-dashboard-card">
			<h2 class="hndle"><span><?php esc_html_e( 'Security Score', 'adc-security' ); ?></span></h2>
			<div class="inside">
				<p class="adc-score-value">
					<span class="adc-score-number adc-grade-<?php echo esc_attr( strtolower( $score['grade'] ) ); ?>"><?php echo (int) $score['score']; ?></span>
					<span class="adc-score-max">/100</span>
					<span class="adc-score-grade">(<?php echo esc_html( $score['grade'] ); ?>)</span>
				</p>
				<ul class="adc-score-checklist">
					<?php foreach ( $score['checks'] as $check ) : ?>
						<li class="<?php echo $check['passed'] ? 'adc-check-pass' : 'adc-check-fail'; ?>">
							<span class="dashicons <?php echo $check['passed'] ? 'dashicons-yes-alt' : 'dashicons-warning'; ?>"></span>
							<?php if ( ! $check['passed'] && ! empty( $check['tab'] ) ) : ?>
								<a href="<?php echo esc_url( add_query_arg( array( 'page' => 'adc-security', 'tab' => $check['tab'] ), admin_url( 'admin.php' ) ) ); ?>"><?php echo esc_html( $check['label'] ); ?></a>
							<?php else : ?>
								<?php echo esc_html( $check['label'] ); ?>
							<?php endif; ?>
						</li>
					<?php endforeach; ?>
				</ul>
			</div>
		</div>
		<?php
	}

	/**
	 * Card 2: login & lockout activity.
	 */
	private function render_login_card() {
		$locked_ips = get_option( 'adc_locked_ips', array() );
		$locked_ips = array_filter(
			$locked_ips,
			static function ( $expiry ) {
				return $expiry > time();
			}
		);

		$stats = class_exists( 'ADC_Security_Stats' ) ? ADC_Security_Stats::get_login_stats() : array();
		?>
		<div class="postbox adc-dashboard-card">
			<h2 class="hndle"><span><?php esc_html_e( 'Login & Lockout', 'adc-security' ); ?></span></h2>
			<div class="inside">
				<p>
					<strong><?php echo (int) count( $locked_ips ); ?></strong>
					<?php esc_html_e( 'IP address(es) currently blocked.', 'adc-security' ); ?>
				</p>
				<?php if ( ! empty( $stats ) ) : ?>
					<p class="description">
						<?php
						printf(
							/* translators: 1: failed logins in 24h, 2: in 7 days, 3: in 30 days */
							esc_html__( 'Failed logins: %1$d (24h) / %2$d (7d) / %3$d (30d)', 'adc-security' ),
							(int) $stats['attempts_24h'],
							(int) $stats['attempts_7d'],
							(int) $stats['attempts_30d']
						);
						?>
					</p>
					<?php if ( ! empty( $stats['sparkline'] ) ) : ?>
						<?php echo $this->render_sparkline( $stats['sparkline'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- built internally from esc_attr()'d numbers. ?>
					<?php endif; ?>
					<?php if ( ! empty( $stats['top_ips'] ) ) : ?>
						<h4><?php esc_html_e( 'Top attacking IPs (30d)', 'adc-security' ); ?></h4>
						<ul class="adc-dashboard-list">
							<?php foreach ( $stats['top_ips'] as $row ) : ?>
								<li><code><?php echo esc_html( $row['value'] ); ?></code> &mdash; <?php echo (int) $row['total']; ?></li>
							<?php endforeach; ?>
						</ul>
					<?php endif; ?>
				<?php endif; ?>
				<p class="description">
					<a href="<?php echo esc_url( add_query_arg( array( 'page' => 'adc-security', 'tab' => 'login' ), admin_url( 'admin.php' ) ) ); ?>"><?php esc_html_e( 'Manage Login Security settings', 'adc-security' ); ?></a>
				</p>
			</div>
		</div>
		<?php
	}

	/**
	 * Build an inline, CSP-safe SVG sparkline from a day => count series.
	 *
	 * @param array $series Associative array of 'Y-m-d' => int count, oldest first.
	 * @return string SVG markup.
	 */
	private function render_sparkline( array $series ) {
		$values = array_values( $series );
		$max    = max( 1, max( $values ) );
		$width  = 260;
		$height = 40;
		$step   = count( $values ) > 1 ? $width / ( count( $values ) - 1 ) : $width;

		$points = array();
		foreach ( $values as $i => $value ) {
			$x        = round( $i * $step, 1 );
			$y        = round( $height - ( $value / $max * $height ), 1 );
			$points[] = $x . ',' . $y;
		}

		return sprintf(
			'<svg class="adc-sparkline" viewBox="0 0 %1$d %2$d" width="%1$d" height="%2$d" role="img" aria-label="%3$s"><polyline fill="none" stroke="currentColor" stroke-width="1.5" points="%4$s" /></svg>',
			(int) $width,
			(int) $height,
			esc_attr__( 'Failed logins over the last 30 days', 'adc-security' ),
			esc_attr( implode( ' ', $points ) )
		);
	}

	/**
	 * Count administrators who do not have 2FA enabled.
	 *
	 * @return int
	 */
	private function count_admins_without_2fa() {
		if ( ! class_exists( 'ADC_Security_2fa' ) ) {
			return 0;
		}

		$without = 0;
		foreach ( get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) ) as $user ) {
			if ( ! ADC_Security_2fa::instance()->is_enabled( $user->ID ) ) {
				++$without;
			}
		}
		return $without;
	}

	/**
	 * Card 3: users & sessions.
	 *
	 * @param bool $has_default_admin  Whether an "admin" username with manage_options exists.
	 * @param int  $admins_without_2fa Number of administrators without 2FA enabled.
	 */
	private function render_users_card( $has_default_admin, $admins_without_2fa = 0 ) {
		$admin_count     = 0;
		$active_sessions = 0;

		foreach ( get_users( array( 'role' => 'administrator', 'fields' => array( 'ID' ) ) ) as $user ) {
			++$admin_count;

			$tokens = get_user_meta( $user->ID, 'session_tokens', true );
			if ( is_array( $tokens ) ) {
				$active_sessions += count( $tokens );
			}
		}
		?>
		<div class="postbox adc-dashboard-card">
			<h2 class="hndle"><span><?php esc_html_e( 'Users & Sessions', 'adc-security' ); ?></span></h2>
			<div class="inside">
				<p><strong><?php echo (int) $admin_count; ?></strong> <?php esc_html_e( 'administrator account(s).', 'adc-security' ); ?></p>
				<p><strong><?php echo (int) $active_sessions; ?></strong> <?php esc_html_e( 'active admin session(s) right now.', 'adc-security' ); ?></p>
				<?php if ( $admins_without_2fa > 0 ) : ?>
					<p class="adc-dashboard-warning">
						<span class="dashicons dashicons-warning"></span>
						<?php
						printf(
							/* translators: %d: number of administrators without 2FA */
							esc_html( _n( '%d administrator without 2FA enabled.', '%d administrators without 2FA enabled.', $admins_without_2fa, 'adc-security' ) ),
							(int) $admins_without_2fa
						);
						?>
					</p>
				<?php endif; ?>
				<?php if ( $has_default_admin ) : ?>
					<p class="adc-dashboard-warning">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e( 'A default "admin" username exists with administrator rights.', 'adc-security' ); ?>
					</p>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Card 4: system & integrity.
	 *
	 * @param array $htaccess_status Result of ADC_Security_Htaccess::get_status().
	 * @param array $keys_status     Result of ADC_Security_Keys::get_status().
	 */
	private function render_system_card( array $htaccess_status, array $keys_status ) {
		$logs = array_slice( ADC_Security_Logger::get_logs(), 0, 5 );
		?>
		<div class="postbox adc-dashboard-card">
			<h2 class="hndle"><span><?php esc_html_e( 'System & Integrity', 'adc-security' ); ?></span></h2>
			<div class="inside">
				<ul class="adc-dashboard-list">
					<li><?php esc_html_e( 'WordPress', 'adc-security' ); ?>: <strong><?php echo esc_html( get_bloginfo( 'version' ) ); ?></strong></li>
					<li><?php esc_html_e( 'PHP', 'adc-security' ); ?>: <strong><?php echo esc_html( phpversion() ); ?></strong></li>
					<li><?php esc_html_e( 'HTTPS', 'adc-security' ); ?>: <strong><?php echo is_ssl() ? esc_html__( 'Yes', 'adc-security' ) : esc_html__( 'No', 'adc-security' ); ?></strong></li>
					<li>
						<?php esc_html_e( 'Server rules', 'adc-security' ); ?>:
						<strong><?php echo ! empty( $htaccess_status['managed'] ) ? esc_html__( 'Applied', 'adc-security' ) : esc_html__( 'Not applied', 'adc-security' ); ?></strong>
						<?php if ( ! empty( $htaccess_status['drift'] ) ) : ?>
							<span class="adc-dashboard-warning"><?php esc_html_e( '(changed outside ADC Security)', 'adc-security' ); ?></span>
						<?php endif; ?>
					</li>
					<li>
						<?php esc_html_e( 'Security keys backup', 'adc-security' ); ?>:
						<strong><?php echo ! empty( $keys_status['has_backup'] ) ? esc_html( $keys_status['backed_up_at'] ) : esc_html__( 'None', 'adc-security' ); ?></strong>
					</li>
					<?php if ( class_exists( 'ADC_Security_Integrity' ) ) : ?>
						<?php $integrity = ADC_Security_Integrity::get_last_result(); ?>
						<li>
							<?php esc_html_e( 'File integrity scan', 'adc-security' ); ?>:
							<?php if ( empty( $integrity['completed_at'] ) ) : ?>
								<strong><?php esc_html_e( 'Not run yet', 'adc-security' ); ?></strong>
							<?php else : ?>
								<?php $issue_count = count( $integrity['core_findings'] ) + count( $integrity['plugin_theme_findings'] ) + count( $integrity['upload_findings'] ); ?>
								<strong class="<?php echo $issue_count > 0 ? 'adc-dashboard-warning' : ''; ?>">
									<?php
									echo 0 === $issue_count
										? esc_html__( 'Clean', 'adc-security' )
										/* translators: %d: number of integrity issues found */
										: esc_html( sprintf( _n( '%d issue found', '%d issues found', $issue_count, 'adc-security' ), $issue_count ) );
									?>
								</strong>
								<span class="description">(<?php echo esc_html( human_time_diff( $integrity['completed_at'] ) ); ?> <?php esc_html_e( 'ago', 'adc-security' ); ?>)</span>
							<?php endif; ?>
						</li>
					<?php endif; ?>
					<?php if ( class_exists( 'ADC_Security_Vulnerabilities' ) ) : ?>
						<?php $vulns = ADC_Security_Vulnerabilities::get_last_result(); ?>
						<li>
							<?php esc_html_e( 'Plugin health scan', 'adc-security' ); ?>:
							<?php if ( empty( $vulns['scanned_at'] ) ) : ?>
								<strong><?php esc_html_e( 'Not run yet', 'adc-security' ); ?></strong>
							<?php else : ?>
								<strong class="<?php echo ! empty( $vulns['findings'] ) ? 'adc-dashboard-warning' : ''; ?>">
									<?php
									echo empty( $vulns['findings'] )
										? esc_html__( 'No issues found', 'adc-security' )
										/* translators: %d: number of flagged plugins */
										: esc_html( sprintf( _n( '%d plugin flagged', '%d plugins flagged', count( $vulns['findings'] ), 'adc-security' ), count( $vulns['findings'] ) ) );
									?>
								</strong>
							<?php endif; ?>
						</li>
					<?php endif; ?>
				</ul>
				<?php $this->render_cron_health_notice(); ?>
				<h4><?php esc_html_e( 'Recent activity', 'adc-security' ); ?></h4>
				<?php if ( empty( $logs ) ) : ?>
					<p class="description"><?php esc_html_e( 'No recent errors or warnings.', 'adc-security' ); ?></p>
				<?php else : ?>
					<ul class="adc-dashboard-list">
						<?php foreach ( $logs as $log ) : ?>
							<li>
								<span class="adc-log-level"><?php echo esc_html( $log['level'] ); ?></span>
								<?php echo esc_html( $log['message'] ); ?>
								<span class="description"><?php echo esc_html( $log['timestamp'] ); ?></span>
							</li>
						<?php endforeach; ?>
					</ul>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Warn when a background scan/cron appears stuck (WP-Cron never fires,
	 * or fires far less often than expected — common on low-traffic or
	 * misconfigured sites).
	 */
	private function render_cron_health_notice() {
		if ( ! class_exists( 'ADC_Security_Cron_Health' ) || ! ADC_Security_Cron_Health::any_overdue() ) {
			return;
		}

		$labels = array(
			'adc_security_prune_events'   => __( 'audit-log cleanup', 'adc-security' ),
			'adc_security_integrity_scan' => __( 'file integrity scan', 'adc-security' ),
			'adc_security_vuln_scan'      => __( 'plugin health scan', 'adc-security' ),
		);

		$overdue_labels = array();
		foreach ( ADC_Security_Cron_Health::get_status() as $hook => $hook_status ) {
			if ( $hook_status['overdue'] ) {
				$overdue_labels[] = isset( $labels[ $hook ] ) ? $labels[ $hook ] : $hook;
			}
		}

		if ( empty( $overdue_labels ) ) {
			return;
		}
		?>
		<p class="adc-dashboard-warning">
			<span class="dashicons dashicons-warning"></span>
			<?php
			printf(
				/* translators: %s: comma-separated list of scan names */
				esc_html__( 'WP-Cron looks stuck: %s haven\'t run on schedule. If this site has real traffic, check whether wp-cron.php is being blocked or DISABLE_WP_CRON is set without a real system cron replacing it.', 'adc-security' ),
				esc_html( implode( ', ', $overdue_labels ) )
			);
			?>
		</p>
		<?php
	}
}
