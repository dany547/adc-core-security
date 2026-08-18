<?php
/**
 * ADC Security 2FA Class
 *
 * WordPress integration for TOTP two-factor authentication: enrollment UI
 * (profile screen + the plugin's own "Two-Factor Auth" tab), the two-step
 * login flow, per-role enforcement with a grace period, an Application
 * Passwords opt-out for roles that require 2FA, and a lightweight password
 * policy (minimum length + a common-password blocklist).
 *
 * TOTP math lives in ADC_Security_Totp; this class only handles storage,
 * WordPress hooks, and rendering.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_2fa {

	const META_SECRET         = 'adc_security_totp_secret';
	const META_PENDING_SECRET = 'adc_security_totp_pending_secret';
	const META_ENABLED        = 'adc_security_totp_enabled';
	const META_RECOVERY_CODES = 'adc_security_totp_recovery_codes';
	const META_REQUIRED_SINCE = 'adc_security_2fa_required_since';

	const LOGIN_ACTION = 'adc_2fa';

	/**
	 * @var self|null
	 */
	private static $instance = null;

	/**
	 * @return self
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );

		add_action( 'admin_post_adc_security_2fa_generate', array( $this, 'handle_generate' ) );
		add_action( 'admin_post_adc_security_2fa_confirm', array( $this, 'handle_confirm' ) );
		add_action( 'admin_post_adc_security_2fa_disable', array( $this, 'handle_disable' ) );
		add_action( 'admin_post_adc_security_2fa_regenerate_codes', array( $this, 'handle_regenerate_codes' ) );

		// Priority 40: after captcha (20) and brute-force lockout (30) have
		// already had a chance to reject the request.
		add_filter( 'authenticate', array( $this, 'maybe_challenge_2fa' ), 40, 3 );
		add_action( 'login_form_' . self::LOGIN_ACTION, array( $this, 'handle_2fa_challenge' ) );

		add_action( 'admin_init', array( $this, 'enforce_grace_period' ) );

		add_filter( 'wp_is_application_passwords_available_for_user', array( $this, 'maybe_block_application_passwords' ), 10, 2 );

		add_filter( 'user_profile_update_errors', array( $this, 'validate_password_policy_profile' ), 10, 3 );
		add_action( 'validate_password_reset', array( $this, 'validate_password_policy_reset' ), 10, 2 );
	}

	// -------------------------------------------------------------------------
	// Storage helpers
	// -------------------------------------------------------------------------

	/**
	 * @param int $user_id
	 * @return bool
	 */
	public function is_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, self::META_ENABLED, true );
	}

	/**
	 * @param int $user_id
	 * @return string Decrypted Base32 secret, or '' if none.
	 */
	private function get_secret( $user_id ) {
		$encrypted = get_user_meta( $user_id, self::META_SECRET, true );
		return $encrypted ? self::decrypt( (string) $encrypted ) : '';
	}

	/**
	 * @param int $user_id
	 * @return string Decrypted Base32 pending secret, or '' if none.
	 */
	private function get_pending_secret( $user_id ) {
		$encrypted = get_user_meta( $user_id, self::META_PENDING_SECRET, true );
		return $encrypted ? self::decrypt( (string) $encrypted ) : '';
	}

	/**
	 * Verify a submitted single-use recovery code, consuming it on success.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted recovery code.
	 * @return bool
	 */
	private function verify_recovery_code( $user_id, $code ) {
		$code   = strtoupper( trim( (string) $code ) );
		$hashes = get_user_meta( $user_id, self::META_RECOVERY_CODES, true );
		if ( '' === $code || ! is_array( $hashes ) ) {
			return false;
		}

		foreach ( $hashes as $index => $hash ) {
			if ( wp_check_password( $code, $hash, $user_id ) ) {
				unset( $hashes[ $index ] );
				update_user_meta( $user_id, self::META_RECOVERY_CODES, array_values( $hashes ) );
				return true;
			}
		}

		return false;
	}

	/**
	 * Generate 8 recovery codes, store them hashed, and return the plaintext
	 * codes (only ever available at generation time).
	 *
	 * @param int $user_id User ID.
	 * @return string[] Plaintext recovery codes.
	 */
	private function generate_recovery_codes( $user_id ) {
		$plain  = array();
		$hashed = array();

		for ( $i = 0; $i < 8; $i++ ) {
			$code    = self::random_recovery_code();
			$plain[] = $code;
			$hashed[] = wp_hash_password( $code );
		}

		update_user_meta( $user_id, self::META_RECOVERY_CODES, $hashed );

		return $plain;
	}

	/**
	 * @return string A code shaped like XXXX-XXXX using an unambiguous alphabet.
	 */
	private static function random_recovery_code() {
		$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No 0/O/1/I.
		$code     = '';
		for ( $i = 0; $i < 8; $i++ ) {
			$code .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
			if ( 3 === $i ) {
				$code .= '-';
			}
		}
		return $code;
	}

	// -------------------------------------------------------------------------
	// Encryption (AUTH/SECURE_AUTH salts derive the key; rotating those salts
	// invalidates stored secrets, same trade-off as any salt-derived secret).
	// -------------------------------------------------------------------------

	/**
	 * @return string 32-byte binary key.
	 */
	private static function get_encryption_key() {
		return hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ) . '|adc-security-totp', true );
	}

	/**
	 * @param string $plaintext
	 * @return string
	 */
	public static function encrypt( $plaintext ) {
		$key = self::get_encryption_key();

		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce      = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, $key );
			return 'sodium:' . base64_encode( $nonce . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		}

		$iv         = openssl_random_pseudo_bytes( 16 );
		$ciphertext = openssl_encrypt( $plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
		return 'openssl:' . base64_encode( $iv . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * @param string $encoded
	 * @return string Decrypted plaintext, or '' on any failure.
	 */
	public static function decrypt( $encoded ) {
		if ( '' === $encoded || false === strpos( $encoded, ':' ) ) {
			return '';
		}

		list( $mode, $b64 ) = explode( ':', $encoded, 2 );
		$raw = base64_decode( $b64, true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		if ( false === $raw ) {
			return '';
		}

		$key = self::get_encryption_key();

		if ( 'sodium' === $mode && function_exists( 'sodium_crypto_secretbox_open' ) ) {
			if ( strlen( $raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				return '';
			}
			$nonce      = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$ciphertext = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
			$plain      = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
			return false === $plain ? '' : $plain;
		}

		if ( 'openssl' === $mode ) {
			if ( strlen( $raw ) < 16 ) {
				return '';
			}
			$iv         = substr( $raw, 0, 16 );
			$ciphertext = substr( $raw, 16 );
			$plain      = openssl_decrypt( $ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
			return false === $plain ? '' : $plain;
		}

		return '';
	}

	// -------------------------------------------------------------------------
	// Enrollment UI (profile screen and the plugin's 2FA tab share this)
	// -------------------------------------------------------------------------

	/**
	 * Hook target for show_user_profile/edit_user_profile.
	 *
	 * @param WP_User $user Profile being viewed.
	 */
	public function render_profile_section( $user ) {
		$is_own_profile = get_current_user_id() === $user->ID;
		?>
		<h2><?php esc_html_e( 'Two-Factor Authentication', 'adc-security' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th><?php esc_html_e( 'Status', 'adc-security' ); ?></th>
				<td>
					<?php if ( $is_own_profile ) : ?>
						<?php $this->render_enrollment_panel( $user->ID ); ?>
					<?php else : ?>
						<?php if ( $this->is_enabled( $user->ID ) ) : ?>
							<p><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Enabled', 'adc-security' ); ?></p>
							<?php if ( current_user_can( 'manage_options' ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<input type="hidden" name="action" value="adc_security_2fa_disable">
									<input type="hidden" name="target_user_id" value="<?php echo (int) $user->ID; ?>">
									<?php wp_nonce_field( 'adc_security_2fa_disable_' . $user->ID ); ?>
									<button type="submit" class="button button-secondary" onclick="return confirm('<?php echo esc_js( __( 'Disable two-factor authentication for this user?', 'adc-security' ) ); ?>');"><?php esc_html_e( 'Disable 2FA for this user', 'adc-security' ); ?></button>
								</form>
							<?php endif; ?>
						<?php else : ?>
							<p><span class="dashicons dashicons-warning"></span> <?php esc_html_e( 'Not enabled.', 'adc-security' ); ?></p>
						<?php endif; ?>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
	}

	/**
	 * Renders the full enrollment panel: status, generate/confirm form, or
	 * disable/regenerate controls. Used both on the user's own profile screen
	 * and on the plugin's "Two-Factor Auth" tab.
	 *
	 * @param int $user_id User ID (always the currently logged-in user).
	 */
	public function render_enrollment_panel( $user_id ) {
		if ( get_current_user_id() !== (int) $user_id ) {
			return;
		}

		$new_codes = get_transient( 'adc_2fa_new_codes_' . $user_id );
		if ( $new_codes ) {
			delete_transient( 'adc_2fa_new_codes_' . $user_id );
			?>
			<div class="notice notice-success inline">
				<p><strong><?php esc_html_e( 'Save these recovery codes now — they will not be shown again.', 'adc-security' ); ?></strong></p>
				<p>
					<?php esc_html_e( 'Each code can be used once to sign in if you lose access to your authenticator app.', 'adc-security' ); ?>
				</p>
				<code style="display:block; white-space:pre-wrap; padding:10px; background:#f6f7f7; border:1px solid #ddd;"><?php echo esc_html( implode( "\n", $new_codes ) ); ?></code>
			</div>
			<?php
		}

		if ( isset( $_GET['adc_2fa_error'] ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'That code did not match. Please try again.', 'adc-security' ) . '</p></div>';
		}

		if ( $this->is_enabled( $user_id ) ) {
			?>
			<p><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Two-factor authentication is enabled on your account.', 'adc-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block; margin-right:8px;">
				<input type="hidden" name="action" value="adc_security_2fa_regenerate_codes">
				<?php wp_nonce_field( 'adc_security_2fa_regenerate_codes' ); ?>
				<button type="submit" class="button button-secondary" onclick="return confirm('<?php echo esc_js( __( 'Generate new recovery codes? The old ones will stop working.', 'adc-security' ) ); ?>');"><?php esc_html_e( 'Regenerate Recovery Codes', 'adc-security' ); ?></button>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block;">
				<input type="hidden" name="action" value="adc_security_2fa_disable">
				<?php wp_nonce_field( 'adc_security_2fa_disable_' . $user_id ); ?>
				<button type="submit" class="button button-link-delete" onclick="return confirm('<?php echo esc_js( __( 'Disable two-factor authentication on your account?', 'adc-security' ) ); ?>');"><?php esc_html_e( 'Disable 2FA', 'adc-security' ); ?></button>
			</form>
			<?php
			return;
		}

		$pending_secret = $this->get_pending_secret( $user_id );

		if ( '' === $pending_secret ) {
			?>
			<p><?php esc_html_e( 'Two-factor authentication is not enabled on your account.', 'adc-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="adc_security_2fa_generate">
				<?php wp_nonce_field( 'adc_security_2fa_generate' ); ?>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Enable Two-Factor Authentication', 'adc-security' ); ?></button>
			</form>
			<?php
			return;
		}

		$user       = get_userdata( $user_id );
		$account    = $user ? $user->user_email : '';
		$issuer     = get_bloginfo( 'name' );
		$otpauthUri = ADC_Security_Totp::provisioning_uri( $pending_secret, $account, $issuer );
		?>
		<p><?php esc_html_e( 'Scan this into your authenticator app (Google Authenticator, Aegis, 1Password, etc.), or enter the key manually, then confirm with the 6-digit code it shows.', 'adc-security' ); ?></p>
		<p>
			<?php esc_html_e( 'Manual key:', 'adc-security' ); ?>
			<code><?php echo esc_html( chunk_split( $pending_secret, 4, ' ' ) ); ?></code>
		</p>
		<p>
			<a href="<?php echo esc_url( $otpauthUri ); ?>"><?php esc_html_e( 'Open in authenticator app', 'adc-security' ); ?></a>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
			<input type="hidden" name="action" value="adc_security_2fa_confirm">
			<?php wp_nonce_field( 'adc_security_2fa_confirm' ); ?>
			<label for="adc_2fa_confirm_code"><?php esc_html_e( 'Confirmation code', 'adc-security' ); ?></label>
			<input type="text" name="adc_2fa_confirm_code" id="adc_2fa_confirm_code" inputmode="numeric" autocomplete="one-time-code" size="10">
			<button type="submit" class="button button-primary"><?php esc_html_e( 'Confirm & Enable', 'adc-security' ); ?></button>
		</form>
		<?php
	}

	// -------------------------------------------------------------------------
	// Enrollment handlers
	// -------------------------------------------------------------------------

	public function handle_generate() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'adc-security' ), 403 );
		}
		check_admin_referer( 'adc_security_2fa_generate' );

		$user_id = get_current_user_id();
		$secret  = ADC_Security_Totp::generate_secret();
		update_user_meta( $user_id, self::META_PENDING_SECRET, self::encrypt( $secret ) );

		$this->redirect_back();
	}

	public function handle_confirm() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'adc-security' ), 403 );
		}
		check_admin_referer( 'adc_security_2fa_confirm' );

		$user_id = get_current_user_id();
		$secret  = $this->get_pending_secret( $user_id );
		$code    = isset( $_POST['adc_2fa_confirm_code'] ) ? sanitize_text_field( wp_unslash( $_POST['adc_2fa_confirm_code'] ) ) : '';

		if ( '' === $secret || ! ADC_Security_Totp::verify( $secret, $code ) ) {
			$this->redirect_back( array( 'adc_2fa_error' => '1' ) );
		}

		update_user_meta( $user_id, self::META_SECRET, self::encrypt( $secret ) );
		delete_user_meta( $user_id, self::META_PENDING_SECRET );
		update_user_meta( $user_id, self::META_ENABLED, 1 );
		delete_user_meta( $user_id, self::META_REQUIRED_SINCE );

		$codes = $this->generate_recovery_codes( $user_id );
		set_transient( 'adc_2fa_new_codes_' . $user_id, $codes, MINUTE_IN_SECONDS );

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log( '2fa_enabled', ADC_Security_Events::SEVERITY_NOTICE, array( 'user_id' => $user_id ) );
		}

		$this->redirect_back();
	}

	public function handle_disable() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'adc-security' ), 403 );
		}

		$target_user_id = isset( $_POST['target_user_id'] ) ? (int) $_POST['target_user_id'] : get_current_user_id();
		$current_id     = get_current_user_id();

		if ( $target_user_id !== $current_id && ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do that.', 'adc-security' ), 403 );
		}

		check_admin_referer( 'adc_security_2fa_disable_' . $target_user_id );

		delete_user_meta( $target_user_id, self::META_SECRET );
		delete_user_meta( $target_user_id, self::META_PENDING_SECRET );
		delete_user_meta( $target_user_id, self::META_ENABLED );
		delete_user_meta( $target_user_id, self::META_RECOVERY_CODES );

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log( '2fa_disabled', ADC_Security_Events::SEVERITY_NOTICE, array( 'user_id' => $target_user_id ) );
		}

		$this->redirect_back();
	}

	public function handle_regenerate_codes() {
		if ( ! is_user_logged_in() ) {
			wp_die( esc_html__( 'You must be logged in.', 'adc-security' ), 403 );
		}
		check_admin_referer( 'adc_security_2fa_regenerate_codes' );

		$user_id = get_current_user_id();
		if ( ! $this->is_enabled( $user_id ) ) {
			$this->redirect_back();
		}

		$codes = $this->generate_recovery_codes( $user_id );
		set_transient( 'adc_2fa_new_codes_' . $user_id, $codes, MINUTE_IN_SECONDS );

		$this->redirect_back();
	}

	/**
	 * Redirect back to wherever the enrollment form was rendered.
	 *
	 * @param array $extra_args Extra query args to append.
	 */
	private function redirect_back( array $extra_args = array() ) {
		$referer = wp_get_referer();
		$target  = $referer ? $referer : admin_url( 'profile.php' );

		if ( $extra_args ) {
			$target = add_query_arg( $extra_args, $target );
		}

		wp_safe_redirect( $target );
		exit;
	}

	// -------------------------------------------------------------------------
	// Login flow
	// -------------------------------------------------------------------------

	/**
	 * @param WP_User|WP_Error|null $user     Result so far from earlier authenticate callbacks.
	 * @param string                $username Submitted username.
	 * @param string                $password Submitted password.
	 * @return WP_User|WP_Error|null
	 */
	public function maybe_challenge_2fa( $user, $username, $password ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		if ( ! $this->is_enabled( $user->ID ) ) {
			return $user;
		}

		$token = wp_generate_password( 32, false, false );
		set_transient(
			'adc_2fa_pending_' . $token,
			array(
				'user_id'  => $user->ID,
				'remember' => ! empty( $_POST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification.Missing -- first-factor password auth already validated by WordPress core at this point.
			),
			5 * MINUTE_IN_SECONDS
		);

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		wp_safe_redirect(
			add_query_arg(
				array(
					'action'      => self::LOGIN_ACTION,
					'token'       => $token,
					'redirect_to' => rawurlencode( $redirect_to ),
				),
				wp_login_url()
			)
		);
		exit;
	}

	/**
	 * Renders and processes the second-step (TOTP code) login screen.
	 * Registered on login_form_adc_2fa so it fully replaces wp-login.php's
	 * default handling for this custom action.
	 */
	public function handle_2fa_challenge() {
		$token   = isset( $_REQUEST['token'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['token'] ) ) : '';
		$pending = $token ? get_transient( 'adc_2fa_pending_' . $token ) : false;

		if ( ! $pending || empty( $pending['user_id'] ) ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user_id = (int) $pending['user_id'];
		$error   = '';

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'adc_security_2fa_verify' );

			$fail_key = 'adc_2fa_fail_' . md5( $user_id . '|' . $this->get_client_ip() );
			$fails    = (int) get_transient( $fail_key );

			if ( $fails >= 5 ) {
				$error = __( 'Too many invalid codes. Please wait a few minutes and log in again.', 'adc-security' );
			} else {
				$ok = false;

				if ( ! empty( $_POST['adc_2fa_recovery_code'] ) ) {
					$ok = $this->verify_recovery_code( $user_id, sanitize_text_field( wp_unslash( $_POST['adc_2fa_recovery_code'] ) ) );
				} elseif ( ! empty( $_POST['adc_2fa_code'] ) ) {
					$secret = $this->get_secret( $user_id );
					$ok     = $secret && ADC_Security_Totp::verify( $secret, sanitize_text_field( wp_unslash( $_POST['adc_2fa_code'] ) ) );
				}

				if ( $ok ) {
					delete_transient( 'adc_2fa_pending_' . $token );
					delete_transient( $fail_key );

					$user = get_user_by( 'id', $user_id );
					wp_set_current_user( $user_id );
					wp_set_auth_cookie( $user_id, ! empty( $pending['remember'] ) );
					do_action( 'wp_login', $user->user_login, $user );
					do_action( 'adc_security_2fa_success', $user_id );

					$redirect_to = isset( $_REQUEST['redirect_to'] ) ? esc_url_raw( wp_unslash( $_REQUEST['redirect_to'] ) ) : admin_url();
					wp_safe_redirect( $redirect_to );
					exit;
				}

				set_transient( $fail_key, $fails + 1, 15 * MINUTE_IN_SECONDS );
				if ( class_exists( 'ADC_Security_Events' ) ) {
					ADC_Security_Events::log( '2fa_failed', ADC_Security_Events::SEVERITY_WARNING, array( 'user_id' => $user_id ) );
				}
				$error = __( 'Invalid code. Please try again.', 'adc-security' );
			}
		}

		$this->render_2fa_challenge_form( $token, $error );
		exit;
	}

	/**
	 * @param string $token Pending-login token.
	 * @param string $error Error message to display, if any.
	 */
	private function render_2fa_challenge_form( $token, $error ) {
		login_header( __( 'Two-Factor Authentication', 'adc-security' ), '', $error ? new WP_Error( 'adc_2fa_invalid', $error ) : null );

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action_url  = add_query_arg(
			array(
				'action' => self::LOGIN_ACTION,
				'token'  => $token,
			),
			wp_login_url()
		);
		?>
		<form name="adc2faform" id="adc2faform" action="<?php echo esc_url( $action_url ); ?>" method="post">
			<p>
				<label for="adc_2fa_code"><?php esc_html_e( 'Authentication code', 'adc-security' ); ?></label>
				<input type="text" name="adc_2fa_code" id="adc_2fa_code" class="input" inputmode="numeric" autocomplete="one-time-code" value="" size="20" autofocus>
			</p>
			<p>
				<label for="adc_2fa_recovery_code"><?php esc_html_e( 'Or a recovery code', 'adc-security' ); ?></label>
				<input type="text" name="adc_2fa_recovery_code" id="adc_2fa_recovery_code" class="input" value="" size="20">
			</p>
			<?php wp_nonce_field( 'adc_security_2fa_verify' ); ?>
			<?php if ( $redirect_to ) : ?>
				<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>">
			<?php endif; ?>
			<p class="submit">
				<input type="submit" name="wp-submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Verify', 'adc-security' ); ?>">
			</p>
		</form>
		<p id="backtoblog">
			<a href="<?php echo esc_url( home_url( '/' ) ); ?>"><?php echo esc_html( sprintf( '&larr; %s', get_bloginfo( 'name', 'display' ) ) ); ?></a>
		</p>
		<?php
		login_footer();
	}

	/**
	 * @return string
	 */
	private function get_client_ip() {
		return ADC_Security_Ip::get_client_ip();
	}

	// -------------------------------------------------------------------------
	// Enforcement (required roles + grace period)
	// -------------------------------------------------------------------------

	public function enforce_grace_period() {
		if ( wp_doing_ajax() || wp_doing_cron() ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! $user || ! $user->exists() || $this->is_enabled( $user->ID ) ) {
			return;
		}

		$options        = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		$required_roles = isset( $options['2fa_required_roles'] ) && is_array( $options['2fa_required_roles'] ) ? $options['2fa_required_roles'] : array();

		if ( empty( $required_roles ) || ! array_intersect( $required_roles, (array) $user->roles ) ) {
			return;
		}

		$first_seen = (int) get_user_meta( $user->ID, self::META_REQUIRED_SINCE, true );
		if ( ! $first_seen ) {
			$first_seen = time();
			update_user_meta( $user->ID, self::META_REQUIRED_SINCE, $first_seen );
		}

		$grace_days = isset( $options['2fa_grace_days'] ) ? (int) $options['2fa_grace_days'] : 0;
		if ( time() < $first_seen + ( $grace_days * DAY_IN_SECONDS ) ) {
			return;
		}

		global $pagenow;
		if ( in_array( $pagenow, array( 'admin-ajax.php', 'admin-post.php' ), true ) ) {
			return;
		}
		if ( 'admin.php' === $pagenow && isset( $_GET['page'] ) && 'adc-security' === $_GET['page'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'             => 'adc-security',
					'tab'              => '2fa',
					'adc_2fa_required' => '1',
				),
				admin_url( 'admin.php' )
			)
		);
		exit;
	}

	/**
	 * @param bool    $available Whether Application Passwords are available for the user.
	 * @param WP_User $user      The user in question.
	 * @return bool
	 */
	public function maybe_block_application_passwords( $available, $user ) {
		if ( ! $available || ! ( $user instanceof WP_User ) ) {
			return $available;
		}

		$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );
		if ( empty( $options['2fa_disable_application_passwords'] ) ) {
			return $available;
		}

		$required_roles = isset( $options['2fa_required_roles'] ) && is_array( $options['2fa_required_roles'] ) ? $options['2fa_required_roles'] : array();
		if ( empty( $required_roles ) || ! array_intersect( $required_roles, (array) $user->roles ) ) {
			return $available;
		}

		return false;
	}

	// -------------------------------------------------------------------------
	// Password policy (minimum length + common-password blocklist)
	// -------------------------------------------------------------------------

	/**
	 * @param WP_Error $errors WP_Error to append to.
	 * @param bool     $update Whether this is an existing user being updated.
	 * @param stdClass $user   Raw user object being saved (has ->user_pass when a new password was submitted).
	 */
	public function validate_password_policy_profile( $errors, $update, $user ) {
		if ( empty( $user->user_pass ) ) {
			return;
		}
		$this->check_password_policy( $user->user_pass, $errors );
	}

	/**
	 * @param WP_Error $errors WP_Error to append to.
	 * @param WP_User  $user   User whose password is being reset.
	 */
	public function validate_password_policy_reset( $errors, $user ) {
		if ( ! isset( $_POST['pass1'] ) || '' === $_POST['pass1'] ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- core's own reset-password nonce already gates this handler.
			return;
		}
		$this->check_password_policy( wp_unslash( $_POST['pass1'] ), $errors ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
	}

	/**
	 * @param string   $password Candidate plaintext password.
	 * @param WP_Error $errors   WP_Error to append violations to.
	 */
	private function check_password_policy( $password, WP_Error $errors ) {
		$options = get_option( ADC_Security_Settings::OPTION_NAME, array() );

		$min_length = isset( $options['password_min_length'] ) ? (int) $options['password_min_length'] : 0;
		if ( $min_length > 0 && strlen( $password ) < $min_length ) {
			$errors->add(
				'adc_security_password_too_short',
				sprintf(
					/* translators: %d: minimum password length */
					__( '<strong>Error</strong>: Password must be at least %d characters long.', 'adc-security' ),
					$min_length
				)
			);
		}

		if ( ! empty( $options['password_block_common'] ) && self::is_common_password( $password ) ) {
			$errors->add(
				'adc_security_password_too_common',
				__( '<strong>Error</strong>: That password is on a list of commonly leaked passwords and cannot be used.', 'adc-security' )
			);
		}
	}

	/**
	 * @param string $password
	 * @return bool
	 */
	private static function is_common_password( $password ) {
		static $common = array(
			'123456', '123456789', 'qwerty', 'password', '12345', '12345678',
			'111111', '1234567', 'sunshine', 'qwerty123', 'iloveyou', '000000',
			'1q2w3e4r5t', 'admin', 'admin123', 'welcome', 'monkey', 'login',
			'abc123', 'starwars', 'dragon', 'passw0rd', 'master', 'hello',
			'freedom', 'whatever', 'qazwsx', 'trustno1', 'letmein', '1qaz2wsx',
			'football', 'baseball', 'access', 'shadow', 'superman', 'michael',
			'password1', 'password123', 'qwertyuiop', '123123', 'test1234',
			'changeme', 'p@ssw0rd', 'wordpress', 'administrator',
		);

		return in_array( strtolower( $password ), $common, true );
	}
}
