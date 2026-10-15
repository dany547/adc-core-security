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
 * Concurrency note: the per-user lock (acquire_user_lock) is built on
 * add_option(), which is atomic at the database level for a unique option
 * name. Counters that are read-modify-written without that lock (the per-IP
 * and per-user failure counters) can undercount under heavy parallel load.
 * That is acceptable: the limits are a brake, not an exact quota.
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
	const META_LAST_STEP      = 'adc_2fa_last_step';

	const LOGIN_ACTION   = 'adc_2fa';
	const PENDING_COOKIE = 'adc_2fa_pending';

	const PENDING_TTL        = 300; // Seconds a pending login token lives.
	const PENDING_MAX_FAILS  = 5;   // Failures before a pending token is destroyed.
	const USER_FAIL_LIMIT    = 10;  // Failures across all IPs per user...
	const USER_FAIL_WINDOW   = 900; // ...within this many seconds.
	const USER_FAIL_PREFIX   = 'adc_2fa_user_fail_';
	const LOCK_TTL           = 10;  // Seconds before a stale per-user lock is broken.

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
		return $this->read_encrypted_meta( $user_id, self::META_SECRET );
	}

	/**
	 * @param int $user_id
	 * @return string Decrypted Base32 pending secret, or '' if none.
	 */
	private function get_pending_secret( $user_id ) {
		return $this->read_encrypted_meta( $user_id, self::META_PENDING_SECRET );
	}

	/**
	 * Read and decrypt an encrypted secret meta value. A value still in the
	 * legacy ciphertext format is transparently re-encrypted to the current
	 * format on successful read.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $meta_key Meta key holding the ciphertext.
	 * @return string Plaintext, or '' if missing or undecryptable.
	 */
	private function read_encrypted_meta( $user_id, $meta_key ) {
		$encrypted = get_user_meta( $user_id, $meta_key, true );
		if ( ! $encrypted ) {
			return '';
		}

		$encrypted = (string) $encrypted;
		$plain     = self::decrypt( $encrypted );
		if ( '' !== $plain && self::is_legacy_ciphertext( $encrypted ) ) {
			update_user_meta( $user_id, $meta_key, self::encrypt( $plain ) );
		}

		return $plain;
	}

	/**
	 * Check a submitted TOTP code for a user during login (or re-auth) and,
	 * on success, record its time step so it cannot be replayed.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted authenticator code.
	 * @return bool
	 */
	private function verify_totp_for_user( $user_id, $code ) {
		$secret = $this->get_secret( $user_id );
		if ( '' === $secret ) {
			return false;
		}

		return $this->consume_totp_step( $user_id, $secret, $code );
	}

	/**
	 * Verify a TOTP code against a secret and atomically reject it if its
	 * time step was already accepted (RFC 6238 section 5.2). The check and the
	 * update of META_LAST_STEP happen under the per-user lock so two parallel
	 * requests cannot both accept the same code.
	 *
	 * @param int    $user_id User ID.
	 * @param string $secret  Base32 secret (pending or active).
	 * @param string $code    Submitted code.
	 * @return bool
	 */
	private function consume_totp_step( $user_id, $secret, $code ) {
		$step = ADC_Security_Totp::verify_step( $secret, $code );
		if ( false === $step ) {
			return false;
		}

		$lock = $this->acquire_user_lock( $user_id );
		if ( '' === $lock ) {
			return false;
		}

		wp_cache_delete( $user_id, 'user_meta' );
		$last_step = (int) get_user_meta( $user_id, self::META_LAST_STEP, true );
		$ok        = $step > $last_step;
		if ( $ok ) {
			update_user_meta( $user_id, self::META_LAST_STEP, $step );
		}

		$this->release_user_lock( $lock );

		return $ok;
	}

	/**
	 * Verify a submitted single-use recovery code, consuming it on success.
	 * Serialized with the per-user lock so two concurrent requests cannot
	 * both consume the same code. Logs and emails the user on success.
	 *
	 * @param int    $user_id User ID.
	 * @param string $code    Submitted recovery code.
	 * @return bool
	 */
	private function verify_recovery_code( $user_id, $code ) {
		// Normalize to the stored XXXX-XXXX shape, tolerating case, spaces and a missing hyphen.
		$normalized = strtoupper( preg_replace( '/[^A-Za-z0-9]/', '', (string) $code ) );
		if ( 8 !== strlen( $normalized ) ) {
			return false;
		}
		$code = substr( $normalized, 0, 4 ) . '-' . substr( $normalized, 4 );

		$lock = $this->acquire_user_lock( $user_id );
		if ( '' === $lock ) {
			return false;
		}

		wp_cache_delete( $user_id, 'user_meta' );
		$hashes = get_user_meta( $user_id, self::META_RECOVERY_CODES, true );
		$ok     = false;

		if ( is_array( $hashes ) ) {
			foreach ( $hashes as $index => $hash ) {
				if ( wp_check_password( $code, $hash, $user_id ) ) {
					unset( $hashes[ $index ] );
					$hashes = array_values( $hashes );
					update_user_meta( $user_id, self::META_RECOVERY_CODES, $hashes );
					$ok = true;
					break;
				}
			}
		}

		$this->release_user_lock( $lock );

		if ( ! $ok ) {
			return false;
		}

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				'2fa_recovery_used',
				ADC_Security_Events::SEVERITY_WARNING,
				array(
					'user_id' => $user_id,
					'ip'      => ADC_Security_Ip::get_client_ip(),
					'context' => array( 'remaining' => count( $hashes ) ),
				)
			);
		}

		$this->send_security_email(
			$user_id,
			sprintf(
				/* translators: %s: site name */
				__( '[%s] A two-factor recovery code was used', 'adc-security' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			),
			sprintf(
				/* translators: 1: date and time, 2: IP address, 3: number of unused recovery codes left */
				__( "A two-factor recovery code was used to sign in to your account.\n\nTime: %1\$s\nIP address: %2\$s\nUnused recovery codes remaining: %3\$d\n\nIf this was not you, change your password immediately and review your account.", 'adc-security' ),
				wp_date( 'Y-m-d H:i:s T' ),
				ADC_Security_Ip::get_client_ip(),
				count( $hashes )
			)
		);

		return true;
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
	// Per-user lock (add_option is atomic: exactly one request can create it)
	// -------------------------------------------------------------------------

	/**
	 * @param int $user_id User ID.
	 * @return string Lock option name when acquired, '' when another request holds it.
	 */
	private function acquire_user_lock( $user_id ) {
		$key = 'adc_2fa_lock_' . (int) $user_id;

		if ( add_option( $key, time(), '', 'no' ) ) {
			return $key;
		}

		// Break a lock left behind by a request that died mid-flight.
		$started = (int) get_option( $key );
		if ( $started && ( time() - $started ) > self::LOCK_TTL ) {
			delete_option( $key );
			if ( add_option( $key, time(), '', 'no' ) ) {
				return $key;
			}
		}

		return '';
	}

	/**
	 * @param string $lock Lock name returned by acquire_user_lock().
	 */
	private function release_user_lock( $lock ) {
		delete_option( $lock );
	}

	// -------------------------------------------------------------------------
	// Per-user failure limiter (across all IPs)
	// -------------------------------------------------------------------------

	/**
	 * @param int $user_id User ID.
	 * @return array{count:int,start:int}
	 */
	private function get_user_fail_state( $user_id ) {
		$state = get_transient( self::USER_FAIL_PREFIX . (int) $user_id );
		if ( is_array( $state ) && isset( $state['count'], $state['start'] ) ) {
			return $state;
		}
		return array(
			'count' => 0,
			'start' => 0,
		);
	}

	/**
	 * @param int $user_id User ID.
	 * @return bool True while the user has hit the failure limit in the current window.
	 */
	private function is_user_locked( $user_id ) {
		$state = $this->get_user_fail_state( $user_id );
		return $state['count'] >= self::USER_FAIL_LIMIT && ( time() - $state['start'] ) < self::USER_FAIL_WINDOW;
	}

	/**
	 * Record one failed 2FA attempt for a user. The window starts at the first
	 * failure and ends USER_FAIL_WINDOW seconds later. Logs '2fa_locked' once,
	 * when the limit is first reached.
	 *
	 * @param int $user_id User ID.
	 */
	private function register_user_failure( $user_id ) {
		$user_id = (int) $user_id;
		$now     = time();
		$state   = $this->get_user_fail_state( $user_id );

		if ( 0 === $state['count'] || ( $now - $state['start'] ) >= self::USER_FAIL_WINDOW ) {
			$state = array(
				'count' => 0,
				'start' => $now,
			);
		}

		$state['count']++;
		$ttl = max( 1, self::USER_FAIL_WINDOW - ( $now - $state['start'] ) );
		set_transient( self::USER_FAIL_PREFIX . $user_id, $state, $ttl );

		if ( self::USER_FAIL_LIMIT === $state['count'] && class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				'2fa_locked',
				ADC_Security_Events::SEVERITY_WARNING,
				array(
					'user_id' => $user_id,
					'ip'      => ADC_Security_Ip::get_client_ip(),
					'context' => array( 'window_seconds' => self::USER_FAIL_WINDOW ),
				)
			);
		}
	}

	// -------------------------------------------------------------------------
	// Notifications
	// -------------------------------------------------------------------------

	/**
	 * Plain-text security email to a user. Delivery failures are intentionally
	 * ignored so mail problems never block a login or an admin action.
	 *
	 * @param int    $user_id User ID.
	 * @param string $subject Subject line.
	 * @param string $body    Plain-text body. Must never contain codes or secrets.
	 */
	private function send_security_email( $user_id, $subject, $body ) {
		$user = get_userdata( (int) $user_id );
		if ( ! $user || '' === $user->user_email ) {
			return;
		}

		wp_mail( $user->user_email, $subject, $body );
	}

	// -------------------------------------------------------------------------
	// Encryption (AUTH/SECURE_AUTH salts derive the key; rotating those salts
	// invalidates stored secrets, same trade-off as any salt-derived secret).
	//
	// Current format ("v2"): key = HMAC-SHA256 over the salts, keyed with a
	// fixed label. Ciphertext prefixes:
	//   sodium2:   libsodium secretbox (authenticated by design).
	//   openssl2:  AES-256-CBC, random IV, encrypt-then-MAC with HMAC-SHA256.
	// Legacy format (read-only, auto-migrated on read): 'sodium:' / 'openssl:'
	// with key = SHA-256 over the salts plus a label.
	// -------------------------------------------------------------------------

	/**
	 * @return string 32-byte binary key (v2).
	 */
	private static function get_encryption_key() {
		return hash_hmac( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ), 'adc-security-totp-v2', true );
	}

	/**
	 * @return string 32-byte binary key used by the legacy formats.
	 */
	private static function get_legacy_encryption_key() {
		return hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ) . '|adc-security-totp', true );
	}

	/**
	 * Independent MAC key derived from the encryption key.
	 *
	 * @param string $key 32-byte encryption key.
	 * @return string 32-byte binary key.
	 */
	private static function get_mac_key( $key ) {
		return hash_hmac( 'sha256', 'adc-security-totp-mac', $key, true );
	}

	/**
	 * @param string $plaintext
	 * @return string
	 */
	public static function encrypt( $plaintext ) {
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			return self::encrypt_sodium_v2( $plaintext );
		}
		return self::encrypt_openssl_v2( $plaintext );
	}

	/**
	 * @param string $plaintext
	 * @return string
	 */
	private static function encrypt_sodium_v2( $plaintext ) {
		$nonce      = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$ciphertext = sodium_crypto_secretbox( $plaintext, $nonce, self::get_encryption_key() );
		return 'sodium2:' . base64_encode( $nonce . $ciphertext ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
	}

	/**
	 * @param string $plaintext
	 * @return string
	 */
	private static function encrypt_openssl_v2( $plaintext ) {
		$key        = self::get_encryption_key();
		$iv         = random_bytes( 16 );
		$ciphertext = openssl_encrypt( $plaintext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
		$tag        = hash_hmac( 'sha256', $iv . $ciphertext, self::get_mac_key( $key ), true );
		return 'openssl2:' . base64_encode( $iv . $ciphertext . $tag ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
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

		if ( 'sodium2' === $mode ) {
			return self::decrypt_sodium( $raw, self::get_encryption_key() );
		}
		if ( 'openssl2' === $mode ) {
			return self::decrypt_openssl_v2( $raw, self::get_encryption_key() );
		}
		if ( 'sodium' === $mode ) {
			return self::decrypt_sodium( $raw, self::get_legacy_encryption_key() );
		}
		if ( 'openssl' === $mode ) {
			return self::decrypt_openssl_legacy( $raw, self::get_legacy_encryption_key() );
		}

		return '';
	}

	/**
	 * @param string $encoded Stored ciphertext.
	 * @return bool True when the value uses a pre-v2 format and should be re-encrypted.
	 */
	public static function is_legacy_ciphertext( $encoded ) {
		return 0 === strpos( (string) $encoded, 'sodium:' ) || 0 === strpos( (string) $encoded, 'openssl:' );
	}

	/**
	 * @param string $raw Decoded payload (nonce + ciphertext).
	 * @param string $key 32-byte key.
	 * @return string
	 */
	private static function decrypt_sodium( $raw, $key ) {
		if ( ! function_exists( 'sodium_crypto_secretbox_open' ) || strlen( $raw ) < SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return '';
		}
		$nonce      = substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$ciphertext = substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		$plain      = sodium_crypto_secretbox_open( $ciphertext, $nonce, $key );
		return false === $plain ? '' : $plain;
	}

	/**
	 * Verifies the MAC (constant-time) before decrypting.
	 *
	 * @param string $raw Decoded payload (iv + ciphertext + 32-byte tag).
	 * @param string $key 32-byte encryption key.
	 * @return string
	 */
	private static function decrypt_openssl_v2( $raw, $key ) {
		if ( strlen( $raw ) < 16 + 32 ) {
			return '';
		}
		$tag  = substr( $raw, -32 );
		$body = substr( $raw, 0, -32 );
		$iv   = substr( $body, 0, 16 );

		$expected = hash_hmac( 'sha256', $body, self::get_mac_key( $key ), true );
		if ( ! hash_equals( $expected, $tag ) ) {
			return '';
		}

		$plain = openssl_decrypt( substr( $body, 16 ), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
		return false === $plain ? '' : $plain;
	}

	/**
	 * Legacy 'openssl:' format (no MAC). Read-only, kept so existing secrets still work.
	 *
	 * @param string $raw Decoded payload (iv + ciphertext).
	 * @param string $key 32-byte legacy key.
	 * @return string
	 */
	private static function decrypt_openssl_legacy( $raw, $key ) {
		if ( strlen( $raw ) < 16 ) {
			return '';
		}
		$iv         = substr( $raw, 0, 16 );
		$ciphertext = substr( $raw, 16 );
		$plain      = openssl_decrypt( $ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv );
		return false === $plain ? '' : $plain;
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
								<?php $this->render_reauth_notice(); ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<input type="hidden" name="action" value="adc_security_2fa_disable">
									<input type="hidden" name="target_user_id" value="<?php echo (int) $user->ID; ?>">
									<?php wp_nonce_field( 'adc_security_2fa_disable_' . $user->ID ); ?>
									<p>
										<label for="adc_2fa_admin_password_<?php echo (int) $user->ID; ?>"><?php esc_html_e( 'Your administrator password (to confirm)', 'adc-security' ); ?></label><br>
										<input type="password" name="adc_2fa_admin_password" id="adc_2fa_admin_password_<?php echo (int) $user->ID; ?>" autocomplete="current-password" class="regular-text" required>
									</p>
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

		if ( isset( $_GET['adc_2fa_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'That code did not match. Please try again.', 'adc-security' ) . '</p></div>';
		}

		$this->render_reauth_notice();

		if ( $this->is_enabled( $user_id ) ) {
			?>
			<p><span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e( 'Two-factor authentication is enabled on your account.', 'adc-security' ); ?></p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block; margin-right:8px; vertical-align:top;">
				<input type="hidden" name="action" value="adc_security_2fa_regenerate_codes">
				<?php wp_nonce_field( 'adc_security_2fa_regenerate_codes' ); ?>
				<p>
					<label for="adc_2fa_regen_code"><?php esc_html_e( 'Current authenticator or recovery code', 'adc-security' ); ?></label><br>
					<input type="text" name="adc_2fa_reauth_code" id="adc_2fa_regen_code" class="regular-text" inputmode="text" autocomplete="one-time-code" size="20" required>
				</p>
				<button type="submit" class="button button-secondary" onclick="return confirm('<?php echo esc_js( __( 'Generate new recovery codes? The old ones will stop working.', 'adc-security' ) ); ?>');"><?php esc_html_e( 'Regenerate Recovery Codes', 'adc-security' ); ?></button>
			</form>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline-block; vertical-align:top;">
				<input type="hidden" name="action" value="adc_security_2fa_disable">
				<?php wp_nonce_field( 'adc_security_2fa_disable_' . $user_id ); ?>
				<p>
					<label for="adc_2fa_disable_code"><?php esc_html_e( 'Current authenticator or recovery code', 'adc-security' ); ?></label><br>
					<input type="text" name="adc_2fa_reauth_code" id="adc_2fa_disable_code" class="regular-text" inputmode="text" autocomplete="one-time-code" size="20" required>
				</p>
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

	/**
	 * Visible notice after a failed or rate-limited re-authentication. The
	 * message never says which part of the credential was wrong.
	 */
	private function render_reauth_notice() {
		$error = isset( $_GET['adc_2fa_reauth_error'] ) ? sanitize_key( wp_unslash( $_GET['adc_2fa_reauth_error'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( 'locked' === $error ) {
			$message = __( 'Too many failed verification attempts. Please wait 15 minutes and try again. Nothing was changed.', 'adc-security' );
		} elseif ( 'invalid' === $error ) {
			$message = __( 'We could not verify your identity, so nothing was changed. Check the code or password you entered and try again.', 'adc-security' );
		} else {
			return;
		}

		echo '<div class="notice notice-error inline"><p>' . esc_html( $message ) . '</p></div>';
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

		if ( '' === $secret || ! $this->consume_totp_step( $user_id, $secret, $code ) ) {
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

		$reauth_error = $this->check_reauth( $current_id, $target_user_id );
		if ( '' !== $reauth_error ) {
			$this->redirect_back( array( 'adc_2fa_reauth_error' => $reauth_error ) );
		}

		delete_user_meta( $target_user_id, self::META_SECRET );
		delete_user_meta( $target_user_id, self::META_PENDING_SECRET );
		delete_user_meta( $target_user_id, self::META_ENABLED );
		delete_user_meta( $target_user_id, self::META_RECOVERY_CODES );
		delete_user_meta( $target_user_id, self::META_LAST_STEP );

		if ( class_exists( 'ADC_Security_Events' ) ) {
			ADC_Security_Events::log(
				'2fa_disabled',
				ADC_Security_Events::SEVERITY_NOTICE,
				array(
					'user_id' => $target_user_id,
					'ip'      => ADC_Security_Ip::get_client_ip(),
					'context' => array( 'actor_user_id' => $current_id ),
				)
			);
		}

		$this->send_security_email(
			$target_user_id,
			sprintf(
				/* translators: %s: site name */
				__( '[%s] Two-factor authentication was disabled', 'adc-security' ),
				wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES )
			),
			sprintf(
				/* translators: 1: date and time, 2: IP address */
				__( "Two-factor authentication was disabled on your account.\n\nTime: %1\$s\nIP address: %2\$s\n\nIf you did not make this change, contact your site administrator and change your password.", 'adc-security' ),
				wp_date( 'Y-m-d H:i:s T' ),
				ADC_Security_Ip::get_client_ip()
			)
		);

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

		$reauth_error = $this->check_reauth( $user_id, $user_id );
		if ( '' !== $reauth_error ) {
			$this->redirect_back( array( 'adc_2fa_reauth_error' => $reauth_error ) );
		}

		$codes = $this->generate_recovery_codes( $user_id );
		set_transient( 'adc_2fa_new_codes_' . $user_id, $codes, MINUTE_IN_SECONDS );

		$this->redirect_back();
	}

	/**
	 * Re-authentication before a sensitive change.
	 *  - Acting on your own account: a current authenticator or recovery code.
	 *  - An administrator acting on another user: the administrator's own password.
	 * Failures count toward the limiter of the ACTING account (the credential
	 * owner), and a locked account is refused before any check runs.
	 *
	 * @param int $actor_id  Logged-in user performing the action.
	 * @param int $target_id User whose 2FA is being changed.
	 * @return string '' when verified, otherwise 'locked' or 'invalid'.
	 */
	private function check_reauth( $actor_id, $target_id ) {
		if ( $this->is_user_locked( $actor_id ) ) {
			return 'locked';
		}

		if ( (int) $target_id === (int) $actor_id ) {
			$input = isset( $_POST['adc_2fa_reauth_code'] ) ? sanitize_text_field( wp_unslash( $_POST['adc_2fa_reauth_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked by the calling handler.
			$ok    = $this->verify_second_factor( $actor_id, $input );
		} else {
			$password = isset( $_POST['adc_2fa_admin_password'] ) ? (string) wp_unslash( $_POST['adc_2fa_admin_password'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce checked by the calling handler.
			$admin    = get_userdata( $actor_id );
			$ok       = '' !== $password && $admin && wp_check_password( $password, $admin->user_pass, $actor_id );
		}

		if ( ! $ok ) {
			$this->register_user_failure( $actor_id );
			if ( class_exists( 'ADC_Security_Events' ) ) {
				ADC_Security_Events::log(
					'2fa_reauth_failed',
					ADC_Security_Events::SEVERITY_WARNING,
					array(
						'user_id' => $actor_id,
						'ip'      => ADC_Security_Ip::get_client_ip(),
						'context' => array( 'target_user_id' => (int) $target_id ),
					)
				);
			}
			return 'invalid';
		}

		return '';
	}

	/**
	 * Accepts either an authenticator code or a recovery code in one field.
	 * Recovery codes always contain a hyphen or letters, so the TOTP check runs
	 * first and the recovery check is the fallback.
	 *
	 * @param int    $user_id User ID.
	 * @param string $input   Submitted value.
	 * @return bool
	 */
	private function verify_second_factor( $user_id, $input ) {
		$input = trim( (string) $input );
		if ( '' === $input ) {
			return false;
		}

		if ( $this->verify_totp_for_user( $user_id, $input ) ) {
			return true;
		}

		return $this->verify_recovery_code( $user_id, $input );
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
				'fails'    => 0,
				'created'  => time(),
			),
			self::PENDING_TTL
		);
		$this->set_pending_cookie( $token );

		// The token travels in an HttpOnly cookie, not the URL. Only the
		// (non-secret) redirect target is placed in the query string, and
		// add_query_arg() performs the single encoding pass.
		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		wp_safe_redirect(
			add_query_arg(
				array(
					'action'      => self::LOGIN_ACTION,
					'redirect_to' => $redirect_to,
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
		$token   = $this->get_pending_token();
		$pending = $token ? get_transient( 'adc_2fa_pending_' . $token ) : false;

		if ( ! $pending || empty( $pending['user_id'] ) ) {
			$this->clear_pending_cookie();
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		$user_id = (int) $pending['user_id'];
		$error   = '';

		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) {
			check_admin_referer( 'adc_security_2fa_verify' );

			$fail_key = 'adc_2fa_fail_' . md5( $user_id . '|' . ADC_Security_Ip::get_client_ip() );
			$fails    = (int) get_transient( $fail_key );

			if ( $this->is_user_locked( $user_id ) ) {
				$this->invalidate_pending( $token );
				$error = __( 'Too many invalid codes for this account. Please wait a few minutes and log in again.', 'adc-security' );
			} elseif ( $fails >= 5 ) {
				$this->invalidate_pending( $token );
				$error = __( 'Too many invalid codes. Please wait a few minutes and log in again.', 'adc-security' );
			} else {
				$ok = false;

				if ( ! empty( $_POST['adc_2fa_recovery_code'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
					$ok = $this->verify_recovery_code( $user_id, sanitize_text_field( wp_unslash( $_POST['adc_2fa_recovery_code'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
				} elseif ( ! empty( $_POST['adc_2fa_code'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified above.
					$ok = $this->verify_totp_for_user( $user_id, sanitize_text_field( wp_unslash( $_POST['adc_2fa_code'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Missing
				}

				if ( $ok ) {
					delete_transient( 'adc_2fa_pending_' . $token );
					$this->clear_pending_cookie();
					delete_transient( $fail_key );

					$user = get_user_by( 'id', $user_id );
					wp_set_current_user( $user_id );
					wp_set_auth_cookie( $user_id, ! empty( $pending['remember'] ) );
					do_action( 'wp_login', $user->user_login, $user );
					do_action( 'adc_security_2fa_success', $user_id );

					if ( class_exists( 'ADC_Security_Events' ) ) {
						ADC_Security_Events::log(
							'2fa_success',
							ADC_Security_Events::SEVERITY_INFO,
							array(
								'user_id' => $user_id,
								'ip'      => ADC_Security_Ip::get_client_ip(),
							)
						);
					}

					$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					wp_safe_redirect( $redirect_to );
					exit;
				}

				set_transient( $fail_key, $fails + 1, 15 * MINUTE_IN_SECONDS );
				$this->register_user_failure( $user_id );

				if ( class_exists( 'ADC_Security_Events' ) ) {
					ADC_Security_Events::log( '2fa_failed', ADC_Security_Events::SEVERITY_WARNING, array( 'user_id' => $user_id ) );
				}

				$pending['fails'] = (int) ( $pending['fails'] ?? 0 ) + 1;
				if ( $pending['fails'] >= self::PENDING_MAX_FAILS ) {
					$this->invalidate_pending( $token );
					$error = __( 'Too many invalid codes. Please log in again.', 'adc-security' );
				} else {
					$created = isset( $pending['created'] ) ? (int) $pending['created'] : time();
					$ttl     = max( 1, self::PENDING_TTL - ( time() - $created ) );
					set_transient( 'adc_2fa_pending_' . $token, $pending, $ttl );
					$error = __( 'Invalid code. Please try again.', 'adc-security' );
				}
			}
		}

		$this->render_2fa_challenge_form( $error );
		exit;
	}

	/**
	 * @return string The pending-login token from the HttpOnly cookie, or '' if absent or malformed.
	 */
	private function get_pending_token() {
		$raw = isset( $_COOKIE[ self::PENDING_COOKIE ] ) ? sanitize_text_field( wp_unslash( $_COOKIE[ self::PENDING_COOKIE ] ) ) : '';
		return preg_match( '/^[A-Za-z0-9]{32}$/', $raw ) ? $raw : '';
	}

	/**
	 * @return string Cookie domain, or '' for the current host.
	 */
	private function cookie_domain() {
		return defined( 'COOKIE_DOMAIN' ) && COOKIE_DOMAIN ? COOKIE_DOMAIN : '';
	}

	/**
	 * @param string $token Pending-login token.
	 */
	private function set_pending_cookie( $token ) {
		setcookie(
			self::PENDING_COOKIE,
			$token,
			array(
				'expires'  => time() + self::PENDING_TTL,
				'path'     => COOKIEPATH,
				'domain'   => $this->cookie_domain(),
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	private function clear_pending_cookie() {
		setcookie(
			self::PENDING_COOKIE,
			'',
			array(
				'expires'  => time() - HOUR_IN_SECONDS,
				'path'     => COOKIEPATH,
				'domain'   => $this->cookie_domain(),
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	/**
	 * Destroys a pending-login token (after too many failures or a lock).
	 *
	 * @param string $token Pending-login token.
	 */
	private function invalidate_pending( $token ) {
		if ( '' !== $token ) {
			delete_transient( 'adc_2fa_pending_' . $token );
		}
		$this->clear_pending_cookie();
	}

	/**
	 * @param string $error Error message to display, if any.
	 */
	private function render_2fa_challenge_form( $error ) {
		login_header( __( 'Two-Factor Authentication', 'adc-security' ), '', $error ? new WP_Error( 'adc_2fa_invalid', $error ) : null );

		$redirect_to = isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action_url  = add_query_arg( array( 'action' => self::LOGIN_ACTION ), wp_login_url() );
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

		if ( ! empty( $options['password_check_hibp'] ) && self::is_pwned_password( $password ) ) {
			$errors->add(
				'adc_security_password_pwned',
				__( '<strong>Error</strong>: That password has appeared in a known data breach. Please choose a different one.', 'adc-security' )
			);
		}
	}

	/**
	 * Check a password against the Have I Been Pwned breached-password list
	 * using k-anonymity: only the first 5 characters of the SHA-1 hash are
	 * ever sent, so the API never sees the actual password. Fails open (does
	 * not block) on any network/API error, so an outage never locks users out.
	 *
	 * @param string $password Candidate plaintext password.
	 * @return bool
	 */
	private static function is_pwned_password( $password ) {
		$hash   = strtoupper( sha1( $password ) );
		$prefix = substr( $hash, 0, 5 );
		$suffix = substr( $hash, 5 );

		$response = wp_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout' => 4,
				'headers' => array( 'Add-Padding' => 'true' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		return self::suffix_found_in_range_response( $suffix, wp_remote_retrieve_body( $response ) );
	}

	/**
	 * Pure matcher for the HIBP range-API response body, split out so it can
	 * be unit tested without a WordPress environment (tests/test-hibp.php).
	 * Each line is "SUFFIX:COUNT"; a count of 0 marks decoy padding
	 * (Add-Padding: true) and must not be treated as a real match.
	 *
	 * @param string $suffix Uppercase 35-character SHA-1 suffix to look for.
	 * @param string $body   Raw HIBP range API response body.
	 * @return bool
	 */
	public static function suffix_found_in_range_response( $suffix, $body ) {
		foreach ( explode( "\n", $body ) as $line ) {
			$line = trim( $line );
			if ( '' === $line || false === strpos( $line, ':' ) ) {
				continue;
			}
			list( $candidate_suffix, $count ) = explode( ':', $line, 2 );
			if ( hash_equals( $suffix, trim( $candidate_suffix ) ) && (int) $count > 0 ) {
				return true;
			}
		}

		return false;
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
