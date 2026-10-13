<?php
/**
 * Content-Security-Policy builder.
 *
 * Pure PHP: this class must not call WordPress functions so it can be unit tested
 * without a WordPress installation.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Csp_Policy {

	/**
	 * Build the configured policy or the safe default policy.
	 *
	 * @param string $custom_policy Custom policy from the administrator.
	 * @param bool   $allow_dynamic_scripts Whether frontend dynamic compilation is enabled.
	 * @return string
	 */
	public function build( $custom_policy, $allow_dynamic_scripts = false ) {
		if ( ! empty( $custom_policy ) ) {
			return $custom_policy;
		}

		return $this->build_generated( array(), array(), array(), $allow_dynamic_scripts );
	}

	/**
	 * Build a policy from the default sources, service presets, and user edits.
	 *
	 * @param array  $presets           Preset keys from get_service_presets(). Unknown keys are ignored.
	 * @param array  $extra_sources     Directive => string[] sources added by the administrator.
	 * @param array  $removed_defaults  Directive => string[] default sources the administrator turned off.
	 * @param bool   $allow_dynamic_scripts Whether to add 'unsafe-eval' to script-src.
	 * @param string $report_uri        Optional https:// URI for CSP violation reports.
	 * @return string
	 */
	public function build_generated( array $presets, array $extra_sources, array $removed_defaults, $allow_dynamic_scripts = false, $report_uri = '' ) {
		$supported = self::get_directives();
		$map       = self::get_default_sources();
		$catalog   = self::get_service_presets();

		if ( $allow_dynamic_scripts ) {
			$map = self::add_sources( $map, 'script-src', array( "'unsafe-eval'" ) );
		}

		foreach ( $presets as $key ) {
			if ( ! is_string( $key ) || ! isset( $catalog[ $key ] ) ) {
				continue;
			}
			foreach ( $catalog[ $key ]['directives'] as $directive => $sources ) {
				$map = self::add_sources( $map, $directive, $sources );
			}
		}

		foreach ( $extra_sources as $directive => $sources ) {
			if ( ! is_string( $directive ) || ! in_array( $directive, $supported, true ) || ! is_array( $sources ) ) {
				continue;
			}
			$clean = array();
			foreach ( $sources as $source ) {
				$valid = self::sanitize_source( $source );
				if ( '' !== $valid ) {
					$clean[] = $valid;
				}
			}
			$map = self::add_sources( $map, $directive, $clean );
		}

		// Explicit removals win over presets and extras. 'self' is never removed from default-src.
		foreach ( $removed_defaults as $directive => $sources ) {
			if ( ! is_string( $directive ) || ! isset( $map[ $directive ] ) || ! is_array( $sources ) ) {
				continue;
			}
			foreach ( $sources as $source ) {
				$valid = self::sanitize_source( $source );
				if ( '' === $valid ) {
					continue;
				}
				if ( 'default-src' === $directive && "'self'" === $valid ) {
					continue;
				}
				$map[ $directive ] = array_values( array_diff( $map[ $directive ], array( $valid ) ) );
			}
		}

		$parts = array();
		foreach ( $supported as $directive ) {
			if ( ! isset( $map[ $directive ] ) ) {
				continue;
			}
			$list    = empty( $map[ $directive ] ) ? array( "'none'" ) : $map[ $directive ];
			$parts[] = $directive . ' ' . implode( ' ', $list );
		}

		$parts[] = "frame-ancestors 'self'";
		$parts[] = "base-uri 'self'";
		$parts[] = "form-action 'self'";
		$parts[] = "object-src 'none'";

		$report = self::sanitize_source( $report_uri );
		if ( '' !== $report && ( 0 === stripos( $report, 'https://' ) || 0 === stripos( $report, 'http://' ) ) ) {
			$parts[] = 'report-uri ' . $report;
		}

		return implode( '; ', $parts ) . ';';
	}

	/**
	 * Decide whether dynamic script compatibility can be used for this request.
	 *
	 * Fails closed for admin, login, REST, and malformed request paths.
	 *
	 * @param bool   $enabled Whether the administrator enabled compatibility.
	 * @param bool   $is_admin Whether WordPress considers this an admin request.
	 * @param string $request_uri Raw request URI.
	 * @return bool
	 */
	public function allows_dynamic_scripts( $enabled, $is_admin, $request_uri ) {
		if ( ! $enabled || $is_admin || ! is_string( $request_uri ) || '' === $request_uri ) {
			return false;
		}

		$path = parse_url( $request_uri, PHP_URL_PATH );
		if ( ! is_string( $path ) || '' === $path ) {
			return false;
		}

		$path = '/' . ltrim( strtolower( $path ), '/' );

		if ( '/wp-login.php' === $path || 0 === strpos( $path, '/wp-admin/' ) || '/wp-admin' === $path ) {
			return false;
		}

		if ( '/wp-json' === $path || 0 === strpos( $path, '/wp-json/' ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Directives an administrator may edit in the generated policy.
	 *
	 * frame-ancestors, base-uri, form-action and object-src are fixed.
	 *
	 * @return string[]
	 */
	public static function get_directives() {
		return array(
			'default-src',
			'script-src',
			'style-src',
			'img-src',
			'font-src',
			'connect-src',
			'frame-src',
			'media-src',
			'worker-src',
			'manifest-src',
		);
	}

	/**
	 * Sources used by the default policy, keyed by directive.
	 *
	 * @return array<string, string[]>
	 */
	public static function get_default_sources() {
		return array(
			'default-src' => array( "'self'" ),
			'script-src'  => array(
				"'self'",
				"'unsafe-inline'",
				'https://challenges.cloudflare.com',
				'https://www.googletagmanager.com',
				'https://googleads.g.doubleclick.net',
			),
			'style-src'   => array(
				"'self'",
				"'unsafe-inline'",
				'https://fonts.googleapis.com',
				'https://www.googletagmanager.com',
				'https://challenges.cloudflare.com',
			),
			'img-src'     => array( "'self'", 'data:', 'https:' ),
			'font-src'    => array( "'self'", 'data:', 'https://fonts.gstatic.com' ),
			'connect-src' => array(
				"'self'",
				'https:',
				'https://www.google-analytics.com',
				'https://region1.google-analytics.com',
				'https://analytics.google.com',
				'https://stats.g.doubleclick.net',
			),
			'frame-src'   => array(
				"'self'",
				'https://challenges.cloudflare.com',
				'https://maps.google.com',
				'https://www.google.com',
				'https://www.googletagmanager.com',
			),
		);
	}

	/**
	 * Service presets an administrator can enable with one click.
	 *
	 * @return array<string, array{label: string, description: string, directives: array<string, string[]>}>
	 */
	public static function get_service_presets() {
		return array(
			'gtm'            => array(
				'label'       => 'Google Tag Manager',
				'description' => 'Loads the GTM container script and its noscript iframe.',
				'directives'  => array(
					'script-src'  => array( 'https://www.googletagmanager.com' ),
					'connect-src' => array( 'https://www.googletagmanager.com' ),
					'frame-src'   => array( 'https://www.googletagmanager.com' ),
				),
			),
			'ga4'            => array(
				'label'       => 'Google Analytics 4',
				'description' => 'Sends GA4 measurement hits through gtag.js.',
				'directives'  => array(
					'script-src'  => array( 'https://www.googletagmanager.com' ),
					'connect-src' => array(
						'https://www.google-analytics.com',
						'https://region1.google-analytics.com',
						'https://analytics.google.com',
						'https://stats.g.doubleclick.net',
					),
				),
			),
			'google_ads'     => array(
				'label'       => 'Google Ads',
				'description' => 'Conversion tracking and remarketing tags.',
				'directives'  => array(
					'script-src'  => array(
						'https://www.googletagmanager.com',
						'https://www.googleadservices.com',
						'https://googleads.g.doubleclick.net',
						'https://pagead2.googlesyndication.com',
					),
					'connect-src' => array(
						'https://www.googleadservices.com',
						'https://googleads.g.doubleclick.net',
						'https://www.google.com',
					),
					'frame-src'   => array(
						'https://td.doubleclick.net',
						'https://googleads.g.doubleclick.net',
						'https://www.google.com',
					),
				),
			),
			'turnstile'      => array(
				'label'       => 'Cloudflare Turnstile',
				'description' => 'Turnstile widget script, iframe and verification requests.',
				'directives'  => array(
					'script-src'  => array( 'https://challenges.cloudflare.com' ),
					'connect-src' => array( 'https://challenges.cloudflare.com' ),
					'frame-src'   => array( 'https://challenges.cloudflare.com' ),
				),
			),
			'google_fonts'   => array(
				'label'       => 'Google Fonts',
				'description' => 'Google Fonts stylesheets and font files.',
				'directives'  => array(
					'style-src' => array( 'https://fonts.googleapis.com' ),
					'font-src'  => array( 'https://fonts.gstatic.com' ),
				),
			),
			'google_maps'    => array(
				'label'       => 'Google Maps',
				'description' => 'Maps JavaScript API and embedded maps.',
				'directives'  => array(
					'script-src'  => array( 'https://maps.googleapis.com', 'https://maps.gstatic.com' ),
					'connect-src' => array( 'https://maps.googleapis.com' ),
					'img-src'     => array( 'https://maps.gstatic.com', 'https://maps.googleapis.com' ),
					'frame-src'   => array( 'https://www.google.com', 'https://maps.google.com' ),
				),
			),
			'youtube'        => array(
				'label'       => 'YouTube',
				'description' => 'Embedded YouTube videos and the IFrame player API.',
				'directives'  => array(
					'script-src' => array( 'https://www.youtube.com', 'https://s.ytimg.com' ),
					'frame-src'  => array( 'https://www.youtube.com', 'https://www.youtube-nocookie.com' ),
					'img-src'    => array( 'https://i.ytimg.com' ),
				),
			),
			'vimeo'          => array(
				'label'       => 'Vimeo',
				'description' => 'Embedded Vimeo players.',
				'directives'  => array(
					'script-src' => array( 'https://player.vimeo.com' ),
					'frame-src'  => array( 'https://player.vimeo.com' ),
					'img-src'    => array( 'https://i.vimeocdn.com' ),
				),
			),
			'stripe'         => array(
				'label'       => 'Stripe',
				'description' => 'Stripe.js, Elements iframes and payment API calls.',
				'directives'  => array(
					'script-src'  => array( 'https://js.stripe.com' ),
					'frame-src'   => array( 'https://js.stripe.com', 'https://hooks.stripe.com' ),
					'connect-src' => array( 'https://api.stripe.com', 'https://m.stripe.network', 'https://q.stripe.com' ),
				),
			),
			'paypal'         => array(
				'label'       => 'PayPal',
				'description' => 'PayPal JavaScript SDK and checkout frames.',
				'directives'  => array(
					'script-src'  => array( 'https://www.paypal.com', 'https://www.paypalobjects.com' ),
					'frame-src'   => array( 'https://www.paypal.com' ),
					'connect-src' => array( 'https://www.paypal.com' ),
					'img-src'     => array( 'https://www.paypalobjects.com' ),
				),
			),
			'recaptcha'      => array(
				'label'       => 'Google reCAPTCHA',
				'description' => 'reCAPTCHA scripts, challenge frames and verification requests.',
				'directives'  => array(
					'script-src'  => array( 'https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/' ),
					'frame-src'   => array( 'https://www.google.com/recaptcha/' ),
					'connect-src' => array( 'https://www.google.com/recaptcha/' ),
				),
			),
			'facebook_pixel' => array(
				'label'       => 'Facebook Pixel',
				'description' => 'Meta Pixel script and event beacons.',
				'directives'  => array(
					'script-src'  => array( 'https://connect.facebook.net' ),
					'connect-src' => array( 'https://www.facebook.com' ),
					'img-src'     => array( 'https://www.facebook.com' ),
					'frame-src'   => array( 'https://www.facebook.com' ),
				),
			),
		);
	}

	/**
	 * Validate one CSP source expression.
	 *
	 * Accepts quoted keywords, nonce/hash tokens, scheme sources, host sources
	 * with optional scheme, wildcard subdomain, port and path, and the bare '*'.
	 *
	 * @param mixed $source Candidate source.
	 * @return string The normalised source, or '' when invalid.
	 */
	public static function sanitize_source( $source ) {
		if ( ! is_string( $source ) ) {
			return '';
		}

		if ( '' === $source || preg_match( '/[\x00-\x20\x7F-\xFF;,"<>\\\\]/', $source ) ) {
			return '';
		}

		if ( false !== strpos( $source, "'" ) ) {
			if ( preg_match( "#^'(self|none|unsafe-inline|unsafe-eval|strict-dynamic|wasm-unsafe-eval)'$#i", $source, $matches ) ) {
				return "'" . strtolower( $matches[1] ) . "'";
			}
			if ( preg_match( "#^'(nonce-[A-Za-z0-9+/_=-]+|sha(256|384|512)-[A-Za-z0-9+/_=-]+)'$#i", $source ) ) {
				return $source;
			}
			return '';
		}

		if ( '*' === $source ) {
			return '*';
		}

		if ( preg_match( '#^(https?|wss?|data|blob):$#i', $source ) ) {
			return strtolower( $source );
		}

		$label   = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
		$host    = '(?:(?:\*\.)?(?:' . $label . '\.)+' . $label . '|localhost)';
		$pattern = '#^((?:https?|wss?)://)?(' . $host . ')(?::(\d{1,5}|\*))?(/[A-Za-z0-9._~!$&()*+=:@%/-]*)?$#i';

		if ( ! preg_match( $pattern, $source, $matches ) ) {
			return '';
		}

		if ( isset( $matches[3] ) && is_numeric( $matches[3] ) && (int) $matches[3] > 65535 ) {
			return '';
		}

		return $source;
	}

	/**
	 * Normalise a policy typed by an administrator.
	 *
	 * Newlines are folded into spaces and control characters are removed, so the
	 * result can never carry a header-injection payload. Unknown directives,
	 * invalid sources and duplicate directives are dropped with a message each.
	 *
	 * @param mixed $raw Raw policy text.
	 * @return array{value: string, errors: string[]}
	 */
	public static function sanitize_policy( $raw ) {
		if ( ! is_string( $raw ) ) {
			return array(
				'value'  => '',
				'errors' => array( 'The policy must be plain text.' ),
			);
		}

		$normalised = preg_replace( '/[\x00-\x1F\x7F]/', ' ', $raw );
		$normalised = trim( preg_replace( '/\s+/', ' ', $normalised ) );
		$normalised = str_replace( array( "\r", "\n" ), '', $normalised );

		if ( '' === $normalised ) {
			return array(
				'value'  => '',
				'errors' => array(),
			);
		}

		$types  = self::get_directive_types();
		$seen   = array();
		$parts  = array();
		$errors = array();

		foreach ( explode( ';', $normalised ) as $piece ) {
			$piece = trim( $piece );
			if ( '' === $piece ) {
				continue;
			}

			$tokens = explode( ' ', $piece );
			$name   = strtolower( array_shift( $tokens ) );

			if ( ! isset( $types[ $name ] ) ) {
				$errors[] = sprintf( 'Unknown directive "%s" was removed.', $name );
				continue;
			}
			if ( isset( $seen[ $name ] ) ) {
				$errors[] = sprintf( 'Duplicate directive "%s" was removed; the first one is kept.', $name );
				continue;
			}
			$seen[ $name ] = true;

			$kept = array();

			switch ( $types[ $name ] ) {
				case 'sources':
				case 'report-uri':
					foreach ( $tokens as $token ) {
						$valid = self::sanitize_source( $token );
						if ( '' === $valid || ( 'report-uri' === $types[ $name ] && "'" === $valid[0] ) ) {
							$errors[] = sprintf( 'Invalid source "%1$s" in %2$s was removed.', $token, $name );
							continue;
						}
						$kept[] = $valid;
					}
					if ( ! empty( $tokens ) && empty( $kept ) ) {
						// Every source was invalid; dropping the directive avoids silently changing its meaning.
						$errors[] = sprintf( 'Directive "%s" had no valid sources and was removed.', $name );
						continue 2;
					}
					break;

				case 'report-to':
					if ( 1 === count( $tokens ) && preg_match( '/^[A-Za-z0-9_-]+$/', $tokens[0] ) ) {
						$kept = $tokens;
					} elseif ( ! empty( $tokens ) ) {
						$errors[] = 'report-to takes exactly one group name; the value was removed.';
						continue 2;
					}
					break;

				case 'sandbox':
					foreach ( $tokens as $token ) {
						if ( preg_match( '/^allow-[a-z-]+$/i', $token ) ) {
							$kept[] = $token;
						} else {
							$errors[] = sprintf( 'Invalid sandbox flag "%s" was removed.', $token );
						}
					}
					break;

				case 'flag':
					if ( ! empty( $tokens ) ) {
						$errors[] = sprintf( '%s takes no value; the extra text was removed.', $name );
					}
					break;

				case 'tokens':
					foreach ( $tokens as $token ) {
						if ( preg_match( "/^[A-Za-z0-9'*_#=.\\/-]+$/", $token ) ) {
							$kept[] = $token;
						} else {
							$errors[] = sprintf( 'Invalid value "%1$s" in %2$s was removed.', $token, $name );
						}
					}
					break;
			}

			$parts[] = trim( $name . ' ' . implode( ' ', $kept ) );
		}

		if ( empty( $parts ) ) {
			$errors[] = 'The policy contains no valid directives.';
			return array(
				'value'  => '',
				'errors' => $errors,
			);
		}

		return array(
			'value'  => implode( '; ', $parts ) . ';',
			'errors' => $errors,
		);
	}

	/**
	 * Human-readable warnings for risky custom policies.
	 *
	 * @param mixed $policy Policy text.
	 * @return string[]
	 */
	public static function detect_warnings( $policy ) {
		$warnings = array();

		if ( ! is_string( $policy ) || '' === trim( $policy ) ) {
			return $warnings;
		}

		$directives = self::parse_directives( $policy );
		$has_default = isset( $directives['default-src'] );
		$has_script  = isset( $directives['script-src'] );

		if ( ! $has_default && ! $has_script ) {
			$warnings[] = 'No default-src or script-src is set, so scripts are not restricted.';
		}

		$script = $has_script ? $directives['script-src'] : ( $has_default ? $directives['default-src'] : array() );

		if ( in_array( "'unsafe-inline'", $script, true ) ) {
			$warnings[] = "script-src allows 'unsafe-inline', so injected inline scripts can run.";
		}
		if ( in_array( "'unsafe-eval'", $script, true ) ) {
			$warnings[] = "script-src allows 'unsafe-eval', so string-to-code functions can run.";
		}
		if ( in_array( 'data:', $script, true ) ) {
			$warnings[] = 'script-src allows data: URIs, which can carry script payloads.';
		}
		if ( in_array( 'http:', $script, true ) ) {
			$warnings[] = 'script-src allows http:, so scripts can load without transport encryption.';
		}

		foreach ( array( 'script-src', 'default-src' ) as $name ) {
			if ( isset( $directives[ $name ] ) && in_array( '*', $directives[ $name ], true ) ) {
				$warnings[] = sprintf( '%s uses a wildcard (*), which allows loading from any origin.', $name );
			}
		}

		if ( ! isset( $directives['object-src'] ) || array( "'none'" ) !== $directives['object-src'] ) {
			$warnings[] = "object-src 'none' is not set, so plugins and legacy embeds may load.";
		}

		if ( ! isset( $directives['frame-ancestors'] ) ) {
			$warnings[] = 'frame-ancestors is not set, so clickjacking protection depends on X-Frame-Options alone.';
		}

		return $warnings;
	}

	/**
	 * Parse a policy into directive => lowercase tokens. The first occurrence wins, as in browsers.
	 *
	 * @param string $policy Policy text.
	 * @return array<string, string[]>
	 */
	private static function parse_directives( $policy ) {
		$map = array();

		foreach ( explode( ';', $policy ) as $piece ) {
			$tokens = preg_split( '/\s+/', trim( $piece ), -1, PREG_SPLIT_NO_EMPTY );
			if ( empty( $tokens ) ) {
				continue;
			}

			$name = strtolower( array_shift( $tokens ) );
			if ( ! isset( $map[ $name ] ) ) {
				$map[ $name ] = array_map( 'strtolower', $tokens );
			}
		}

		return $map;
	}

	/**
	 * Add sources to a directive without duplicates, keeping insertion order.
	 *
	 * @param array  $map       Directive => string[].
	 * @param string $directive Directive name.
	 * @param array  $sources   Sources to add.
	 * @return array
	 */
	private static function add_sources( array $map, $directive, array $sources ) {
		if ( ! isset( $map[ $directive ] ) ) {
			$map[ $directive ] = array();
		}
		foreach ( $sources as $source ) {
			if ( ! in_array( $source, $map[ $directive ], true ) ) {
				$map[ $directive ][] = $source;
			}
		}
		return $map;
	}

	/**
	 * Every directive recognised by sanitize_policy(), with how its value is validated.
	 *
	 * @return array<string, string>
	 */
	private static function get_directive_types() {
		$source_list = array(
			'child-src',
			'connect-src',
			'default-src',
			'font-src',
			'frame-src',
			'img-src',
			'manifest-src',
			'media-src',
			'object-src',
			'prefetch-src',
			'script-src',
			'script-src-elem',
			'script-src-attr',
			'style-src',
			'style-src-elem',
			'style-src-attr',
			'worker-src',
			'base-uri',
			'form-action',
			'frame-ancestors',
			'navigate-to',
		);

		$types = array();
		foreach ( $source_list as $name ) {
			$types[ $name ] = 'sources';
		}

		$types['report-uri']                = 'report-uri';
		$types['report-to']                 = 'report-to';
		$types['sandbox']                   = 'sandbox';
		$types['block-all-mixed-content']   = 'flag';
		$types['upgrade-insecure-requests'] = 'flag';
		$types['require-trusted-types-for'] = 'tokens';
		$types['trusted-types']             = 'tokens';
		$types['require-sri-for']           = 'tokens';

		return $types;
	}
}
