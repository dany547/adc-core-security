<?php
/**
 * CSP scanner: finds the external origins a site's public pages load resources from.
 *
 * The parsing and merging methods (extract_sources, merge_results, mark_allowed,
 * companion_hints, validate_stored, registrable_domain) are pure PHP and do not call
 * WordPress, so they can be unit tested. Only scan(), get_scan_urls(), get_last_scan()
 * and clear() use WordPress APIs.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Csp_Scanner {

	const OPTION = 'adc_security_csp_scan';

	const MAX_INPUT_BYTES  = 2097152;
	const MAX_URL_LENGTH   = 2048;
	const MAX_EXTRA_URLS   = 3;
	const MAX_EXTRA_PATH   = 500;
	const MAX_STORED_PAGES = 10;
	const MAX_EXISTING_CSP = 8192;

	/**
	 * Parse HTML and list every external origin it loads resources from.
	 *
	 * @param string $html      Page HTML.
	 * @param string $site_host Site host(s), e.g. "example.com". Several hosts may be listed separated by commas or spaces.
	 * @return array<int, array{directive: string, source: string, tag: string, inferred: bool, party: string, notes: string[]}>
	 */
	public static function extract_sources( string $html, string $site_host ): array {
		if ( '' === $html ) {
			return array();
		}
		if ( strlen( $html ) > self::MAX_INPUT_BYTES ) {
			$html = substr( $html, 0, self::MAX_INPUT_BYTES );
		}

		$sites = self::normalize_sites( $site_host );

		$elements = self::elements_from_regex( $html );

		$rows = array();
		foreach ( $elements as $element ) {
			self::collect( $element, $sites, $rows );
		}

		return self::dedupe_page( $rows );
	}

	/**
	 * Merge per-page results into one list keyed by directive and origin.
	 *
	 * @param array<string, array> $per_page URL => extract_sources() result.
	 * @return array<int, array{directive: string, source: string, tag: string, inferred: bool, party: string, notes: string[], pages: string[], count: int}>
	 */
	public static function merge_results( array $per_page ): array {
		$rows = array();

		foreach ( $per_page as $url => $found ) {
			if ( ! is_array( $found ) ) {
				continue;
			}
			$url        = (string) $url;
			$seen_here  = array();

			foreach ( $found as $item ) {
				if ( ! is_array( $item ) || ! isset( $item['directive'], $item['source'] ) ) {
					continue;
				}
				$directive = (string) $item['directive'];
				$source    = (string) $item['source'];
				$key       = $directive . '|' . $source;
				$inferred  = ! empty( $item['inferred'] );
				$tag       = isset( $item['tag'] ) ? (string) $item['tag'] : 'inline';
				$party     = isset( $item['party'] ) && 'first_sub' === $item['party'] ? 'first_sub' : 'third';
				$notes     = isset( $item['notes'] ) && is_array( $item['notes'] ) ? array_map( 'strval', $item['notes'] ) : array();

				if ( ! isset( $rows[ $key ] ) ) {
					$rows[ $key ] = array(
						'directive' => $directive,
						'source'    => $source,
						'tag'       => $tag,
						'inferred'  => $inferred,
						'party'     => $party,
						'notes'     => $notes,
						'pages'     => array(),
						'count'     => 0,
					);
				} else {
					// Prefer a firm sighting's tag over an inferred one.
					if ( $rows[ $key ]['inferred'] && ! $inferred ) {
						$rows[ $key ]['tag'] = $tag;
					}
					$rows[ $key ]['inferred'] = $rows[ $key ]['inferred'] && $inferred;
					$rows[ $key ]['notes']    = array_values( array_unique( array_merge( $rows[ $key ]['notes'], $notes ) ) );
				}

				if ( ! isset( $seen_here[ $key ] ) ) {
					$seen_here[ $key ] = true;
					++$rows[ $key ]['count'];
					if ( count( $rows[ $key ]['pages'] ) < self::MAX_STORED_PAGES ) {
						$rows[ $key ]['pages'][] = $url;
					}
				}
			}
		}

		$order = array_merge( ADC_Security_Csp_Policy::get_directives(), array( 'form-action', 'object-src' ) );
		$list  = array_values( $rows );

		usort(
			$list,
			static function ( $a, $b ) use ( $order ) {
				$ia = array_search( $a['directive'], $order, true );
				$ib = array_search( $b['directive'], $order, true );
				$ia = false === $ia ? count( $order ) : $ia;
				$ib = false === $ib ? count( $order ) : $ib;
				if ( $ia !== $ib ) {
					return $ia <=> $ib;
				}
				return strcmp( $a['source'], $b['source'] );
			}
		);

		return $list;
	}

	/**
	 * Add a boolean 'allowed' flag to each found row.
	 *
	 * @param array $found         Rows from merge_results().
	 * @param array $extra_sources Directive => string[] sources already allowed by the administrator.
	 * @return array
	 */
	public static function mark_allowed( array $found, array $extra_sources ): array {
		$defaults = ADC_Security_Csp_Policy::get_default_sources();

		foreach ( $found as $i => $row ) {
			if ( ! is_array( $row ) || ! isset( $row['directive'], $row['source'] ) ) {
				continue;
			}
			$directive  = (string) $row['directive'];
			$source     = self::canonical( (string) $row['source'] );
			$candidates = array();
			if ( isset( $extra_sources[ $directive ] ) && is_array( $extra_sources[ $directive ] ) ) {
				$candidates = $extra_sources[ $directive ];
			}
			if ( isset( $defaults[ $directive ] ) ) {
				$candidates = array_merge( $candidates, $defaults[ $directive ] );
			}

			$allowed    = false;
			$allowed_by = '';
			foreach ( $candidates as $candidate ) {
				if ( is_string( $candidate ) && self::canonical( $candidate ) === $source ) {
					$allowed    = true;
					$allowed_by = 'list';
					break;
				}
			}
			// The bare scheme 'https:' (in the default img-src and connect-src) allows every https:// origin.
			if ( ! $allowed && 0 === strpos( $source, 'https://' ) && in_array( 'https:', array_filter( $candidates, 'is_string' ), true ) ) {
				$allowed    = true;
				$allowed_by = 'https';
			}
			$found[ $i ]['allowed']    = $allowed;
			$found[ $i ]['allowed_by'] = $allowed_by;
		}

		return $found;
	}

	/**
	 * Service presets whose origins were seen (or not) on the scanned pages.
	 *
	 * Presets are used only as a lookup table. A preset is returned when at least
	 * one third-party origin detected by the scan appears in it.
	 *
	 * @param array $found Rows from merge_results().
	 * @return array<int, array{preset: string, label: string, detected: string[], missing: array<string, string[]>}>
	 */
	public static function companion_hints( array $found ): array {
		$seen        = array();
		$third_party = array();

		foreach ( $found as $row ) {
			if ( ! is_array( $row ) || ! isset( $row['source'] ) ) {
				continue;
			}
			$origin = self::origin_of( (string) $row['source'] );
			if ( '' === $origin ) {
				continue;
			}
			$seen[ $origin ] = true;
			if ( 'first_sub' !== ( $row['party'] ?? 'third' ) ) {
				$third_party[ $origin ] = true;
			}
		}

		$hints = array();
		foreach ( ADC_Security_Csp_Policy::get_service_presets() as $key => $preset ) {
			$preset_origins = array();
			$by_directive   = array();
			foreach ( $preset['directives'] as $directive => $sources ) {
				foreach ( $sources as $source ) {
					$origin = self::origin_of( $source );
					if ( '' === $origin ) {
						continue;
					}
					$preset_origins[ $origin ]              = true;
					$by_directive[ $directive ][ $origin ] = true;
				}
			}

			$detected = array_values( array_intersect( array_keys( $third_party ), array_keys( $preset_origins ) ) );
			if ( empty( $detected ) ) {
				continue;
			}
			sort( $detected, SORT_STRING );

			$missing = array();
			foreach ( $by_directive as $directive => $origins ) {
				$gaps = array_values( array_filter( array_keys( $origins ), static function ( $origin ) use ( $seen ) {
					return ! isset( $seen[ $origin ] );
				} ) );
				if ( ! empty( $gaps ) ) {
					$missing[ $directive ] = $gaps;
				}
			}

			$hints[] = array(
				'preset'   => (string) $key,
				'label'    => (string) $preset['label'],
				'detected' => $detected,
				'missing'  => $missing,
			);
		}

		return $hints;
	}

	/**
	 * Registrable domain (eTLD+1 approximation) without a public suffix list.
	 *
	 * Uses the last two labels, or the last three when the host ends in a 2-letter
	 * country code under a common second-level label (example.co.uk).
	 *
	 * @param string $host Host name.
	 * @return string
	 */
	public static function registrable_domain( string $host ): string {
		$host   = strtolower( rtrim( $host, '.' ) );
		$labels = explode( '.', $host );
		$count  = count( $labels );
		if ( $count < 2 ) {
			return $host;
		}

		$take = 2;
		if ( $count >= 3 && 2 === strlen( $labels[ $count - 1 ] ) && in_array( $labels[ $count - 2 ], array( 'co', 'com', 'org', 'net', 'gov', 'ac', 'edu' ), true ) ) {
			$take = 3;
		}

		return implode( '.', array_slice( $labels, -$take ) );
	}

	/**
	 * Turn a page address typed by the administrator into an absolute URL on the site.
	 *
	 * Accepts "/path", "path", "www.site.ro/path", "//site.ro/path" and full http(s) URLs.
	 * The result always uses the scheme, host and port of $home_url, so the www and
	 * http/https variant of the home URL is used. Returns '' when the input is not a
	 * page of the same site, uses another scheme, carries credentials, or is too long.
	 * Fragments are dropped.
	 *
	 * @param string $raw      Raw input.
	 * @param string $home_url Home URL, e.g. "https://www.example.com/".
	 * @return string Absolute URL, or ''.
	 */
	public static function normalize_extra_url( string $raw, string $home_url ): string {
		$raw = trim( $raw );
		if ( '' === $raw || strlen( $raw ) > self::MAX_URL_LENGTH || preg_match( '/[\x00-\x20\x7F]/', $raw ) ) {
			return '';
		}

		$home = parse_url( $home_url );
		if ( ! is_array( $home ) || empty( $home['scheme'] ) || empty( $home['host'] ) ) {
			return '';
		}
		$home_scheme = strtolower( (string) $home['scheme'] );
		if ( ! in_array( $home_scheme, array( 'http', 'https' ), true ) ) {
			return '';
		}
		$home_host = strtolower( rtrim( (string) $home['host'], '.' ) );
		$home_port = isset( $home['port'] ) ? (int) $home['port'] : 0;
		$origin    = $home_scheme . '://' . $home_host . ( $home_port ? ':' . $home_port : '' );

		if ( 0 === strpos( $raw, '//' ) ) {
			$candidate = 'https:' . $raw;
		} elseif ( preg_match( '#^[a-z][a-z0-9+.\-]*://#i', $raw ) ) {
			$candidate = $raw;
		} elseif ( '/' === $raw[0] ) {
			$candidate = $origin . $raw;
		} elseif ( preg_match( '#^[a-z][a-z0-9+.\-]*:#i', $raw ) && ! preg_match( '#^[a-z0-9-]+(?:\.[a-z0-9-]+)+:\d+(?:[/?\#]|$)#i', $raw ) ) {
			// javascript:, data:, mailto: and other schemes without an authority.
			return '';
		} elseif ( preg_match( '#^[a-z0-9-]+(?:\.[a-z0-9-]+)+(?::\d+)?(?:[/?\#]|$)#i', $raw ) ) {
			$candidate = 'https://' . $raw;
		} else {
			$candidate = $origin . '/' . $raw;
		}

		$parts = parse_url( $candidate );
		if ( ! is_array( $parts ) || empty( $parts['scheme'] ) || empty( $parts['host'] ) ) {
			return '';
		}
		$scheme = strtolower( (string) $parts['scheme'] );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) || isset( $parts['user'] ) || isset( $parts['pass'] ) ) {
			return '';
		}

		$host = strtolower( rtrim( (string) $parts['host'], '.' ) );
		if ( self::strip_www( $host ) !== self::strip_www( $home_host ) ) {
			return '';
		}

		if ( isset( $parts['port'] ) ) {
			$port    = (int) $parts['port'];
			$default = 'https' === $scheme ? 443 : 80;
			if ( $port !== $default && $port !== $home_port ) {
				return '';
			}
		}

		$path = isset( $parts['path'] ) && '' !== $parts['path'] ? $parts['path'] : '/';
		$path_query = $path . ( isset( $parts['query'] ) && '' !== $parts['query'] ? '?' . $parts['query'] : '' );
		if ( strlen( $path_query ) > self::MAX_EXTRA_PATH || preg_match( '/[<>"\\`]/', $path_query ) ) {
			return '';
		}

		return $origin . $path_query;
	}

	/**
	 * Merge service presets and administrator extra sources into one directive map.
	 *
	 * Produces the same policy as build_generated( $preset_keys, $extra_sources, ... ) when
	 * passed to build_generated( array(), result, ... ). Used once on upgrade to move
	 * presets into csp_extra_sources. Pure PHP.
	 *
	 * @param array $preset_keys   Preset keys from ADC_Security_Csp_Policy::get_service_presets().
	 * @param array $extra_sources Directive => string[].
	 * @return array<string, string[]> Directive => sanitised sources.
	 */
	public static function expand_presets( array $preset_keys, array $extra_sources ): array {
		$catalog   = ADC_Security_Csp_Policy::get_service_presets();
		$supported = ADC_Security_Csp_Policy::get_directives();
		$merged    = array();

		$add = static function ( array $map, $directive, array $sources ) {
			if ( ! isset( $map[ $directive ] ) ) {
				$map[ $directive ] = array();
			}
			foreach ( $sources as $source ) {
				$valid = ADC_Security_Csp_Policy::sanitize_source( $source );
				if ( '' !== $valid && ! in_array( $valid, $map[ $directive ], true ) ) {
					$map[ $directive ][] = $valid;
				}
			}
			return $map;
		};

		foreach ( $preset_keys as $key ) {
			if ( ! is_string( $key ) || ! isset( $catalog[ $key ] ) ) {
				continue;
			}
			foreach ( $catalog[ $key ]['directives'] as $directive => $sources ) {
				if ( in_array( $directive, $supported, true ) ) {
					$merged = $add( $merged, (string) $directive, $sources );
				}
			}
		}

		foreach ( $extra_sources as $directive => $sources ) {
			if ( ! is_string( $directive ) || ! in_array( $directive, $supported, true ) || ! is_array( $sources ) ) {
				continue;
			}
			$merged = $add( $merged, $directive, $sources );
		}

		return $merged;
	}

	/**
	 * Scan the site's public pages as an anonymous visitor and store the result.
	 *
	 * @param array $extra_urls Up to MAX_EXTRA_URLS extra page addresses on this site.
	 * @return array|WP_Error
	 */
	public function scan( array $extra_urls = array() ) {
		$home  = home_url( '/' );
		$host  = strtolower( (string) wp_parse_url( $home, PHP_URL_HOST ) );
		$hosts = array_unique( array_filter( array( $host, strtolower( (string) wp_parse_url( site_url( '/' ), PHP_URL_HOST ) ) ) ) );

		$targets = self::get_scan_urls();
		$errors  = array();

		$extra_urls = array_slice( array_values( $extra_urls ), 0, self::MAX_EXTRA_URLS );
		foreach ( $extra_urls as $raw ) {
			if ( ! is_string( $raw ) || '' === trim( $raw ) ) {
				continue;
			}
			$url = self::normalize_extra_url( $raw, $home );
			if ( '' === $url ) {
				/* translators: 1: rejected input, 2: site host. */
				$errors[ $raw ] = sprintf( __( '"%1$s" is not a page of %2$s, so it was skipped.', 'adc-security' ), $raw, $host );
				continue;
			}
			if ( ! in_array( $url, $targets, true ) ) {
				$targets[] = $url;
			}
		}

		$args = array(
			'timeout'             => 10,
			'redirection'         => 3,
			'limit_response_size' => self::MAX_INPUT_BYTES,
			'headers'             => array(
				'Accept'     => 'text/html',
				'User-Agent' => 'ADC-Security-CSP-Scanner/' . ADC_SECURITY_VERSION,
			),
			'cookies'             => array(),
			'sslverify'           => (bool) apply_filters( 'adc_security_csp_scan_sslverify', true ),
		);

		$pages    = array();
		$existing = '';
		$started  = microtime( true );

		foreach ( $targets as $url ) {
			// Stay well inside typical PHP execution limits: stop fetching after 20 seconds.
			if ( ! empty( $pages ) && ( microtime( true ) - $started ) > 20 ) {
				$errors[ $url ] = __( 'Skipped: the scan time limit was reached.', 'adc-security' );
				continue;
			}

			$response = wp_safe_remote_get( $url, $args );
			if ( is_wp_error( $response ) ) {
				$errors[ $url ] = $response->get_error_message();
				continue;
			}

			$code = (int) wp_remote_retrieve_response_code( $response );
			if ( 200 !== $code ) {
				/* translators: %d: HTTP status code. */
				$errors[ $url ] = sprintf( __( 'HTTP %d', 'adc-security' ), $code );
				continue;
			}

			$type = self::header_value( $response, 'content-type' );
			if ( ! preg_match( '#text/html|application/xhtml\+xml#i', $type ) ) {
				$errors[ $url ] = __( 'The response is not an HTML page.', 'adc-security' );
				continue;
			}

			$pages[ $url ] = self::extract_sources( (string) wp_remote_retrieve_body( $response ), implode( ',', $hosts ) );

			if ( '' === $existing ) {
				$existing = self::header_value( $response, 'content-security-policy' );
			}
		}

		if ( empty( $pages ) ) {
			return new WP_Error(
				'adc_security_csp_scan_failed',
				__( 'No page could be fetched as an anonymous visitor. Check that the server can reach this site over HTTP(S) (hosting or firewall rules sometimes block requests from the server to itself), that pages are not behind HTTP authentication or maintenance mode, and that no other security plugin blocks this scanner.', 'adc-security' )
			);
		}

		$data = array(
			'time'         => time(),
			'urls'         => array_values( array_map( 'strval', array_keys( $pages ) ) ),
			'errors'       => $errors,
			'found'        => self::merge_results( $pages ),
			'existing_csp' => $existing,
		);

		update_option( self::OPTION, $data, false );

		return $data;
	}

	/**
	 * Pages to scan: home, latest post and page, blog page, privacy policy, shop pages, and up to two other public post types.
	 *
	 * @param int $max Maximum number of URLs.
	 * @return string[]
	 */
	public static function get_scan_urls( int $max = 8 ): array {
		$home    = home_url( '/' );
		$host    = strtolower( (string) wp_parse_url( $home, PHP_URL_HOST ) );
		$front   = 'page' === get_option( 'show_on_front' ) ? (int) get_option( 'page_on_front' ) : 0;
		$blog    = (int) get_option( 'page_for_posts' );
		$exclude = $front > 0 ? array( $front ) : array();

		$latest = static function ( $post_type, array $exclude_ids ) {
			$args = array(
				'post_type'           => $post_type,
				'post_status'         => 'publish',
				'numberposts'         => 1,
				'orderby'             => 'date',
				'order'               => 'DESC',
				'fields'              => 'ids',
				'has_password'        => false,
				'ignore_sticky_posts' => true,
				'no_found_rows'       => true,
			);
			if ( ! empty( $exclude_ids ) ) {
				$args['post__not_in'] = $exclude_ids;
			}
			$ids = get_posts( $args );
			return empty( $ids ) ? '' : (string) get_permalink( (int) $ids[0] );
		};

		$urls   = array( $home );
		$urls[] = $latest( 'post', array() );
		$urls[] = $latest( 'page', $exclude );
		if ( $blog > 0 ) {
			$urls[] = (string) get_permalink( $blog );
		}
		if ( function_exists( 'get_privacy_policy_url' ) ) {
			$urls[] = (string) get_privacy_policy_url();
		}
		if ( function_exists( 'wc_get_page_permalink' ) ) {
			foreach ( array( 'shop', 'checkout', 'cart', 'myaccount' ) as $key ) {
				$urls[] = (string) wc_get_page_permalink( $key );
			}
		}

		$extra = 0;
		foreach ( get_post_types( array( 'public' => true, '_builtin' => false ), 'names' ) as $post_type ) {
			if ( $extra >= 2 ) {
				break;
			}
			$link = $latest( $post_type, $exclude );
			if ( '' !== $link ) {
				$urls[] = $link;
				++$extra;
			}
		}

		$max  = max( 1, $max );
		$urls = self::filter_scan_urls( $urls, $host, $max );

		$filtered = apply_filters( 'adc_security_csp_scan_urls', $urls );
		if ( ! is_array( $filtered ) ) {
			return $urls;
		}

		return self::filter_scan_urls( $filtered, $host, $max );
	}

	/**
	 * Last stored scan, validated. Empty array when there is none.
	 *
	 * @return array
	 */
	public static function get_last_scan(): array {
		return self::validate_stored( get_option( self::OPTION, array() ) );
	}

	/**
	 * Delete the stored scan.
	 */
	public static function clear(): void {
		delete_option( self::OPTION );
	}

	/**
	 * Validate a stored scan result. Pure; returns array() for anything malformed.
	 *
	 * @param mixed $raw Raw option value.
	 * @return array
	 */
	public static function validate_stored( $raw ): array {
		if ( ! is_array( $raw ) || ! isset( $raw['time'] ) || ! is_int( $raw['time'] ) ) {
			return array();
		}

		$urls = array();
		if ( isset( $raw['urls'] ) && is_array( $raw['urls'] ) ) {
			foreach ( $raw['urls'] as $url ) {
				if ( is_string( $url ) ) {
					$urls[] = $url;
				}
			}
		}

		$errors = array();
		if ( isset( $raw['errors'] ) && is_array( $raw['errors'] ) ) {
			foreach ( $raw['errors'] as $url => $message ) {
				if ( is_string( $url ) && is_string( $message ) ) {
					$errors[ $url ] = $message;
				}
			}
		}

		$found = array();
		if ( isset( $raw['found'] ) && is_array( $raw['found'] ) ) {
			foreach ( $raw['found'] as $row ) {
				if ( ! is_array( $row ) || ! isset( $row['directive'], $row['source'], $row['tag'], $row['inferred'], $row['count'] ) ) {
					continue;
				}
				if ( ! is_string( $row['directive'] ) || ! is_string( $row['source'] ) || ! is_string( $row['tag'] ) || ! is_bool( $row['inferred'] ) || ! is_int( $row['count'] ) ) {
					continue;
				}
				$pages = array();
				if ( isset( $row['pages'] ) && is_array( $row['pages'] ) ) {
					foreach ( $row['pages'] as $page ) {
						if ( is_string( $page ) ) {
							$pages[] = $page;
						}
					}
				}
				$notes = array();
				if ( isset( $row['notes'] ) && is_array( $row['notes'] ) ) {
					foreach ( $row['notes'] as $note ) {
						if ( is_string( $note ) ) {
							$notes[] = $note;
						}
					}
				}
				$found[] = array(
					'directive' => $row['directive'],
					'source'    => $row['source'],
					'tag'       => $row['tag'],
					'inferred'  => $row['inferred'],
					'party'     => isset( $row['party'] ) && 'first_sub' === $row['party'] ? 'first_sub' : 'third',
					'notes'     => $notes,
					'pages'     => $pages,
					'count'     => $row['count'],
				);
			}
		}

		return array(
			'time'         => $raw['time'],
			'urls'         => $urls,
			'errors'       => $errors,
			'found'        => $found,
			'existing_csp' => isset( $raw['existing_csp'] ) && is_string( $raw['existing_csp'] ) ? substr( $raw['existing_csp'], 0, self::MAX_EXISTING_CSP ) : '',
		);
	}

	/* ------------------------------------------------------------------
	 * Parsing
	 * ------------------------------------------------------------------ */

	/**
	 * Tokenise the HTML into elements. One parser on every host, so results
	 * do not depend on which PHP extensions are installed.
	 *
	 * @param string $html HTML.
	 * @return array
	 */
	private static function elements_from_regex( string $html ): array {
		$elements = array();

		// Script and style bodies are raw text: take them out first so their contents are not parsed as tags.
		$blocks = preg_replace_callback(
			'#<(script|style)(?=[\s>/])((?:[^>"\']|"[^"]*"|\'[^\']*\')*)>(.*?)</\1\s*>#is',
			static function ( $m ) use ( &$elements ) {
				$elements[] = array(
					'tag'   => strtolower( $m[1] ),
					'attrs' => self::parse_attributes( $m[2] ),
					'text'  => $m[3],
				);
				return ' ';
			},
			$html
		);
		if ( null === $blocks ) {
			$blocks = $html;
		}

		$blocks = preg_replace( '#<!--.*?-->#s', ' ', $blocks );
		if ( null === $blocks ) {
			return $elements;
		}

		$tag_pattern = '#<([a-zA-Z][a-zA-Z0-9:-]*)((?:\s+[^\s"\'>/=]+(?:\s*=\s*(?:"[^"]*"|\'[^\']*\'|[^\s"\'=<>`]+))?)*)\s*/?>#';
		if ( preg_match_all( $tag_pattern, $blocks, $matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $m ) {
				$elements[] = array(
					'tag'   => strtolower( $m[1] ),
					'attrs' => self::parse_attributes( $m[2] ),
					'text'  => '',
				);
			}
		}

		return $elements;
	}

	/**
	 * Parse an attribute string into name => decoded value.
	 *
	 * @param string $raw Attribute string.
	 * @return array<string, string>
	 */
	private static function parse_attributes( string $raw ): array {
		$attrs = array();
		if ( '' === trim( $raw ) ) {
			return $attrs;
		}

		if ( preg_match_all( '#([^\s"\'>/=]+)(?:\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'=<>`]+)))?#', $raw, $matches, PREG_SET_ORDER ) ) {
			foreach ( $matches as $m ) {
				$name = strtolower( $m[1] );
				if ( isset( $attrs[ $name ] ) ) {
					continue;
				}
				$value = '';
				foreach ( array( 2, 3, 4 ) as $group ) {
					if ( isset( $m[ $group ] ) && '' !== $m[ $group ] ) {
						$value = $m[ $group ];
						break;
					}
				}
				$attrs[ $name ] = html_entity_decode( $value, ENT_QUOTES | ENT_HTML5, 'UTF-8' );
			}
		}

		return $attrs;
	}

	/* ------------------------------------------------------------------
	 * Mapping elements to directives
	 * ------------------------------------------------------------------ */

	/**
	 * Turn one element into sightings.
	 *
	 * @param array $el    Element record (tag, attrs, text).
	 * @param array $sites Normalised site hosts.
	 * @param array $rows  Sightings, appended to.
	 */
	private static function collect( array $el, array $sites, array &$rows ): void {
		$tag  = $el['tag'];
		$a    = $el['attrs'];
		$text = $el['text'];

		switch ( $tag ) {
			case 'script':
				if ( ! self::is_script_type( $a ) ) {
					break;
				}
				if ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'script-src', 'script', $a['src'], $sites, false );
				} elseif ( '' !== trim( $text ) ) {
					self::collect_inline_js( $text, $sites, $rows );
				}
				break;

			case 'link':
				$rel  = preg_split( '/\s+/', strtolower( trim( $a['rel'] ?? '' ) ), -1, PREG_SPLIT_NO_EMPTY );
				$href = $a['href'] ?? '';
				if ( in_array( 'stylesheet', $rel, true ) ) {
					self::push_url( $rows, 'style-src', 'link', $href, $sites, false );
				} elseif ( array_intersect( $rel, array( 'preload', 'prefetch', 'modulepreload' ) ) ) {
					$as  = strtolower( trim( $a['as'] ?? '' ) );
					if ( '' === $as && in_array( 'modulepreload', $rel, true ) ) {
						$as = 'script';
					}
					$map = array(
						'script' => 'script-src',
						'style'  => 'style-src',
						'font'   => 'font-src',
						'image'  => 'img-src',
						'fetch'  => 'connect-src',
						'xhr'    => 'connect-src',
					);
					if ( isset( $map[ $as ] ) ) {
						self::push_url( $rows, $map[ $as ], 'link', $href, $sites, false );
					}
				} elseif ( self::has_icon_token( $rel ) ) {
					self::push_url( $rows, 'img-src', 'link', $href, $sites, false );
				} elseif ( array_intersect( $rel, array( 'preconnect', 'dns-prefetch' ) ) ) {
					self::push_url( $rows, 'connect-src', 'link', $href, $sites, true );
				} elseif ( in_array( 'manifest', $rel, true ) ) {
					self::push_url( $rows, 'manifest-src', 'link', $href, $sites, false );
				}
				break;

			case 'img':
				self::push_url( $rows, 'img-src', 'img', $a['src'] ?? '', $sites, false );
				if ( isset( $a['srcset'] ) ) {
					self::push_srcset( $rows, $a['srcset'], 'img-src', 'img', $sites );
				}
				break;

			case 'source':
				if ( isset( $a['srcset'] ) ) {
					self::push_srcset( $rows, $a['srcset'], 'img-src', 'img', $sites );
				} elseif ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'media-src', 'media', $a['src'], $sites, false );
				}
				break;

			case 'video':
				if ( isset( $a['poster'] ) ) {
					self::push_url( $rows, 'img-src', 'media', $a['poster'], $sites, false );
				}
				if ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'media-src', 'media', $a['src'], $sites, false );
				}
				break;

			case 'audio':
				if ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'media-src', 'media', $a['src'], $sites, false );
				}
				break;

			case 'iframe':
			case 'frame':
				if ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'frame-src', 'iframe', $a['src'], $sites, false );
				}
				break;

			case 'object':
				if ( isset( $a['data'] ) ) {
					self::push_url( $rows, 'object-src', 'object', $a['data'], $sites, false );
				}
				break;

			case 'embed':
				if ( isset( $a['src'] ) ) {
					self::push_url( $rows, 'object-src', 'object', $a['src'], $sites, false );
				}
				break;

			case 'form':
				if ( isset( $a['action'] ) ) {
					self::push_url( $rows, 'form-action', 'form', $a['action'], $sites, false );
				}
				break;

			case 'style':
				foreach ( self::css_references( $text ) as $ref ) {
					self::push_url( $rows, $ref[0], 'style', $ref[1], $sites, false );
				}
				break;
		}

		if ( isset( $a['style'] ) ) {
			foreach ( self::css_references( $a['style'] ) as $ref ) {
				self::push_url( $rows, $ref[0], 'style', $ref[1], $sites, false );
			}
		}
	}

	/**
	 * Inline script bodies: URL string literals become script-src (loader files) or connect-src (everything else).
	 *
	 * @param string $js    Script body.
	 * @param array  $sites Normalised site hosts.
	 * @param array  $rows  Sightings, appended to.
	 */
	private static function collect_inline_js( string $js, array $sites, array &$rows ): void {
		$pattern = '#(?<![A-Za-z0-9+.\-:/])((?:https?:|wss:)?//)([A-Za-z0-9.-]+(?::\d{1,5})?)((?:/[^\s"\'`<>\\\\)]*)?)#i';
		if ( ! preg_match_all( $pattern, $js, $matches, PREG_SET_ORDER ) ) {
			return;
		}

		foreach ( $matches as $m ) {
			$full = $m[1] . $m[2] . $m[3];
			$info = self::origin_info( $full, $sites );
			if ( null === $info ) {
				continue;
			}

			if ( 'wss' === $info['scheme'] ) {
				$directive = 'connect-src';
			} else {
				$lower     = strtolower( $full );
				$path      = preg_replace( '#[?\#].*$#', '', $lower );
				$loader    = preg_match( '#\.js$#', (string) $path )
					|| false !== strpos( $lower, '/gtm.js' )
					|| false !== strpos( $lower, '/gtag/js' )
					|| false !== strpos( $lower, '/analytics.js' );
				$directive = $loader ? 'script-src' : 'connect-src';
			}

			self::push_info( $rows, $directive, 'inline', $info, true );
		}
	}

	/**
	 * CSS references: @import -> style-src, @font-face src -> font-src, other url() -> img-src.
	 *
	 * @param string $css CSS text or style attribute value.
	 * @return array<int, array{0: string, 1: string}> [directive, raw url] pairs.
	 */
	private static function css_references( string $css ): array {
		$refs = array();
		if ( false === stripos( $css, 'url(' ) && false === stripos( $css, '@import' ) ) {
			return $refs;
		}

		if ( preg_match_all( '#@import\s+(?:url\(\s*)?(["\']?)([^"\')\s;]+)\1#i', $css, $matches ) ) {
			foreach ( $matches[2] as $url ) {
				$refs[] = array( 'style-src', $url );
			}
		}
		$css = preg_replace( '#@import\s+[^;]*(?:;|$)#i', ' ', $css ) ?? $css;

		if ( preg_match_all( '#@font-face\s*\{([^}]*)\}#i', $css, $matches ) ) {
			foreach ( $matches[1] as $body ) {
				foreach ( self::url_tokens( $body ) as $url ) {
					$refs[] = array( 'font-src', $url );
				}
			}
		}
		$css = preg_replace( '#@font-face\s*\{[^}]*\}#i', ' ', $css ) ?? $css;

		foreach ( self::url_tokens( $css ) as $url ) {
			$refs[] = array( 'img-src', $url );
		}

		return $refs;
	}

	/**
	 * @param string $css CSS fragment.
	 * @return string[]
	 */
	private static function url_tokens( string $css ): array {
		if ( preg_match_all( '#url\(\s*(["\']?)([^"\')\s]+)\1\s*\)#i', $css, $matches ) ) {
			return $matches[2];
		}
		return array();
	}

	/**
	 * Add a row for a raw URL attribute value when it is an external origin.
	 */
	private static function push_url( array &$rows, string $directive, string $tag, string $raw, array $sites, bool $inferred ): void {
		$info = self::origin_info( $raw, $sites );
		if ( null !== $info ) {
			self::push_info( $rows, $directive, $tag, $info, $inferred );
		}
	}

	/**
	 * Add rows for each candidate URL in a srcset attribute.
	 */
	private static function push_srcset( array &$rows, string $srcset, string $directive, string $tag, array $sites ): void {
		foreach ( explode( ',', $srcset ) as $candidate ) {
			$parts = preg_split( '/\s+/', trim( $candidate ), 2 );
			if ( ! empty( $parts[0] ) ) {
				self::push_url( $rows, $directive, $tag, $parts[0], $sites, false );
			}
		}
	}

	/**
	 * @param array $rows      Sightings, appended to.
	 * @param string $directive CSP directive.
	 * @param string $tag       Element kind.
	 * @param array  $info      Output of origin_info().
	 * @param bool   $inferred  Whether the sighting is a guess.
	 */
	private static function push_info( array &$rows, string $directive, string $tag, array $info, bool $inferred ): void {
		// WebSocket schemes are only meaningful for connect-src.
		if ( 'wss' === $info['scheme'] && 'connect-src' !== $directive ) {
			return;
		}
		$rows[] = array(
			'directive' => $directive,
			'source'    => $info['origin'],
			'tag'       => $tag,
			'inferred'  => $inferred,
			'party'     => $info['party'],
			'notes'     => $info['notes'],
		);
	}

	/**
	 * Normalise a raw URL into an origin with classification.
	 *
	 * Returns null for relative, data:, blob:, javascript:, malformed, same-origin
	 * (the exact site host, covered by 'self') and unusable URLs.
	 *
	 * @param string $raw   Raw URL.
	 * @param array  $sites Normalised site hosts.
	 * @return array{origin: string, scheme: string, party: string, notes: string[]}|null
	 */
	private static function origin_info( string $raw, array $sites ): ?array {
		$url = trim( $raw );
		if ( '' === $url || strlen( $url ) > self::MAX_URL_LENGTH ) {
			return null;
		}
		// No inner whitespace, control characters, non-ASCII or backslashes.
		if ( preg_match( '/[\x00-\x20\x7F-\xFF\\\\]/', $url ) ) {
			return null;
		}
		if ( 0 === strpos( $url, '//' ) ) {
			$url = 'https:' . $url;
		}
		if ( ! preg_match( '#^(https?|wss)://([^/?\#]*)#i', $url, $m ) ) {
			return null;
		}

		$scheme    = strtolower( $m[1] );
		$authority = $m[2];
		if ( '' === $authority || false !== strpos( $authority, '@' ) ) {
			return null;
		}

		$port = 0;
		if ( preg_match( '#^([^:]*):(\d{1,5})$#', $authority, $pm ) ) {
			$host = strtolower( $pm[1] );
			$port = (int) $pm[2];
			if ( $port < 1 || $port > 65535 ) {
				return null;
			}
		} else {
			$host = strtolower( $authority );
		}
		$host = rtrim( $host, '.' );

		if ( ! self::is_valid_host( $host ) ) {
			return null;
		}

		// The site's own origin is covered by 'self'.
		foreach ( $sites as $site ) {
			if ( $host === $site ) {
				return null;
			}
		}

		$party = 'third';
		foreach ( $sites as $site ) {
			if ( self::strip_www( $host ) === self::strip_www( $site ) || self::registrable_domain( $host ) === self::registrable_domain( $site ) ) {
				$party = 'first_sub';
				break;
			}
		}

		$default_port = 'http' === $scheme ? 80 : 443;
		$origin       = $scheme . '://' . $host;
		$notes        = array();

		if ( 0 !== $port && $port !== $default_port ) {
			$origin .= ':' . $port;
			$notes[] = 'port';
		}
		if ( 'http' === $scheme ) {
			$notes[] = 'insecure_http';
		}
		if ( preg_match( '#^\d{1,3}(?:\.\d{1,3}){3}$#', $host ) ) {
			$notes[] = 'ip_host';
		}

		if ( ADC_Security_Csp_Policy::sanitize_source( $origin ) !== $origin ) {
			return null;
		}

		return array(
			'origin' => $origin,
			'scheme' => $scheme,
			'party'  => $party,
			'notes'  => $notes,
		);
	}

	/**
	 * @param string $host Lower-case host.
	 * @return bool
	 */
	private static function is_valid_host( string $host ): bool {
		if ( '' === $host || strlen( $host ) > 253 ) {
			return false;
		}
		if ( 'localhost' === $host ) {
			return true;
		}
		return (bool) preg_match( '#^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$#', $host );
	}

	/**
	 * Collapse duplicate directive+origin rows within one page.
	 *
	 * @param array $rows Sightings.
	 * @return array
	 */
	private static function dedupe_page( array $rows ): array {
		$index = array();
		$out   = array();

		foreach ( $rows as $row ) {
			$key = $row['directive'] . '|' . $row['source'];
			if ( ! isset( $index[ $key ] ) ) {
				$index[ $key ] = count( $out );
				$out[]         = $row;
				continue;
			}

			$i = $index[ $key ];
			if ( $out[ $i ]['inferred'] && ! $row['inferred'] ) {
				$out[ $i ]['inferred'] = false;
				$out[ $i ]['tag']      = $row['tag'];
			}
			$out[ $i ]['notes'] = array_values( array_unique( array_merge( $out[ $i ]['notes'], $row['notes'] ) ) );
		}

		return $out;
	}

	/**
	 * @param array $a Script element attributes.
	 * @return bool Whether the script is JavaScript (not JSON, templates, etc.).
	 */
	private static function is_script_type( array $a ): bool {
		$type = strtolower( trim( $a['type'] ?? '' ) );
		return in_array( $type, array( '', 'text/javascript', 'application/javascript', 'module', 'text/ecmascript', 'application/ecmascript' ), true );
	}

	/**
	 * @param string[] $rel Link relation tokens.
	 * @return bool
	 */
	private static function has_icon_token( array $rel ): bool {
		foreach ( $rel as $token ) {
			if ( 'icon' === $token || 0 === strpos( $token, 'apple-touch-icon' ) || 'mask-icon' === $token ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Normalise a site host list ("example.com, www.example.com") to bare lower-case hosts.
	 *
	 * @param string $hosts Host list.
	 * @return string[]
	 */
	private static function normalize_sites( string $hosts ): array {
		$out = array();
		foreach ( preg_split( '/[\s,]+/', strtolower( $hosts ), -1, PREG_SPLIT_NO_EMPTY ) as $host ) {
			$host = preg_replace( '#^[a-z]+://#', '', $host );
			$host = preg_replace( '#[/?\#].*$#', '', (string) $host );
			$host = preg_replace( '#:\d+$#', '', (string) $host );
			$host = rtrim( (string) $host, '.' );
			if ( '' !== $host && ! in_array( $host, $out, true ) ) {
				$out[] = $host;
			}
		}
		return $out;
	}

	/**
	 * @param string $host Host.
	 * @return string
	 */
	private static function strip_www( string $host ): string {
		return (string) preg_replace( '#^www\.#', '', $host );
	}

	/**
	 * Origin part of a source expression ("https://host:port/path" => "https://host:port").
	 *
	 * @param string $source Source.
	 * @return string Lower-case origin, or '' when none.
	 */
	private static function origin_of( string $source ): string {
		if ( preg_match( '#^((?:https?|wss)://[^/]+)#i', trim( $source ), $m ) ) {
			return strtolower( $m[1] );
		}
		return '';
	}

	/**
	 * @param string $source Source.
	 * @return string
	 */
	private static function canonical( string $source ): string {
		return strtolower( rtrim( trim( $source ), '/' ) );
	}

	/**
	 * Keep valid, same-site-safe, unique URLs on the site host, capped.
	 *
	 * @param array  $urls Candidate URLs.
	 * @param string $host Site host.
	 * @param int    $max  Cap.
	 * @return string[]
	 */
	private static function filter_scan_urls( array $urls, string $host, int $max ): array {
		$clean = array();
		foreach ( $urls as $url ) {
			if ( ! is_string( $url ) || '' === $url ) {
				continue;
			}
			if ( strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) ) !== $host ) {
				continue;
			}
			if ( ! in_array( $url, $clean, true ) ) {
				$clean[] = $url;
			}
		}
		return array_slice( $clean, 0, $max );
	}

	/**
	 * Response header value as a string (first value when repeated).
	 *
	 * @param array|WP_Error $response Response.
	 * @param string         $name     Header name.
	 * @return string
	 */
	private static function header_value( $response, string $name ): string {
		$value = wp_remote_retrieve_header( $response, $name );
		if ( is_array( $value ) ) {
			$value = reset( $value );
		}
		return is_string( $value ) ? substr( trim( $value ), 0, self::MAX_EXISTING_CSP ) : '';
	}
}
