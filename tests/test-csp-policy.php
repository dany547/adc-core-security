<?php
/**
 * Lightweight CSP policy tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-csp.php';
require_once ABSPATH . 'includes/class-adc-security-hardening.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$policy = new ADC_Security_Csp_Policy();
$header_definitions = ADC_Security_Hardening::get_security_header_definitions();
$expected_header_keys = array(
	'content_type_options',
	'frame_options',
	'xss_protection',
	'referrer_policy',
	'csp',
	'permissions_policy',
	'hsts',
);

if ( $expected_header_keys !== array_keys( $header_definitions ) ) {
	$fail( 'Fine-tunable security header keys changed unexpectedly.' );
}

$strict = $policy->build( '', false );
if ( false !== strpos( $strict, "'unsafe-eval'" ) ) {
	$fail( 'Strict CSP unexpectedly allows unsafe-eval.' );
}

if ( false === strpos( $strict, 'https://www.googletagmanager.com' ) || false === strpos( $strict, 'style-src' ) ) {
	$fail( 'Common Google Tag Manager stylesheet origin is missing from style-src.' );
}

$compatibility = $policy->build( '', true );
if ( false === strpos( $compatibility, "'unsafe-eval'" ) ) {
	$fail( 'Compatibility CSP does not allow dynamic script compilation.' );
}

$custom = "default-src 'none'; script-src 'self';";
if ( $custom !== $policy->build( $custom, true ) ) {
	$fail( 'Custom CSP was not preserved exactly.' );
}

$frontend_paths = array(
	'/product/example/?attribute_pa_size=160',
	'/shop/?page=2',
	'/contact/',
);
foreach ( $frontend_paths as $path ) {
	if ( ! $policy->allows_dynamic_scripts( true, false, $path ) ) {
		$fail( 'Frontend compatibility was incorrectly rejected.' );
	}
}

$blocked_paths = array(
	'/wp-admin/options-general.php',
	'/wp-login.php?action=logout',
	'/wp-json/wc/store/v1/cart?context=view',
	'/wp-json?context=view',
);
foreach ( $blocked_paths as $path ) {
	if ( $policy->allows_dynamic_scripts( true, false, $path ) ) {
		$fail( 'Backend or API compatibility was incorrectly allowed.' );
	}
}

if ( $policy->allows_dynamic_scripts( true, true, '/product/example/' ) ) {
	$fail( 'Admin context incorrectly allowed dynamic scripts.' );
}

if ( $policy->allows_dynamic_scripts( true, false, '' ) ) {
	$fail( 'Malformed request context did not fail closed.' );
}

/*
 * Generated-policy builder, presets, source validation, policy sanitising and warnings.
 */

$check = static function ( $condition, $message ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $message );
	}
};

$parse = static function ( $policy ) {
	$out = array();
	foreach ( explode( ';', $policy ) as $piece ) {
		$tokens = preg_split( '/\s+/', trim( $piece ), -1, PREG_SPLIT_NO_EMPTY );
		if ( empty( $tokens ) ) {
			continue;
		}
		$name         = array_shift( $tokens );
		$out[ $name ] = $tokens;
	}
	return $out;
};

$has_warning = static function ( array $warnings, $needle ) {
	foreach ( $warnings as $warning ) {
		if ( false !== strpos( $warning, $needle ) ) {
			return true;
		}
	}
	return false;
};

$golden_default = "default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com https://www.googletagmanager.com https://googleads.g.doubleclick.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://www.googletagmanager.com https://challenges.cloudflare.com; img-src 'self' data: https:; font-src 'self' data: https://fonts.gstatic.com; connect-src 'self' https: https://www.google-analytics.com https://region1.google-analytics.com https://analytics.google.com https://stats.g.doubleclick.net; frame-src 'self' https://challenges.cloudflare.com https://maps.google.com https://www.google.com https://www.googletagmanager.com; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none';";

// Default policy is byte-identical to the golden string, and dynamic mode only adds unsafe-eval to script-src.
$check( $golden_default === $policy->build( '', false ), 'Default CSP output changed unexpectedly.' );
$check( $golden_default === $policy->build_generated( array(), array(), array() ), 'build_generated() without edits does not match the default policy.' );
$check(
	str_replace( 'https://googleads.g.doubleclick.net;', "https://googleads.g.doubleclick.net 'unsafe-eval';", $golden_default ) === $policy->build( '', true ),
	'Dynamic CSP differs from the default by more than unsafe-eval.'
);
$check( $golden_default === $policy->build_generated( array( 'no_such_preset' ), array(), array() ), 'Unknown preset key changed the policy.' );

// Directive lists and presets.
$check(
	array( 'default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'frame-src', 'media-src', 'worker-src', 'manifest-src' ) === ADC_Security_Csp_Policy::get_directives(),
	'Editable directive list changed unexpectedly.'
);

$defaults = ADC_Security_Csp_Policy::get_default_sources();
$check( array_keys( $defaults ) === array( 'default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src', 'frame-src' ), 'Default source directives changed unexpectedly.' );
$check( in_array( 'https://analytics.google.com', $defaults['connect-src'], true ), 'Google Analytics connect source is missing from defaults.' );
$check( in_array( 'https://stats.g.doubleclick.net', $defaults['connect-src'], true ), 'Doubleclick stats connect source is missing from defaults.' );
$check( in_array( 'https://www.googletagmanager.com', $defaults['frame-src'], true ), 'GTM frame source is missing from defaults.' );
foreach ( $defaults as $directive => $sources ) {
	$check( in_array( $directive, ADC_Security_Csp_Policy::get_directives(), true ), "Default source directive {$directive} is not editable." );
}

$presets = ADC_Security_Csp_Policy::get_service_presets();
$expected_presets = array( 'gtm', 'ga4', 'google_ads', 'turnstile', 'google_fonts', 'google_maps', 'youtube', 'vimeo', 'stripe', 'paypal', 'recaptcha', 'facebook_pixel' );
$check( $expected_presets === array_keys( $presets ), 'Service preset keys changed unexpectedly.' );
foreach ( $presets as $key => $preset ) {
	$check( isset( $preset['label'] ) && '' !== $preset['label'], "Preset {$key} has no label." );
	$check( isset( $preset['description'] ) && '' !== $preset['description'], "Preset {$key} has no description." );
	$check( isset( $preset['directives'] ) && is_array( $preset['directives'] ) && ! empty( $preset['directives'] ), "Preset {$key} has no directives." );
	foreach ( $preset['directives'] as $directive => $sources ) {
		$check( in_array( $directive, ADC_Security_Csp_Policy::get_directives(), true ), "Preset {$key} uses non-editable directive {$directive}." );
		foreach ( $sources as $source ) {
			$check( $source === ADC_Security_Csp_Policy::sanitize_source( $source ), "Preset {$key} has an invalid source: {$source}." );
		}
	}
}

$stripe = $parse( $policy->build_generated( array( 'stripe' ), array(), array() ) );
$check( in_array( 'https://js.stripe.com', $stripe['script-src'], true ), 'Stripe preset did not add js.stripe.com to script-src.' );
$check( in_array( 'https://hooks.stripe.com', $stripe['frame-src'], true ), 'Stripe preset did not add hooks.stripe.com to frame-src.' );
$check( in_array( 'https://api.stripe.com', $stripe['connect-src'], true ), 'Stripe preset did not add api.stripe.com to connect-src.' );

$paypal = $parse( $policy->build_generated( array( 'paypal' ), array(), array() ) );
$check( in_array( 'https://www.paypalobjects.com', $paypal['script-src'], true ), 'PayPal preset did not add paypalobjects to script-src.' );

$recaptcha = $parse( $policy->build_generated( array( 'recaptcha' ), array(), array() ) );
$check( in_array( 'https://www.google.com/recaptcha/', $recaptcha['script-src'], true ), 'reCAPTCHA preset did not add its script path.' );
$check( in_array( 'https://www.gstatic.com/recaptcha/', $recaptcha['script-src'], true ), 'reCAPTCHA preset did not add gstatic path.' );

$turnstile_parsed = $parse( $policy->build_generated( array( 'turnstile', 'turnstile', 'gtm' ), array(), array() ) );
$check( 1 === count( array_keys( $turnstile_parsed['script-src'], 'https://challenges.cloudflare.com', true ) ), 'Repeated preset duplicated a source in script-src.' );
$check( 1 === count( array_keys( $turnstile_parsed['script-src'], 'https://www.googletagmanager.com', true ) ), 'Preset overlapping with a default duplicated a source.' );

// sanitize_source: accepted forms.
$valid_sources = array(
	"'self'"                 => "'self'",
	"'UNSAFE-INLINE'"        => "'unsafe-inline'",
	"'none'"                 => "'none'",
	"'unsafe-eval'"          => "'unsafe-eval'",
	"'strict-dynamic'"       => "'strict-dynamic'",
	"'wasm-unsafe-eval'"     => "'wasm-unsafe-eval'",
	"'nonce-abc123+/=_-'"    => "'nonce-abc123+/=_-'",
	"'sha256-AbCd+/=='"      => "'sha256-AbCd+/=='",
	"'sha384-AbCd'"          => "'sha384-AbCd'",
	"'sha512-AbCd'"          => "'sha512-AbCd'",
	'https:'                 => 'https:',
	'data:'                  => 'data:',
	'blob:'                  => 'blob:',
	'wss:'                   => 'wss:',
	'*'                      => '*',
	'https://example.com'    => 'https://example.com',
	'example.com'            => 'example.com',
	'*.example.com'          => '*.example.com',
	'https://*.example.com'  => 'https://*.example.com',
	'https://*.example.com:443/path' => 'https://*.example.com:443/path',
	'localhost:8080'         => 'localhost:8080',
	'http://127.0.0.1:8080'  => 'http://127.0.0.1:8080',
	'https://example.com:*'  => 'https://example.com:*',
	'https://example.com/path/to/file.js' => 'https://example.com/path/to/file.js',
	'https://www.google.com/recaptcha/'  => 'https://www.google.com/recaptcha/',
);
foreach ( $valid_sources as $input => $expected ) {
	$check( $expected === ADC_Security_Csp_Policy::sanitize_source( $input ), "sanitize_source() rejected or changed a valid source: {$input}" );
}

// sanitize_source: rejected forms.
$invalid_sources = array(
	'',
	' ',
	'example',
	'https://',
	'https://exa mple.com',
	' example.com',
	'example.com ',
	"example.com\r\n",
	"https://example.com\nX: y",
	"https://example.com\r",
	'https://example.com;',
	'https://a.com,https://b.com',
	'https://example.com"',
	"https://<script>",
	'https://example.com>',
	'https://example.com:70000',
	'https://-bad.com',
	'https://bad-.com',
	'https://exa_mple.com',
	'https://exämple.com',
	'javascript:alert(1)',
	'https://example.com/pa th',
	"'foo'",
	"'self",
	'self',
	"'unsafe-inline';",
	"'nonce-'",
	"'sha256-a b'",
	'Set-Cookie: x=1',
	'x=1',
	"\x00https://a.com",
	'https://example.com\\evil',
	null,
	123,
	array( 'https://example.com' ),
);
foreach ( $invalid_sources as $input ) {
	$check( '' === ADC_Security_Csp_Policy::sanitize_source( $input ), 'sanitize_source() accepted an invalid source: ' . var_export( $input, true ) );
}

// build_generated: extra sources are sanitised and unknown directives dropped.
$extra = $parse( $policy->build_generated(
	array(),
	array(
		'script-src'     => array( 'https://cdn.example.com', 'javascript:alert(1)', 'https://x.com;evil.com', 'https://ok.example.org/a', "https://y.com\r\nSet-Cookie: x=1" ),
		'frame-ancestors' => array( 'https://evil.com' ),
		'object-src'     => array( 'https://plugin.example.com' ),
		'foo-src'        => array( 'https://a.com' ),
	),
	array()
) );
$check( in_array( 'https://cdn.example.com', $extra['script-src'], true ), 'Valid extra script source was dropped.' );
$check( in_array( 'https://ok.example.org/a', $extra['script-src'], true ), 'Valid extra script source with path was dropped.' );
$check( ! in_array( 'javascript:alert(1)', $extra['script-src'], true ), 'Invalid extra scheme was kept.' );
$check( ! in_array( 'https://x.com;evil.com', $extra['script-src'], true ), 'Extra source containing a semicolon was kept.' );
$check( array( "'self'" ) === $extra['frame-ancestors'] && ! isset( $extra['foo-src'] ), 'Fixed or unknown directive was editable.' );
$check( ! array_key_exists( 'object-src', $extra ) || array( "'none'" ) === $extra['object-src'], 'Extra object-src overrode the fixed value.' );
$check( false === strpos( $policy->build_generated( array(), array( 'script-src' => array( "https://y.com\r\nSet-Cookie: x=1" ) ), array() ), "\r" ), 'CR leaked from extra source.' );
$check( false === strpos( $policy->build_generated( array(), array( 'script-src' => array( "https://y.com\r\nSet-Cookie: x=1" ) ), array() ), 'Set-Cookie' ), 'Header injection text leaked from extra source.' );

// Extra sources added to a directive already in the default are not duplicated.
$dup = $parse( $policy->build_generated( array(), array( 'connect-src' => array( 'https:', 'https://www.google-analytics.com' ) ), array() ) );
$check( 1 === count( array_keys( $dup['connect-src'], 'https:', true ) ), 'Extra source duplicated a default source.' );

// build_generated: removed defaults.
$removed = $parse( $policy->build_generated( array(), array(), array( 'script-src' => array( 'https://googleads.g.doubleclick.net', "'unsafe-inline'" ) ) ) );
$check( ! in_array( 'https://googleads.g.doubleclick.net', $removed['script-src'], true ), 'Removed default script source is still present.' );
$check( ! in_array( "'unsafe-inline'", $removed['script-src'], true ), "Removed 'unsafe-inline' is still present." );
$check( in_array( 'https://challenges.cloudflare.com', $removed['script-src'], true ), 'Unrelated default script source was removed.' );

$kept_self = $parse( $policy->build_generated( array(), array(), array( 'default-src' => array( "'self'" ) ) ) );
$check( array( "'self'" ) === $kept_self['default-src'], "'self' was removed from default-src." );

$removed_self_script = $parse( $policy->build_generated( array(), array(), array( 'script-src' => array( "'self'" ) ) ) );
$check( ! in_array( "'self'", $removed_self_script['script-src'], true ), "'self' could not be removed from script-src." );

$emptied = $policy->build_generated( array(), array(), array( 'img-src' => array( "'self'", 'data:', 'https:' ) ) );
$check( false !== strpos( $emptied, "img-src 'none';" ), 'Emptied directive did not fall back to none.' );
$check( array( "'none'" ) === $parse( $emptied )['img-src'], 'Emptied img-src was not exactly none.' );

$removed_preset = $parse( $policy->build_generated( array( 'stripe' ), array(), array( 'script-src' => array( 'https://js.stripe.com' ) ) ) );
$check( ! in_array( 'https://js.stripe.com', $removed_preset['script-src'], true ), 'Removal did not win over a preset that added the same source.' );

$removed_unknown = $policy->build_generated( array(), array(), array( 'no-such-dir' => array( 'https://a.com' ), 'frame-ancestors' => array( "'self'" ) ) );
$check( $golden_default === $removed_unknown, 'Removing an unknown or fixed directive changed the policy.' );

// build_generated: fixed directives, dynamic scripts, report-uri, stability.
$fixed = $parse( $policy->build_generated( array( 'stripe', 'youtube' ), array(), array() ) );
$check( array( "'self'" ) === $fixed['frame-ancestors'] && array( "'self'" ) === $fixed['base-uri'] && array( "'self'" ) === $fixed['form-action'] && array( "'none'" ) === $fixed['object-src'], 'Fixed directives are not as specified.' );

$dynamic = $parse( $policy->build_generated( array(), array(), array(), true ) );
$check( in_array( "'unsafe-eval'", $dynamic['script-src'], true ), 'Dynamic mode did not add unsafe-eval.' );

$report = $policy->build_generated( array(), array(), array(), false, 'https://example.com/csp-report' );
$check( substr( $report, -strlen( 'report-uri https://example.com/csp-report;' ) ) === 'report-uri https://example.com/csp-report;', 'report-uri was not appended.' );

foreach ( array( 'javascript:alert(1)', "'self'", "https://a.com; script-src *", "https://a.com\r\nSet-Cookie: x=1", '/relative' ) as $bad_report ) {
	$check( false === strpos( $policy->build_generated( array(), array(), array(), false, $bad_report ), 'report-uri' ), 'Unsafe report-uri was accepted: ' . var_export( $bad_report, true ) );
}

$generated = $policy->build_generated( array( 'ga4', 'google_ads', 'youtube' ), array( 'img-src' => array( 'https://img.example.com' ) ), array( 'font-src' => array( 'data:' ) ), true, 'https://example.com/r' );
$check( $generated === $policy->build_generated( array( 'ga4', 'google_ads', 'youtube' ), array( 'img-src' => array( 'https://img.example.com' ) ), array( 'font-src' => array( 'data:' ) ), true, 'https://example.com/r' ), 'Generated policy is not stable across calls.' );
$check( 0 === strpos( $generated, 'default-src ' ), 'Generated policy does not start with default-src.' );
$check( false === strpos( $generated, "\r" ) && false === strpos( $generated, "\n" ), 'Generated policy contains a line break.' );
$check( substr( $generated, -1 ) === ';', 'Generated policy does not end with a semicolon.' );

// sanitize_policy: normal, multiline and whitespace handling.
$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self';\n  script-src 'self'   https://cdn.example.com;\r\n\r\nimg-src *;\n" );
$check( "default-src 'self'; script-src 'self' https://cdn.example.com; img-src *;" === $result['value'], 'Multiline policy was not normalised: ' . $result['value'] );
$check( array() === $result['errors'], 'Valid multiline policy produced errors.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'" );
$check( "default-src 'self';" === $result['value'], 'Missing trailing semicolon was not added.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( 'DEFAULT-SRC \'self\'' );
$check( "default-src 'self';" === $result['value'], 'Directive names were not case-normalised.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; report-uri https://example.com/r; report-to csp-group; upgrade-insecure-requests; block-all-mixed-content; sandbox allow-forms allow-scripts" );
$check( array() === $result['errors'], 'Full valid policy produced errors: ' . implode( ' | ', $result['errors'] ) );
$check( false !== strpos( $result['value'], 'sandbox allow-forms allow-scripts;' ), 'Sandbox flags were lost.' );
$check( false !== strpos( $result['value'], 'upgrade-insecure-requests;' ), 'Flag directive was lost.' );

// sanitize_policy: CRLF and header-injection attempts.
$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'\r\nSet-Cookie: x=1" );
$check( false === strpos( $result['value'], "\r" ) && false === strpos( $result['value'], "\n" ), 'CRLF survived sanitising.' );
$check( false === stripos( $result['value'], 'set-cookie' ), 'Injected header text survived sanitising.' );
$check( "default-src 'self';" === $result['value'], 'CRLF injection did not leave only the real directive: ' . $result['value'] );
$check( count( $result['errors'] ) >= 1, 'CRLF injection produced no error message.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self';\r\nSet-Cookie: x=1" );
$check( "default-src 'self';" === $result['value'], 'Injected directive after a semicolon survived.' );
$check( false !== strpos( implode( ' ', $result['errors'] ), 'set-cookie:' ), 'Injected directive produced no unknown-directive error.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'\rX-Evil: 1\nScript-Src *" );
$check( false === strpos( $result['value'], "\r" ) && false === strpos( $result['value'], "\n" ), 'Bare CR or LF survived sanitising.' );

// sanitize_policy: invalid pieces dropped with messages.
$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self' https://bad host.com; script-src https://exa\$mple.com" );
$check( "default-src 'self' host.com;" === $result['value'], 'Invalid hosts were not dropped: ' . $result['value'] );
$check( count( $result['errors'] ) >= 2, 'Invalid hosts produced too few errors.' );
$check( false === strpos( $result['value'], 'script-src' ), 'Directive with only invalid sources was kept.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "foo-src 'self'; default-src 'self'" );
$check( "default-src 'self';" === $result['value'], 'Unknown directive was not dropped.' );
$check( false !== strpos( implode( ' ', $result['errors'] ), 'foo-src' ), 'Unknown directive produced no error.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'; default-src 'none'" );
$check( "default-src 'self';" === $result['value'], 'Duplicate directive did not keep the first.' );
$check( 1 === count( $result['errors'] ), 'Duplicate directive produced wrong error count.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'; script-src 'self' 'nonce-'; report-uri 'self'" );
$check( "default-src 'self'; script-src 'self';" === $result['value'], 'Invalid quoted nonce or quoted report-uri was kept: ' . $result['value'] );

$result = ADC_Security_Csp_Policy::sanitize_policy( 'report-to a b' );
$check( '' === $result['value'], 'report-to with several groups was kept.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "default-src 'self'; upgrade-insecure-requests now" );
$check( "default-src 'self'; upgrade-insecure-requests;" === $result['value'], 'Flag directive kept a value.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( "sandbox allow-forms evil<script>" );
$check( 'sandbox allow-forms;' === $result['value'], 'Invalid sandbox flag was kept: ' . $result['value'] );

// sanitize_policy: fully invalid or empty input.
$result = ADC_Security_Csp_Policy::sanitize_policy( 'bogus-src https://a.com' );
$check( '' === $result['value'] && ! empty( $result['errors'] ), 'Fully invalid policy did not return an empty value with errors.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( '   ' );
$check( '' === $result['value'] && array() === $result['errors'], 'Blank policy was not treated as empty.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( '' );
$check( '' === $result['value'] && array() === $result['errors'], 'Empty policy was not treated as empty.' );

$result = ADC_Security_Csp_Policy::sanitize_policy( null );
$check( '' === $result['value'] && ! empty( $result['errors'] ), 'Non-string policy was not rejected.' );

// detect_warnings.
$check( array() === ADC_Security_Csp_Policy::detect_warnings( '' ), 'Empty policy produced warnings.' );
$check( array() === ADC_Security_Csp_Policy::detect_warnings( null ), 'Non-string policy produced warnings.' );

$clean = ADC_Security_Csp_Policy::detect_warnings( "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self';" );
$check( array() === $clean, 'Clean policy produced warnings: ' . implode( ' | ', $clean ) );

$risky = ADC_Security_Csp_Policy::detect_warnings( "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: * http:; object-src 'self'" );
$check( $has_warning( $risky, "'unsafe-inline'" ), 'unsafe-inline was not flagged.' );
$check( $has_warning( $risky, "'unsafe-eval'" ), 'unsafe-eval was not flagged.' );
$check( $has_warning( $risky, 'data:' ), 'data: in script-src was not flagged.' );
$check( $has_warning( $risky, 'wildcard' ), 'Wildcard in script-src was not flagged.' );
$check( $has_warning( $risky, 'http:' ), 'http: in script-src was not flagged.' );
$check( $has_warning( $risky, "object-src 'none'" ), 'Non-none object-src was not flagged.' );
$check( $has_warning( $risky, 'frame-ancestors' ), 'Missing frame-ancestors was not flagged.' );

$no_script = ADC_Security_Csp_Policy::detect_warnings( "img-src 'self'" );
$check( $has_warning( $no_script, 'No default-src or script-src' ), 'Policy without default-src or script-src was not flagged.' );

$default_wild = ADC_Security_Csp_Policy::detect_warnings( 'default-src *; object-src none; frame-ancestors none' );
$check( $has_warning( $default_wild, 'default-src uses a wildcard' ), 'Wildcard default-src was not flagged.' );
$check( $has_warning( $default_wild, "object-src 'none'" ), 'Unquoted object-src none was not flagged; it is not a valid none source.' );

$case = ADC_Security_Csp_Policy::detect_warnings( "DEFAULT-SRC 'self'; SCRIPT-SRC 'UNSAFE-INLINE'; OBJECT-SRC 'none'; FRAME-ANCESTORS 'self'" );
$check( $has_warning( $case, "'unsafe-inline'" ), 'Warnings are not case-insensitive.' );

$only_object = ADC_Security_Csp_Policy::detect_warnings( "default-src 'self'; script-src 'self'; object-src 'none'" );
$check( 1 === count( $only_object ) && $has_warning( $only_object, 'frame-ancestors' ), 'Expected exactly one frame-ancestors warning.' );

fwrite( STDOUT, "CSP policy tests passed.\n" );
