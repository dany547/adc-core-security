<?php
/**
 * CSP report normalization tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-csp-reports.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$normalize = static function ( array $raw ) {
	return ADC_Security_Csp_Reports::normalize_report( $raw );
};

// Legacy application/csp-report shape.
$legacy = array(
	'csp-report' => array(
		'document-uri'        => 'https://site.test/shop/',
		'violated-directive'  => 'script-src-elem',
		'effective-directive' => 'script-src-elem',
		'blocked-uri'         => 'https://cdn.example.com/widget.js',
		'original-policy'     => "script-src 'self'",
		'disposition'         => 'enforce',
	),
);
$result = $normalize( $legacy );
if ( ! is_array( $result )
	|| 'script-src-elem' !== $result['directive']
	|| 'cdn.example.com' !== $result['host']
	|| 'https://cdn.example.com' !== $result['suggested_source']
) {
	$fail( 'Legacy csp-report shape was not normalized correctly.' );
}

// Legacy shape with only violated-directive: the first token is the directive.
$violated_only = array(
	'csp-report' => array(
		'violated-directive' => "style-src 'self' 'unsafe-inline'",
		'blocked-uri'        => 'https://fonts.example.org/css',
	),
);
$result = $normalize( $violated_only );
if ( ! is_array( $result ) || 'style-src' !== $result['directive'] ) {
	$fail( 'violated-directive fallback did not yield the first token.' );
}

// Reporting API envelope element (type csp-violation, camelCase body), with a non-default port.
$reporting_api = array(
	'type' => 'csp-violation',
	'age'  => 12,
	'url'  => 'https://site.test/',
	'body' => array(
		'documentURL'        => 'https://site.test/',
		'effectiveDirective' => 'img-src',
		'blockedURL'         => 'https://img.example.net:8443/x.png',
		'disposition'        => 'report',
	),
);
$result = $normalize( $reporting_api );
if ( ! is_array( $result )
	|| 'img-src' !== $result['directive']
	|| 'img.example.net' !== $result['host']
	|| 'https://img.example.net:8443' !== $result['suggested_source']
) {
	$fail( 'Reporting API shape was not normalized correctly.' );
}

// Other Reporting API report types are not CSP violations.
if ( null !== $normalize( array( 'type' => 'network-error', 'body' => array( 'blockedURL' => 'https://x.test/' ) ) ) ) {
	$fail( 'Non csp-violation Reporting API report was not ignored.' );
}

// Data and blob URIs have no host; the scheme becomes the host and source.
$data_uri = $normalize( array( 'csp-report' => array( 'effective-directive' => 'img-src', 'blocked-uri' => 'data:image/png;base64,AAAA' ) ) );
if ( ! is_array( $data_uri ) || 'data' !== $data_uri['host'] || 'data:' !== $data_uri['suggested_source'] ) {
	$fail( 'data: URI was not reduced to its scheme.' );
}

$blob_uri = $normalize( array( 'csp-report' => array( 'effective-directive' => 'worker-src', 'blocked-uri' => 'blob:https://site.test/1234' ) ) );
if ( ! is_array( $blob_uri ) || 'blob' !== $blob_uri['host'] || 'blob:' !== $blob_uri['suggested_source'] ) {
	$fail( 'blob: URI was not reduced to its scheme.' );
}

// Browser extensions are ignored.
$extensions = array(
	'chrome-extension://abcdefghijklmnop/content.js',
	'moz-extension://1234-5678/script.js',
	'safari-extension://com.example.ext/inject.js',
);
foreach ( $extensions as $blocked ) {
	if ( null !== $normalize( array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => $blocked ) ) ) ) {
		$fail( 'Browser extension report was not ignored: ' . $blocked );
	}
}

// Inline and eval, empty blocked URI.
foreach ( array( 'inline', 'eval', 'INLINE', '', '   ' ) as $blocked ) {
	if ( null !== $normalize( array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => $blocked ) ) ) ) {
		$fail( 'Blocked-uri "' . $blocked . '" was not ignored.' );
	}
}

// Missing blocked-uri entirely.
if ( null !== $normalize( array( 'csp-report' => array( 'effective-directive' => 'script-src' ) ) ) ) {
	$fail( 'Report without blocked-uri was not ignored.' );
}

// Garbage and malformed input.
$garbage = array(
	array(),
	array( 'csp-report' => 'not-an-array' ),
	array( 'csp-report' => array() ),
	array( 'type' => 'csp-violation', 'body' => 'string-body' ),
	array( 'csp-report' => array( 'effective-directive' => 'script-src;<script>', 'blocked-uri' => 'https://a.test/' ) ),
	array( 'csp-report' => array( 'effective-directive' => 9, 'blocked-uri' => 'https://a.test/' ) ),
	array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => 'not a url at all' ) ),
	array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => array( 'https://a.test/' ) ) ),
	array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => 'https://' . str_repeat( 'a', 300 ) . '.test/' ) ),
	array( 'csp-report' => array( 'effective-directive' => str_repeat( 'a', 200 ), 'blocked-uri' => 'https://a.test/' ) ),
);
foreach ( $garbage as $index => $raw ) {
	if ( null !== $normalize( $raw ) ) {
		$fail( 'Garbage input #' . $index . ' was not ignored.' );
	}
}

// Oversized blocked URI: only the host and scheme are kept, never the path or query.
$long_path = 'https://tracker.example.io/' . str_repeat( 'x', 5000 ) . '?token=secret';
$result    = $normalize( array( 'csp-report' => array( 'effective-directive' => 'connect-src', 'blocked-uri' => $long_path ) ) );
if ( ! is_array( $result ) || 'tracker.example.io' !== $result['host'] || 'https://tracker.example.io' !== $result['suggested_source'] ) {
	$fail( 'Long blocked URI did not reduce to host and source.' );
}

// Markup in the blocked URI must never reach stored fields.
$result = $normalize( array( 'csp-report' => array( 'effective-directive' => 'script-src', 'blocked-uri' => 'https://evil.example/"><script>alert(1)</script>' ) ) );
if ( is_array( $result ) ) {
	foreach ( $result as $value ) {
		if ( false !== strpos( $value, '<' ) || false !== strpos( $value, '"' ) || false !== strpos( $value, ' ' ) ) {
			$fail( 'Markup leaked into a normalized field.' );
		}
	}
}

// Directive is lowercased; host is lowercased.
$result = $normalize( array( 'csp-report' => array( 'effective-directive' => 'Script-Src', 'blocked-uri' => 'HTTPS://CDN.Example.COM/a.js' ) ) );
if ( ! is_array( $result ) || 'script-src' !== $result['directive'] || 'cdn.example.com' !== $result['host'] ) {
	$fail( 'Directive or host was not normalized to lowercase.' );
}

// Request limits that handle_report() relies on.
if ( 8192 !== ADC_Security_Csp_Reports::MAX_BODY_BYTES ) {
	$fail( 'Body cap is not 8192 bytes.' );
}
foreach ( array( 'application/csp-report', 'application/reports+json', 'application/json' ) as $type ) {
	if ( ! in_array( $type, ADC_Security_Csp_Reports::ALLOWED_TYPES, true ) ) {
		$fail( 'Media type missing from allowlist: ' . $type );
	}
}
if ( 'adc-security/v1' !== ADC_Security_Csp_Reports::REST_NAMESPACE || '/csp-report' !== ADC_Security_Csp_Reports::REST_ROUTE ) {
	$fail( 'REST namespace or route changed unexpectedly.' );
}

fwrite( STDOUT, "CSP reports tests passed.\n" );
