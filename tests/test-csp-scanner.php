<?php
/**
 * CSP scanner tests that do not require a WordPress installation.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );
require_once ABSPATH . 'includes/class-adc-security-csp.php';
require_once ABSPATH . 'includes/class-adc-security-csp-scanner.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$check = static function ( $condition, $message ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $message );
	}
};

$has = static function ( array $rows, $directive, $source ) {
	foreach ( $rows as $row ) {
		if ( $row['directive'] === $directive && $row['source'] === $source ) {
			return true;
		}
	}
	return false;
};

$find = static function ( array $rows, $directive, $source ) {
	foreach ( $rows as $row ) {
		if ( $row['directive'] === $directive && $row['source'] === $source ) {
			return $row;
		}
	}
	return null;
};

$scanner = 'ADC_Security_Csp_Scanner';
$site    = 'site.test';

$gtm = '<!DOCTYPE html><html><head><script>(function(w,d,s,l,i){w[l]=w[l]||[];'
	. 'var f=d.getElementsByTagName(s)[0],j=d.createElement(s);j.async=true;'
	. 'j.src="https://www.googletagmanager.com/gtm.js?id="+i;f.parentNode.insertBefore(j,f);'
	. '})(window,document,"script","dataLayer","GTM-ABC123");</script></head><body>'
	. '<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-ABC123" height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>'
	. '</body></html>';

$ga4 = '<script async src="https://www.googletagmanager.com/gtag/js?id=G-XXXX"></script>'
	. "<script>gtag('config','G-XXXX');fetch('https://www.google-analytics.com/g/collect?v=2');</script>";

$fonts = '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
	. '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter&amp;display=swap">'
	. '<link rel="preload" as="font" type="font/woff2" href="https://fonts.gstatic.com/s/inter/v1.woff2" crossorigin>'
	. "<style>@font-face { font-family: 'Inter'; src: url(https://fonts.gstatic.com/s/inter/v1.woff2) format('woff2'); }</style>";

$youtube = '<iframe width="560" src="https://www.youtube-nocookie.com/embed/abc"></iframe>';

$srcset = '<img src="https://cdn.one.net/a.jpg" srcset="https://cdn.one.net/a-2x.jpg 2x, https://img.two.org/a.jpg 1.5x, https://three.example.io/a.jpg 3x">';

$inline_css = '<div style="background-image: url(\'https://assets.bg.com/hero.png\')"></div>'
	. '<style>@import url("https://cdn.fonts.io/x.css"); .a{background:url(https://bgs.net/t.png)}</style>';

$proto = '<script src="//cdn.proto.net/lib.js"></script><img src="//img.proto.net/x.png">';

$skipped = '<img src="/local.png"><img src="relative.png"><img src="data:image/png;base64,AAAA">'
	. '<img src="blob:https://site.test/uuid"><script src="javascript:void(0)"></script>'
	. '<a href="mailto:a@b.com">m</a><a href="tel:+100">t</a><img src="about:blank"><img src="#frag">'
	. '<iframe src="https://site.test/embed"></iframe>'
	. '<img src="https://bad host.example/x.png"><img src="https://exa&#x0301;mple.ro/x.png">'
	. '<img src="https://user:pw@evil.test/x.png"><img src="wss://ws.test/x">';

$first_party_www = '<script src="https://www.site.test/x.js"></script><link rel="icon" href="https://www.site.test/favicon.ico">';

$malformed = '<html><div><script src="https://broken.cdn.org/a.js"<<<>>> <img src="https://ok.img.dev/a.png"><<script>>'
	. '<style>@import url(';

$json_ld = '<script type="application/ld+json">{"@context":"https://schema.org","logo":"https://logo.cdn.biz/x.png"}</script>';

$misc = '<form action="https://pay.partner.com/checkout"></form><embed src="https://swf.media.tv/a.swf">'
	. '<object data="https://obj.media.tv/o"></object>'
	. '<video poster="https://poster.vid.com/p.jpg"><source src="https://stream.vid.com/a.mp4"></video>';

$wss = '<script>const ws = new WebSocket("wss://realtime.chat.io/socket");</script>';

$dedupe = '<img src="https://dup.net/a.png"><img src="https://dup.net/b.png">';

$notes = '<img src="http://old.cdn.net/a.png"><img src="https://203.0.113.7/a.png"><img src="https://cdn.port.net:8443/x.png">';

$parties = '<img src="https://example.co.uk/a.png"><img src="https://www.example.co.uk/a.png">'
	. '<img src="https://cdn.example.co.uk/a.png"><img src="https://other.co.uk/a.png">'
	. '<img src="https://example.co.uk.evil.net/a.png">';

$fixture_page = $gtm . $ga4 . $fonts . $youtube . $srcset . $inline_css . $proto . $skipped . $first_party_www . $json_ld . $misc . $wss . $dedupe;

// Extraction checks. There is a single regex parser, so results do not depend on PHP extensions.
$modes = array( false );

foreach ( $modes as $prefer_dom ) {
	$label = 'regex';

	// GTM: inline loader is inferred script-src, noscript iframe is frame-src.
	$rows = $scanner::extract_sources( $gtm, $site );
	$check( $has( $rows, 'script-src', 'https://www.googletagmanager.com' ), "[$label] GTM loader not detected." );
	$check( $find( $rows, 'script-src', 'https://www.googletagmanager.com' )['inferred'] === true, "[$label] GTM inline loader should be inferred." );
	$check( $find( $rows, 'frame-src', 'https://www.googletagmanager.com' )['tag'] === 'iframe', "[$label] GTM noscript iframe not detected." );

	// GA4: gtag script is firm; collect endpoint in inline script is inferred connect-src.
	$rows = $scanner::extract_sources( $ga4, $site );
	$check( $find( $rows, 'script-src', 'https://www.googletagmanager.com' )['inferred'] === false, "[$label] GA4 script tag should be firm." );
	$check( $find( $rows, 'connect-src', 'https://www.google-analytics.com' )['inferred'] === true, "[$label] GA4 collect endpoint should be inferred." );

	// Fonts: preconnect is inferred; the @font-face url and preload both give font-src.
	$rows = $scanner::extract_sources( $fonts, $site );
	$check( $find( $rows, 'connect-src', 'https://fonts.gstatic.com' )['inferred'] === true, "[$label] preconnect should be inferred connect-src." );
	$check( $has( $rows, 'style-src', 'https://fonts.googleapis.com' ), "[$label] Google Fonts stylesheet missing." );
	$font = $find( $rows, 'font-src', 'https://fonts.gstatic.com' );
	$check( null !== $font && false === $font['inferred'], "[$label] font-src gstatic missing or inferred." );
	$check( 1 === count( array_filter( $rows, static function ( $r ) {
		return 'font-src' === $r['directive'];
	} ) ), "[$label] duplicate font-src rows for the same origin." );

	// YouTube iframe.
	$rows = $scanner::extract_sources( $youtube, $site );
	$check( $has( $rows, 'frame-src', 'https://www.youtube-nocookie.com' ), "[$label] YouTube iframe missing." );

	// srcset with several CDNs.
	$rows = $scanner::extract_sources( $srcset, $site );
	foreach ( array( 'https://cdn.one.net', 'https://img.two.org', 'https://three.example.io' ) as $origin ) {
		$check( $has( $rows, 'img-src', $origin ), "[$label] srcset origin $origin missing." );
	}

	// Inline style url() and @import.
	$rows = $scanner::extract_sources( $inline_css, $site );
	$check( $find( $rows, 'img-src', 'https://assets.bg.com' )['tag'] === 'style', "[$label] style attribute url() missing." );
	$check( $has( $rows, 'style-src', 'https://cdn.fonts.io' ), "[$label] @import origin missing." );
	$check( $has( $rows, 'img-src', 'https://bgs.net' ), "[$label] style block url() missing." );

	// Protocol-relative URLs count as https.
	$rows = $scanner::extract_sources( $proto, $site );
	$check( $has( $rows, 'script-src', 'https://cdn.proto.net' ), "[$label] protocol-relative script missing." );
	$check( $has( $rows, 'img-src', 'https://img.proto.net' ), "[$label] protocol-relative img missing." );

	// Skipped URLs must produce nothing.
	$rows = $scanner::extract_sources( $skipped, $site );
	$check( array() === $rows, "[$label] skipped URLs produced rows: " . json_encode( $rows ) );

	// Same-site www twin and other subdomains are first-party, not dropped.
	$rows = $scanner::extract_sources( $first_party_www, $site );
	$check( $find( $rows, 'script-src', 'https://www.site.test' )['party'] === 'first_sub', "[$label] www twin should be first_sub." );
	$check( $find( $rows, 'img-src', 'https://www.site.test' )['party'] === 'first_sub', "[$label] www favicon should be first_sub." );

	// Malformed HTML never throws and still yields what it can read.
	$rows = $scanner::extract_sources( $malformed, $site );
	$check( is_array( $rows ) && $has( $rows, 'img-src', 'https://ok.img.dev' ), "[$label] malformed HTML lost a valid image." );

	// JSON-LD is data, not script loading.
	$rows = $scanner::extract_sources( $json_ld, $site );
	$check( array() === $rows, "[$label] JSON-LD produced rows." );

	$rows = $scanner::extract_sources( $misc, $site );
	$check( $has( $rows, 'form-action', 'https://pay.partner.com' ), "[$label] form action missing." );
	$check( $has( $rows, 'object-src', 'https://swf.media.tv' ), "[$label] embed missing." );
	$check( $has( $rows, 'object-src', 'https://obj.media.tv' ), "[$label] object missing." );
	$check( $has( $rows, 'img-src', 'https://poster.vid.com' ), "[$label] video poster missing." );
	$check( $has( $rows, 'media-src', 'https://stream.vid.com' ), "[$label] video source missing." );

	// wss only ever as connect-src.
	$rows = $scanner::extract_sources( $wss, $site );
	$check( $has( $rows, 'connect-src', 'wss://realtime.chat.io' ), "[$label] wss connect-src missing." );

	// Duplicate sightings collapse.
	$rows = $scanner::extract_sources( $dedupe, $site );
	$check( 1 === count( array_filter( $rows, static function ( $r ) {
		return 'https://dup.net' === $r['source'];
	} ) ), "[$label] duplicate origin not collapsed." );

	// Best-practice notes.
	$rows = $scanner::extract_sources( $notes, $site );
	$check( in_array( 'insecure_http', $find( $rows, 'img-src', 'http://old.cdn.net' )['notes'], true ), "[$label] http origin not flagged." );
	$check( in_array( 'ip_host', $find( $rows, 'img-src', 'https://203.0.113.7' )['notes'], true ), "[$label] IP host not flagged." );
	$check( in_array( 'port', $find( $rows, 'img-src', 'https://cdn.port.net:8443' )['notes'], true ), "[$label] non-default port not flagged." );
	$check( null === $find( $rows, 'img-src', 'https://old.cdn.net' ), "[$label] http origin recorded with https scheme." );

	// Party classification for the site's own registrable domain.
	$rows = $scanner::extract_sources( $parties, 'example.co.uk' );
	$check( null === $find( $rows, 'img-src', 'https://example.co.uk' ), "[$label] exact site host should be skipped." );
	$check( 'first_sub' === $find( $rows, 'img-src', 'https://www.example.co.uk' )['party'], "[$label] www twin not first_sub." );
	$check( 'first_sub' === $find( $rows, 'img-src', 'https://cdn.example.co.uk' )['party'], "[$label] cdn subdomain not first_sub." );
	$check( 'third' === $find( $rows, 'img-src', 'https://other.co.uk' )['party'], "[$label] other .co.uk site not third." );
	$check( 'third' === $find( $rows, 'img-src', 'https://example.co.uk.evil.net' )['party'], "[$label] look-alike host not third." );

	// Empty input and empty site host.
	$check( array() === $scanner::extract_sources( '', $site ), "[$label] empty input did not return an empty list." );
	$rows = $scanner::extract_sources( '<img src="https://x.io/a.png">', '' );
	$check( $has( $rows, 'img-src', 'https://x.io' ), "[$label] empty site host should treat every origin as third party." );

	// Oversized input is capped and does not throw.
	$rows = $scanner::extract_sources( '<img src="https://early.net/a.png">' . str_repeat( ' ', 3 * 1024 * 1024 ), $site );
	$check( $has( $rows, 'img-src', 'https://early.net' ), "[$label] oversized input lost the early image." );
}

// The full fixture page should yield the expected set of origins.
$rows = $scanner::extract_sources( $fixture_page, $site );
foreach (
	array(
		array( 'script-src', 'https://www.googletagmanager.com' ),
		array( 'connect-src', 'https://www.google-analytics.com' ),
		array( 'style-src', 'https://fonts.googleapis.com' ),
		array( 'font-src', 'https://fonts.gstatic.com' ),
		array( 'frame-src', 'https://www.youtube-nocookie.com' ),
		array( 'img-src', 'https://three.example.io' ),
		array( 'script-src', 'https://cdn.proto.net' ),
		array( 'connect-src', 'wss://realtime.chat.io' ),
		array( 'img-src', 'https://www.site.test' ),
	) as $pair
) {
	$check( $has( $rows, $pair[0], $pair[1] ), 'Full page missing ' . $pair[0] . ' ' . $pair[1] );
}
foreach ( $rows as $row ) {
	$check( ! in_array( $row['source'], array( 'https://site.test' ), true ), 'Exact site origin leaked into results.' );
	$check( false === strpos( $row['source'], '*' ) && false === strpos( $row['source'], 'unsafe' ), 'Unsafe source produced.' );
	$check( in_array( $row['party'], array( 'first_sub', 'third' ), true ), 'Unknown party value.' );
}

// Registrable domain approximation.
$check( 'example.co.uk' === $scanner::registrable_domain( 'cdn.example.co.uk' ), 'registrable_domain failed for co.uk.' );
$check( 'example.com' === $scanner::registrable_domain( 'static.example.com' ), 'registrable_domain failed for .com.' );
$check( 'example.org.uk' === $scanner::registrable_domain( 'a.b.example.org.uk' ), 'registrable_domain failed for org.uk.' );
$check( 'localhost' === $scanner::registrable_domain( 'localhost' ), 'registrable_domain failed for single label.' );

// merge_results: counts, inferred AND across pages, ordering by directive.
$row = static function ( $directive, $source, $tag, $inferred, $party = 'third', $notes = array() ) {
	return array(
		'directive' => $directive,
		'source'    => $source,
		'tag'       => $tag,
		'inferred'  => $inferred,
		'party'     => $party,
		'notes'     => $notes,
	);
};
$per_page = array(
	'https://site.test/'      => array(
		$row( 'object-src', 'https://swf.media.tv', 'object', false ),
		$row( 'connect-src', 'https://www.google-analytics.com', 'inline', true ),
		$row( 'script-src', 'https://www.googletagmanager.com', 'script', false ),
		$row( 'img-src', 'https://cdn.one.net', 'img', false ),
		$row( 'form-action', 'https://pay.partner.com', 'form', false ),
	),
	'https://site.test/shop/' => array(
		$row( 'script-src', 'https://www.googletagmanager.com', 'inline', true ),
		$row( 'connect-src', 'https://www.google-analytics.com', 'inline', true ),
	),
);
$merged = $scanner::merge_results( $per_page );
$order  = array_map( static function ( $r ) {
	return $r['directive'];
}, $merged );
$check( array( 'script-src', 'img-src', 'connect-src', 'form-action', 'object-src' ) === $order, 'merge_results ordering wrong: ' . implode( ',', $order ) );

$gtm_row = $merged[0];
$check( 2 === $gtm_row['count'] && false === $gtm_row['inferred'] && 'script' === $gtm_row['tag'], 'GTM row count/inferred/tag wrong after merge.' );
$check( array( 'https://site.test/', 'https://site.test/shop/' ) === $gtm_row['pages'], 'GTM row pages wrong.' );
$check( true === $merged[2]['inferred'] && 2 === $merged[2]['count'], 'GA row should stay inferred when every sighting is inferred.' );
$check( 1 === $merged[1]['count'] && false === $merged[1]['inferred'], 'Single firm sighting merged incorrectly.' );

$many = array();
for ( $i = 0; $i < 12; $i++ ) {
	$many[ 'https://site.test/p' . $i ] = array( $row( 'img-src', 'https://many.net', 'img', false ) );
}
$merged = $scanner::merge_results( $many );
$check( 12 === $merged[0]['count'] && 10 === count( $merged[0]['pages'] ), 'Page list cap or count wrong.' );

$check( array() === $scanner::merge_results( array() ), 'merge_results of nothing should be empty.' );

// mark_allowed: extra sources and defaults, canonicalised.
$found = array(
	array( 'directive' => 'img-src', 'source' => 'https://cdn.one.net' ),
	array( 'directive' => 'script-src', 'source' => 'https://www.googletagmanager.com' ),
	array( 'directive' => 'frame-src', 'source' => 'https://www.youtube-nocookie.com' ),
	array( 'directive' => 'frame-src', 'source' => 'https://www.google.com' ),
);
$marked = $scanner::mark_allowed( $found, array( 'img-src' => array( 'https://cdn.one.net/' ) ) );
$check( true === $marked[0]['allowed'], 'Extra source with trailing slash not marked allowed.' );
$check( true === $marked[1]['allowed'], 'Default source not marked allowed.' );
$check( false === $marked[2]['allowed'], 'Unlisted source marked allowed.' );
$check( true === $marked[3]['allowed'], 'Default frame-src not marked allowed.' );
$check( false === $scanner::mark_allowed( array( array( 'directive' => 'img-src', 'source' => 'http://cdn.one.net' ) ), array( 'script-src' => array( 'http://cdn.one.net' ) ) )[0]['allowed'], 'Source allowed under the wrong directive.' );

// companion_hints: GTM-only page.
$gtm_found = $scanner::merge_results( array( 'https://site.test/' => $scanner::extract_sources( $gtm, $site ) ) );
$hints     = $scanner::companion_hints( $gtm_found );
$by_key    = array();
foreach ( $hints as $hint ) {
	$by_key[ $hint['preset'] ] = $hint;
}
$check( isset( $by_key['gtm'] ), 'GTM-only page produced no gtm hint.' );
$check( array( 'https://www.googletagmanager.com' ) === $by_key['gtm']['detected'], 'GTM hint detected list wrong.' );
$check( array() === $by_key['gtm']['missing'], 'GTM hint should have nothing missing (all its origins were seen).' );
$check( isset( $by_key['ga4'] ) && isset( $by_key['ga4']['missing']['connect-src'] ), 'GA4 hint should list unseen connect-src origins.' );
$check( in_array( 'https://www.google-analytics.com', $by_key['ga4']['missing']['connect-src'], true ), 'GA4 hint missing list lacks google-analytics.' );
$check( ! isset( $by_key['turnstile'] ), 'Turnstile hint returned without detection.' );

// companion_hints: nothing third-party detected.
$check( array() === $scanner::companion_hints( array() ), 'companion_hints of nothing should be empty.' );
$first_only = $scanner::merge_results( array( 'https://site.test/' => $scanner::extract_sources( $first_party_www, $site ) ) );
$check( array() === $scanner::companion_hints( $first_only ), 'First-party-only scan produced companion hints.' );
$plain = $scanner::merge_results( array( 'https://site.test/' => $scanner::extract_sources( '<p>hello</p><img src="/a.png">', $site ) ) );
$check( array() === $scanner::companion_hints( $plain ), 'Plain page produced companion hints.' );

// validate_stored: malformed input is dropped, good rows survive.
$check( array() === $scanner::validate_stored( array() ), 'validate_stored accepted an empty array.' );
$check( array() === $scanner::validate_stored( array( 'time' => 'bad' ) ), 'validate_stored accepted a string time.' );
$check( array() === $scanner::validate_stored( 'nope' ), 'validate_stored accepted a string.' );
$stored = $scanner::validate_stored(
	array(
		'time'         => 1700000000,
		'urls'         => array( 'https://site.test/', 42 ),
		'errors'       => array( 'https://site.test/x' => 'HTTP 404', 'https://site.test/y' => array( 'bad' ) ),
		'found'        => array(
			array(
				'directive' => 'img-src',
				'source'    => 'https://cdn.one.net',
				'tag'       => 'img',
				'inferred'  => false,
				'party'     => 'first_sub',
				'notes'     => array( 'port', 5 ),
				'pages'     => array( 'https://site.test/' ),
				'count'     => 1,
			),
			array( 'directive' => 'img-src', 'source' => 'https://broken.net' ),
		),
		'existing_csp' => "default-src 'self'",
	)
);
$check( 1700000000 === $stored['time'] && array( 'https://site.test/' ) === $stored['urls'], 'validate_stored urls wrong.' );
$check( array( 'https://site.test/x' => 'HTTP 404' ) === $stored['errors'], 'validate_stored errors wrong.' );
$check( 1 === count( $stored['found'] ) && 'first_sub' === $stored['found'][0]['party'] && array( 'port' ) === $stored['found'][0]['notes'], 'validate_stored found rows wrong.' );
$check( "default-src 'self'" === $stored['existing_csp'], 'validate_stored existing_csp wrong.' );

// normalize_extra_url: same-site page addresses only, always on the home URL's scheme, host and port.
$home = 'https://www.site.test/';
$norm = static function ( $raw, $home_url = 'https://www.site.test/' ) use ( $scanner ) {
	return $scanner::normalize_extra_url( $raw, $home_url );
};
$cases = array(
	array( '/contact', 'https://www.site.test/contact' ),
	array( 'contact', 'https://www.site.test/contact' ),
	array( 'site.test/contact?x=1', 'https://www.site.test/contact?x=1' ),
	array( 'www.site.test/contact', 'https://www.site.test/contact' ),
	array( 'https://site.test/contact', 'https://www.site.test/contact' ),
	array( 'http://www.site.test/a', 'https://www.site.test/a' ),
	array( '//site.test/a', 'https://www.site.test/a' ),
	array( 'https://site.test/a#frag', 'https://www.site.test/a' ),
	array( 'site.test:443/x', 'https://www.site.test/x' ),
	array( '  /trim  ', 'https://www.site.test/trim' ),
	array( 'https://www.site.test/', 'https://www.site.test/' ),
	array( 'https://www.site.test', 'https://www.site.test/' ),
	array( '', '' ),
	array( '   ', '' ),
	array( 'javascript:alert(1)', '' ),
	array( 'JavaScript:alert(1)', '' ),
	array( 'data:text/html,hi', '' ),
	array( 'mailto:a@site.test', '' ),
	array( 'ftp://site.test/a', '' ),
	array( 'https://user:pass@site.test/a', '' ),
	array( 'https://site.test@evil.test/a', '' ),
	array( 'https://other.test/a', '' ),
	array( 'other.test/a', '' ),
	array( 'https://evil.site.test/a', '' ),
	array( 'https://site.test:8080/a', '' ),
	array( 'https://www.site.test/a b', '' ),
	array( '/a<b', '' ),
	array( '/' . str_repeat( 'a', 499 ), 'https://www.site.test/' . str_repeat( 'a', 499 ) ),
	array( '/' . str_repeat( 'a', 500 ), '' ),
);
foreach ( $cases as $case ) {
	$got = $norm( $case[0] );
	$check( $case[1] === $got, 'normalize_extra_url(' . var_export( $case[0], true ) . ') gave ' . var_export( $got, true ) . ', expected ' . var_export( $case[1], true ) );
}

// The home URL's scheme is used when the home is plain http on the bare domain.
$check( 'http://site.test/x' === $norm( 'https://www.site.test/x', 'http://site.test/' ), 'normalize_extra_url should follow the http home URL.' );
$check( 'http://site.test/x' === $norm( '/x', 'http://site.test/' ), 'normalize_extra_url relative path should use the http home URL.' );
$check( 'https://site.test:8443/x' === $norm( '/x', 'https://site.test:8443/' ), 'normalize_extra_url should keep the home port.' );
$check( 'https://site.test:8443/x' === $norm( 'https://site.test:8443/x', 'https://site.test:8443/' ), 'normalize_extra_url should accept the home port.' );
$check( '' === $norm( '/x', 'ftp://site.test/' ), 'normalize_extra_url should reject a non-http home URL.' );
$check( '' === $norm( '/x', 'not a url' ), 'normalize_extra_url should reject an unparseable home URL.' );
$check( 3 === $scanner::MAX_EXTRA_URLS, 'MAX_EXTRA_URLS should be 3.' );

// mark_allowed: a found https:// origin is allowed by the bare 'https:' default in img-src and connect-src.
$https_found = array(
	array( 'directive' => 'img-src', 'source' => 'https://img.one.net' ),
	array( 'directive' => 'connect-src', 'source' => 'https://api.one.net' ),
	array( 'directive' => 'script-src', 'source' => 'https://cdn.one.net' ),
	array( 'directive' => 'img-src', 'source' => 'http://old.one.net' ),
	array( 'directive' => 'img-src', 'source' => 'https://listed.one.net' ),
);
$marked = $scanner::mark_allowed( $https_found, array( 'img-src' => array( 'https://listed.one.net' ) ) );
$check( true === $marked[0]['allowed'] && 'https' === $marked[0]['allowed_by'], 'https:// img-src origin should be allowed by the https scheme.' );
$check( true === $marked[1]['allowed'] && 'https' === $marked[1]['allowed_by'], 'https:// connect-src origin should be allowed by the https scheme.' );
$check( false === $marked[2]['allowed'] && '' === $marked[2]['allowed_by'], 'https:// script-src origin must not be allowed by the https scheme.' );
$check( false === $marked[3]['allowed'], 'http:// origin must not be allowed by the https scheme.' );
$check( true === $marked[4]['allowed'] && 'list' === $marked[4]['allowed_by'], 'Listed origin should be allowed by list.' );
$check( 'https://img.one.net' === $marked[0]['source'] && 'img-src' === $marked[0]['directive'], 'mark_allowed should keep existing keys.' );

// expand_presets: presets and extras merged by directive, de-duplicated, sanitised.
$expanded = $scanner::expand_presets( array( 'gtm' ), array() );
$check( array( 'https://www.googletagmanager.com' ) === $expanded['script-src'], 'expand_presets gtm script-src wrong.' );
$check( array( 'https://www.googletagmanager.com' ) === $expanded['frame-src'], 'expand_presets gtm frame-src wrong.' );
$expanded = $scanner::expand_presets(
	array( 'gtm', 'gtm', 'no_such_preset', 42 ),
	array(
		'script-src' => array( 'https://www.googletagmanager.com', 'https://x.test', 'not a source' ),
		'img-src'    => array( 'https://img.test' ),
		'bogus-src'  => array( 'https://ignored.test' ),
		'worker-src' => array(),
	)
);
$check( array( 'https://www.googletagmanager.com', 'https://x.test' ) === $expanded['script-src'], 'expand_presets should merge and de-duplicate script-src.' );
$check( array( 'https://img.test' ) === $expanded['img-src'], 'expand_presets extra img-src wrong.' );
$check( ! isset( $expanded['bogus-src'] ), 'expand_presets should drop unsupported directives.' );
$check( array_key_exists( 'worker-src', $expanded ) && array() === $expanded['worker-src'], 'expand_presets should keep an empty extra directive.' );
$check( array() === $scanner::expand_presets( array(), array() ), 'expand_presets of nothing should be empty.' );

fwrite( STDOUT, "CSP scanner tests passed.\n" );
