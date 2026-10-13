<?php
/**
 * Corpus tests for the firewall matchers. The legitimate corpus must never be
 * flagged by any matcher, and the attack corpus must always be flagged.
 *
 * The request-level helper below applies each matcher to the parameter it is
 * meant for, the same way the guards do: pagename for traversal, author
 * arguments for author injection, author_exclude for ID lists, and the REST
 * route for the batch rule. Plain ".." text in a search or title field is
 * therefore not screened, which is why "wait...what" passes here.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

require_once ABSPATH . 'includes/class-adc-security-firewall-registry.php';
require_once ABSPATH . 'includes/class-adc-security-firewall-matchers.php';
require_once ABSPATH . 'includes/class-adc-security-firewall-engine.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$assert = static function ( $condition, $message ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $message );
	}
};

$M = 'ADC_Security_Firewall_Matchers';
$E = 'ADC_Security_Firewall_Engine';

/**
 * Names of the matchers that flag a request.
 *
 * @param array  $get  Query and body parameters.
 * @param string $path Request path, optionally with a query string.
 * @return string[]
 */
$flags = static function ( array $get, $path = '' ) use ( $M ) {
	$hits = array();

	if ( isset( $get['pagename'] ) && is_string( $get['pagename'] ) && $M::contains_traversal( $get['pagename'] ) ) {
		$hits[] = 'traversal';
	}

	if ( $M::contains_author_injection_arg( $get ) ) {
		$hits[] = 'author';
	}

	if ( array_key_exists( 'author_exclude', $get ) && ! $M::is_valid_int_list( $get['author_exclude'] ) ) {
		$hits[] = 'author_exclude';
	}

	if ( $M::is_batch_route( $M::rest_route_from_request( $get, $path ) ) ) {
		$hits[] = 'batch';
	}

	return $hits;
};

// -------------------------------------------------------------------------
// Legitimate traffic: nothing may be flagged.
// -------------------------------------------------------------------------

$legitimate = array(
	'hyphenated slug'          => array( array( 'pagename' => 'my-page-name' ), '' ),
	'hierarchical slug'        => array( array( 'pagename' => 'a/b' ), '' ),
	'title with dots'          => array( array( 'title' => 'wait...what' ), '' ),
	'search with dots'         => array( array( 's' => '..hello' ), '' ),
	'search with dots, s=...'  => array( array( 's' => 'wait...what' ), '' ),
	'author id'                => array( array( 'author' => '3' ), '' ),
	'author_name'              => array( array( 'author_name' => 'jane' ), '' ),
	'author_exclude list'      => array( array( 'author_exclude' => '1,2,3' ), '' ),
	'author_exclude array'     => array( array( 'author_exclude' => array( 1, 2 ) ), '' ),
	'REST post with context'   => array( array( 'rest_route' => '/wp/v2/posts/12', 'context' => 'edit' ), '' ),
	'REST post, pretty path'   => array( array(), '/wp-json/wp/v2/posts/12?context=edit' ),
	'locale parameter'         => array( array( '_locale' => 'user' ), '' ),
	'WooCommerce store cart'   => array( array( 'rest_route' => '/wc/store/v1/cart' ), '' ),
	'WooCommerce store, path'  => array( array(), '/wp-json/wc/store/v1/cart' ),
	'batch-like word in slug'  => array( array( 'pagename' => 'batch-v1-notes' ), '' ),
	'batch-like REST prefix'   => array( array(), '/wp-json/batchy/v1' ),
);

foreach ( $legitimate as $label => $case ) {
	list( $get, $path ) = $case;
	$hits = $flags( $get, $path );
	$assert( array() === $hits, 'Legitimate traffic flagged (' . $label . '): ' . implode( ',', $hits ) . '.' );
}

// Plain traversal-looking text is only screened in the pagename, never in other fields.
$assert( array() === $flags( array( 's' => '..', 'title' => '../../x' ) ), 'Search and title fields must not be screened for "..".' );

// Legitimate ID lists pass the list check.
foreach ( array( '1,2,3', '5', '', array( 1, 2 ), array( '1,2', 3 ), 5, array() ) as $ids ) {
	$assert( $M::is_valid_int_list( $ids ), 'Valid ID list rejected: ' . json_encode( $ids ) . '.' );
}

// Sub-paths and near-miss routes that are not the batch route.
foreach ( array( '/wc/store/v1/cart', '/wp/v2/posts/12', '/batchy/v1', '/batch/v10', '/wp/v2/batch-notes', '' ) as $route ) {
	$assert( ! $M::is_batch_route( $route ), 'Non-batch route flagged as batch: ' . $route . '.' );
}

// Authenticated batch requests are still batch requests to the matcher. The
// engine lets them through because the REST batch rule only applies to
// anonymous requests.
$assert( $M::is_batch_route( '/batch/v1' ), 'Batch route must be recognised for the engine to decide on it.' );

$allowed = $E::decide(
	array(
		'rule_id'     => 'block_rest_batch_unauth',
		'wp_version'  => '6.9.4',
		'logged_in'   => true,
		'can_edit'    => false,
		'matched'     => true,
	),
	array(
		'enabled' => 1,
		'mode'    => 'enforce',
		'rules'   => array( 'block_rest_batch_unauth' => 'on' ),
	)
);
$assert( 'allow' === $allowed['action'], 'Logged-in batch request must be allowed on 6.9.4 (' . $allowed['reason'] . ').' );

// -------------------------------------------------------------------------
// Attack traffic: every case must be flagged.
// -------------------------------------------------------------------------

$attacks = array(
	'double-encoded traversal'   => array( array( 'pagename' => 'templates%252E%252E%252F%252E%252E%252Findex' ), '' ),
	'triple-encoded traversal'   => array( array( 'pagename' => 'templates%25252E%25252E%25252Findex' ), '' ),
	'encoded dots and slash'     => array( array( 'pagename' => '%2e%2e%2fwp-config' ), '' ),
	'null byte in pagename'      => array( array( 'pagename' => "about\0" ), '' ),
	'SQL in author_exclude'      => array( array( 'author_exclude' => "1) OR SLEEP(5)--" ), '' ),
	'SQL in author__not_in'      => array( array( 'author__not_in' => "1) OR SLEEP(5)--" ), '' ),
	'batch route'                => array( array( 'rest_route' => '/batch/v1' ), '' ),
	'batch route, double slash'  => array( array( 'rest_route' => '//batch/v1' ), '' ),
	'batch route, upper case'    => array( array( 'rest_route' => '/BATCH/v1/' ), '' ),
	'batch route, encoded slash' => array( array( 'rest_route' => '%2Fbatch%2Fv1' ), '' ),
	'batch route, wp-json path'  => array( array(), '/wp-json/batch/v1' ),
);

foreach ( $attacks as $label => $case ) {
	list( $get, $path ) = $case;
	$assert( array() !== $flags( $get, $path ), 'Attack not flagged: ' . $label . '.' );
}

// The encoded traversal must be caught by the matcher itself, not only by the request helper.
$assert( $M::contains_traversal( 'templates%252E%252E%252F%252E%252E%252Findex' ), 'Double-encoded traversal not detected.' );
$assert( $M::contains_traversal( 'templates%25252E%25252E%25252Findex' ), 'Triple-encoded traversal not detected.' );
$assert( $M::contains_traversal( "about\0" ), 'Null byte not detected.' );

// Injected author arguments in nested bracket notation.
$assert(
	$M::contains_author_injection_arg( array( 'author__not_in' => array( "1) OR SLEEP(5)--" ) ) ),
	'Nested author__not_in injection not detected.'
);

// Non-list values and SQL-ish characters are rejected for ID lists.
foreach ( array( '1) OR SLEEP(5)--', '1 OR 1=1', '1--', '1,2)', "1'", '1;DROP', array( array( 1 ) ), array( 1.5 ), true, null ) as $bad ) {
	$assert( ! $M::is_valid_int_list( $bad ), 'Hostile or invalid ID list accepted: ' . json_encode( $bad ) . '.' );
}

// Lists longer than 100 items are rejected.
$assert( $M::is_valid_int_list( array_fill( 0, 100, 1 ) ), 'A list of exactly 100 items must be accepted.' );
$assert( ! $M::is_valid_int_list( array_fill( 0, 101, 1 ) ), 'A list of 101 items must be rejected.' );
$assert( ! $M::is_valid_int_list( implode( ',', array_fill( 0, 101, 1 ) ) ), 'A 101-item comma string must be rejected.' );

// -------------------------------------------------------------------------
// REST route extraction
// -------------------------------------------------------------------------

$assert( '/batch/v1' === $M::rest_route_from_request( array( 'rest_route' => '/batch/v1' ), '/' ), 'rest_route query parameter must win.' );
$assert( '/batch/v1' === $M::rest_route_from_request( array(), '/wp-json/batch/v1' ), 'Pretty permalink route must be extracted.' );
$assert( '/batch/v1' === $M::rest_route_from_request( array(), '/wp-json/batch/v1?x=1' ), 'Query string must be dropped from the pretty route.' );
$assert( '/' === $M::rest_route_from_request( array(), '/wp-json' ), 'Bare /wp-json must resolve to the index route.' );
$assert( '' === $M::rest_route_from_request( array(), '/about-us' ), 'A non-REST path must return an empty route.' );
$assert( '' === $M::rest_route_from_request( array( 'rest_route' => '' ), '' ), 'Empty inputs must return an empty route.' );

// -------------------------------------------------------------------------
// Probe paths (block_vulnerability_probes): probes must match, pages must not.
// -------------------------------------------------------------------------

$probes = array(
	'/.env',
	'/.env.local',
	'/.env.production',
	'/.git/config',
	'/.git/HEAD',
	'/.svn/entries',
	'/.hg/hgrc',
	'/.aws/credentials',
	'/.ssh/id_rsa',
	'/.DS_Store',
	'/phpmyadmin',
	'/PHPMYADMIN/',
	'/pma/index.php',
	'/adminer.php',
	'/vendor/phpunit/phpunit/phpunit',
	'/wp-config.php.bak',
	'/wp-config.php.old',
	'/wp-config.php.save',
	'/wp-content/debug.log',
	'/backup.sql',
	'/dump.sql',
	'/database.sql',
	'/id_rsa',
	'/xmlrpc.php.bak',
	'/%2e%65nv',
	'/%252e%2565nv',
	'/%2E%65%6E%76',
	'/.ENV?x=1',
	'//.env',
	'/.git/config?foo=bar',
	'/.git',
);

foreach ( $probes as $path ) {
	$assert( $M::is_probe_path( $path ), 'Probe path not matched: ' . $path . '.' );
}

$not_probes = array(
	'/blog/env-variables/',
	'/wp-content/uploads/2024/05/photo.jpg',
	'/shop/',
	'/contact/',
	'/wp-content/plugins/x/style.css',
	'/feed/',
	'/sitemap.xml',
	'/robots.txt',
	'/favicon.ico',
	'/.well-known/acme-challenge/token',
	'/.well-known/security.txt',
	'/.well-known/',
	'/.environment',
	'/.gitignore',
	'/.git-notes/',
	'/pmastuff/',
	'/adminers/',
	'/wp-config.php',
	'/wp-content/debug-info/',
	'/id_rsa_notes/',
	'',
	'/',
);

foreach ( $not_probes as $path ) {
	$assert( ! $M::is_probe_path( $path ), 'Ordinary path matched as a probe: ' . $path . '.' );
}

// Query strings and fragments are ignored; the normalised value is lower-case and decoded.
$assert( '/.env' === $M::normalize_probe_path( '/%2E%65NV?x=1#top' ), 'Probe path normalisation must decode, lower-case and drop the query.' );
$assert( '/shop/' === $M::normalize_probe_path( 'shop/' ), 'A relative path must gain a leading slash.' );
$assert( '' === $M::normalize_probe_path( '' ), 'An empty path must normalise to an empty string.' );

echo 'Firewall corpus tests passed.' . PHP_EOL;
