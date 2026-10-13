<?php
/**
 * Firewall registry tests that do not require a WordPress installation.
 * They cover the version matrix (affected, fixed and not-affected versions),
 * the state precedence rules, and the integrity of the rule data.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

require_once ABSPATH . 'includes/class-adc-security-firewall-registry.php';

$fail = static function ( $message ) {
	fwrite( STDERR, $message . PHP_EOL );
	exit( 1 );
};

$assert = static function ( $condition, $message ) use ( $fail ) {
	if ( ! $condition ) {
		$fail( $message );
	}
};

$R = 'ADC_Security_Firewall_Registry';

$rest  = 'block_rest_batch_unauth';
$author = 'reject_author_query_injection';
$lfi   = 'block_page_template_traversal';

$enforce = array(
	'enabled' => 1,
	'mode'    => 'enforce',
	'rules'   => array(
		$rest   => 'on',
		$author => 'on',
		$lfi    => 'on',
	),
);

// -------------------------------------------------------------------------
// Rule ids
// -------------------------------------------------------------------------

$probe  = 'block_vulnerability_probes';
$search = 'limit_anonymous_search';

$assert(
	array( $rest, $author, $lfi, $probe, $search ) === $R::get_rule_ids(),
	'Expected the three CVE rule ids, then the two generic rule ids, in registry order.'
);
$assert(
	array( $rest, $author, $lfi, $probe, $search ) === array_keys( $R::all() ),
	'Rule ids must match the keys returned by all().'
);
$assert( ! $R::is_generic( $rest ) && ! $R::is_generic( $author ) && ! $R::is_generic( $lfi ), 'CVE rules must not be generic.' );
$assert( $R::is_generic( $probe ) && $R::is_generic( $search ), 'Both generic rules must be generic.' );
$assert( ! $R::is_generic( 'not_a_rule' ), 'Unknown ids must not be generic.' );
$assert( 'cve' === $R::all()[ $rest ]['kind'] && 'generic' === $R::all()[ $probe ]['kind'], 'Rule kind must be cve or generic.' );
$assert( 'Stop vulnerability scanners' === $R::all()[ $probe ]['title'], 'Unexpected title for the probe rule.' );
$assert( 'Limit repeated searches' === $R::all()[ $search ]['title'], 'Unexpected title for the search rule.' );
$assert( '' === $R::all()[ $probe ]['cve'] && '' === $R::all()[ $search ]['cve'], 'Generic rules must have an empty cve.' );

// Generic rules: never not_needed, for any version, with or without the firewall.
$generic_versions = array( '6.9.4', '7.2', '7.2-beta1', '4.6.9', '', 'garbage' );
$generic_enforce = array(
	'enabled' => 1,
	'mode'    => 'enforce',
	'rules'   => array(
		$probe  => 'on',
		$search => 'on',
	),
);

foreach ( array( $probe, $search ) as $generic_id ) {
	foreach ( $generic_versions as $version ) {
		$assert(
			'active' === $R::status( $generic_id, $version, $generic_enforce )['state'],
			'Generic rule ' . $generic_id . ' must be active on "' . $version . '" when enabled and enforced.'
		);
		$assert( ! $R::is_fixed( $generic_id, $version ), 'Generic rule ' . $generic_id . ' must never be fixed.' );
	}

	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 0, 'mode' => 'enforce', 'rules' => array( $generic_id => 'on' ) ) )['state'], 'Firewall off must disable ' . $generic_id . '.' );
	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $generic_id => 'off' ) ) )['state'], 'Rule off must disable ' . $generic_id . '.' );
	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array() ) )['state'], 'Missing rule must disable ' . $generic_id . '.' );
	$assert( 'monitor' === $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'monitor', 'rules' => array( $generic_id => 'on' ) ) )['state'], 'Monitor mode must monitor ' . $generic_id . '.' );
	$assert( 'monitor' === $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $generic_id => 'monitor' ) ) )['state'], 'Rule in monitor must monitor ' . $generic_id . '.' );
	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 0, 'mode' => 'monitor', 'rules' => array( $generic_id => 'monitor' ) ) )['state'], 'Firewall off must win over monitor for ' . $generic_id . '.' );

	// An unreliable client IP forces monitor, but a switched-off rule stays off.
	$unreliable = $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $generic_id => 'on' ), 'ip_unreliable' => true ) );
	$assert( 'monitor' === $unreliable['state'], 'Unreliable IP must put ' . $generic_id . ' in monitor.' );
	$assert( false !== strpos( $unreliable['reason'], 'proxy' ), 'Unreliable IP reason must mention the proxy.' );
	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $generic_id => 'off' ), 'ip_unreliable' => true ) )['state'], 'Unreliable IP must not re-enable an off rule.' );
	$assert( 'disabled' === $R::status( $generic_id, '7.2', array( 'enabled' => 0, 'ip_unreliable' => true, 'rules' => array( $generic_id => 'on' ) ) )['state'], 'Firewall off must win over unreliable IP.' );
}

// The unreliable-IP flag only changes generic rules; CVE rules keep their state.
$assert(
	'active' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'on' ), 'ip_unreliable' => true ) )['state'],
	'Unreliable IP must not change CVE rule states.'
);

$assert(
	'active' === $R::status( $probe, '7.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $probe => 'on' ), 'ip_unreliable' => false ) )['state'],
	'A reliable IP must leave generic rules active.'
);

// Generic rules must not change the state of CVE rules on any version.
$assert(
	'not_needed' === $R::status( $rest, '7.0.2', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'on', $probe => 'on' ) ) )['state'],
	'Enabling generic rules must not change a fixed CVE rule.'
);

// -------------------------------------------------------------------------
// Status matrix: state per version for each rule (enforce mode, rule on).
// Columns: block_rest_batch_unauth, reject_author_query_injection, block_page_template_traversal
// -------------------------------------------------------------------------

$matrix = array(
	//  version         REST batch    author__not_in   page-template
	'6.8.5'        => array( 'not_needed', 'active',     'active' ),
	'6.8.6'        => array( 'not_needed', 'not_needed', 'active' ),
	'6.9.4'        => array( 'active',     'active',     'active' ),
	'6.9.5'        => array( 'not_needed', 'not_needed', 'active' ),
	'7.0.1'        => array( 'active',     'active',     'active' ),
	'7.0.2'        => array( 'not_needed', 'not_needed', 'active' ),
	'7.1.1'        => array( 'not_needed', 'not_needed', 'active' ),
	'7.1.2'        => array( 'not_needed', 'not_needed', 'not_needed' ),
	'7.2-beta1'    => array( 'not_needed', 'not_needed', 'not_needed' ),
	''             => array( 'active',     'active',     'active' ),
	'garbage'      => array( 'active',     'active',     'active' ),
	'4.6.9'        => array( 'not_needed', 'not_needed', 'not_needed' ),
	'4.7.36'       => array( 'not_needed', 'not_needed', 'active' ),
	'4.7.37'       => array( 'not_needed', 'not_needed', 'not_needed' ),
);

$rule_order = array( $rest, $author, $lfi );

foreach ( $matrix as $version => $expected ) {
	foreach ( $rule_order as $index => $rule_id ) {
		$status = $R::status( $rule_id, $version, $enforce );

		$assert(
			isset( $status['state'], $status['reason'] ) && '' !== $status['reason'],
			'Status for ' . $rule_id . ' at "' . $version . '" must carry a state and a reason.'
		);
		$assert(
			$expected[ $index ] === $status['state'],
			sprintf( 'Version "%s", rule %s: expected %s, got %s (%s).', $version, $rule_id, $expected[ $index ], $status['state'], $status['reason'] )
		);
		$assert(
			$R::is_fixed( $rule_id, $version ) === ( 'not_needed' === $expected[ $index ] ),
			sprintf( 'is_fixed() disagrees with status() for %s at "%s".', $rule_id, $version )
		);
	}
}

// Exact reason strings for the shipped examples.
$fixed_reason = $R::status( $rest, '7.0.2', $enforce );
$assert(
	'WordPress 7.0.2 already includes the fix for CVE-2026-63030 (fixed in 7.0.2).' === $fixed_reason['reason'],
	'Unexpected fixed reason: ' . $fixed_reason['reason']
);

$not_affected = $R::status( $author, '6.7.9', $enforce );
$assert( 'not_needed' === $not_affected['state'], 'Versions below the affected range must be not needed.' );
$assert( 0 === strpos( $not_affected['reason'], 'Not affected:' ), 'Not-affected reason must start with "Not affected:".' );

// -------------------------------------------------------------------------
// State precedence: not_needed > disabled > monitor > active
// -------------------------------------------------------------------------

$assert(
	'not_needed' === $R::status( $rest, '7.0.2', array( 'enabled' => 0 ) )['state'],
	'A fixed version must stay not_needed even when the firewall is off.'
);

$assert(
	'disabled' === $R::status( $rest, '6.9.4', array( 'enabled' => 0, 'mode' => 'enforce', 'rules' => array( $rest => 'on' ) ) )['state'],
	'Firewall turned off must disable an affected rule.'
);
$assert(
	'disabled' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'off' ) ) )['state'],
	'A rule set to off must be disabled.'
);
$assert(
	'disabled' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array() ) )['state'],
	'A missing rule must be disabled.'
);
$assert(
	'disabled' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce' ) )['state'],
	'A missing rules key must disable the rule.'
);
$assert(
	'monitor' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'monitor', 'rules' => array( $rest => 'on' ) ) )['state'],
	'Monitor mode must put an affected rule in monitor state.'
);
$assert(
	'monitor' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'monitor' ) ) )['state'],
	'A rule set to monitor must be in monitor state.'
);
$assert(
	'active' === $R::status( $rest, '6.9.4', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'on' ) ) )['state'],
	'An enforced, enabled, affected rule must be active.'
);
$assert(
	'active' === $R::status( $rest, '6.9.4', array( 'enabled' => '1', 'mode' => '', 'rules' => array( $rest => 'on' ) ) )['state'],
	'String "1" for enabled must count as enabled.'
);

$assert(
	'disabled' === $R::status( 'not_a_rule', '6.9.4', $enforce )['state'],
	'An unknown rule id must be disabled.'
);

// Unknown version is treated as affected, with its own reason wording.
$unknown = $R::status( $rest, 'garbage', $enforce );
$assert( false !== strpos( $unknown['reason'], 'could not be determined' ), 'Unknown version reason must say the version is unknown.' );

// -------------------------------------------------------------------------
// Rule data integrity
// -------------------------------------------------------------------------

$required = array( 'id', 'kind', 'cve', 'title', 'summary', 'severity', 'scope', 'requires_unauth', 'affected', 'fixed', 'matcher', 'sources' );

foreach ( $R::all() as $id => $rule ) {
	foreach ( $required as $field ) {
		$assert( array_key_exists( $field, $rule ), 'Rule ' . $id . ' is missing field ' . $field . '.' );
	}

	$assert( $id === $rule['id'], 'Rule id field must equal its key (' . $id . ').' );
	$assert( in_array( $rule['severity'], array( 'critical', 'high', 'medium' ), true ), 'Bad severity on ' . $id . '.' );
	$assert( in_array( $rule['scope'], array( 'frontend', 'rest', 'any' ), true ), 'Bad scope on ' . $id . '.' );
	$assert( is_bool( $rule['requires_unauth'] ), 'requires_unauth must be bool on ' . $id . '.' );
	$assert( is_array( $rule['affected'] ) && is_array( $rule['fixed'] ) && is_array( $rule['sources'] ), 'affected, fixed and sources must be arrays on ' . $id . '.' );

	if ( 'generic' === $rule['kind'] ) {
		$assert( '' === $rule['cve'] && array() === $rule['affected'] && array() === $rule['fixed'] && array() === $rule['sources'], 'Generic rule ' . $id . ' must have no CVE, range, fix or source.' );
		continue;
	}

	$assert( 'cve' === $rule['kind'], 'Rule kind must be cve or generic on ' . $id . '.' );
	$assert( ! empty( $rule['affected'] ), 'affected must be a non-empty list on ' . $id . '.' );
	$assert( ! empty( $rule['fixed'] ), 'fixed must be a non-empty map on ' . $id . '.' );
	$assert( ! empty( $rule['sources'] ), 'sources must be a non-empty list on ' . $id . '.' );

	foreach ( $rule['sources'] as $url ) {
		$assert( 0 === strpos( $url, 'https://' ), 'Source URL must be https on ' . $id . '.' );
	}

	foreach ( $rule['affected'] as $range ) {
		$assert( 1 === preg_match( '/^\d+\.\d+\.\d+-\d+\.\d+\.\d+$/', $range ), 'Bad affected range "' . $range . '" on ' . $id . '.' );
	}

	// Each fixed version must sit above the affected maximum on its branch.
	foreach ( $rule['fixed'] as $branch => $fixed ) {
		$assert( 0 === strpos( $fixed, $branch . '.' ), 'Fixed version ' . $fixed . ' is not on branch ' . $branch . ' (' . $id . ').' );

		foreach ( $rule['affected'] as $range ) {
			list( , $max ) = explode( '-', $range, 2 );

			if ( 0 === strpos( $max, $branch . '.' ) ) {
				$assert( version_compare( $fixed, $max, '>' ), 'Fixed ' . $fixed . ' must be greater than affected max ' . $max . ' (' . $id . ').' );
			}
		}
	}
}

$assert( 'CVE-2026-63030' === $R::all()[ $rest ]['cve'], 'REST batch rule must reference CVE-2026-63030.' );
$assert( 'CVE-2026-60137' === $R::all()[ $author ]['cve'], 'Author rule must reference CVE-2026-60137.' );
$assert( 'CVE-2026-87902' === $R::all()[ $lfi ]['cve'], 'Traversal rule must reference CVE-2026-87902.' );

echo 'Firewall registry tests passed.' . PHP_EOL;
