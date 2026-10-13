<?php
/**
 * Firewall engine tests that do not require a WordPress installation. They
 * cover the allow/monitor/block decision order, the safe-mode threshold and
 * the fingerprint helper.
 */

define( 'ABSPATH', dirname( __DIR__ ) . '/' );

require_once ABSPATH . 'includes/class-adc-security-firewall-registry.php';
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

$E = 'ADC_Security_Firewall_Engine';

$rest   = 'block_rest_batch_unauth';
$author = 'reject_author_query_injection';

$enforce = array(
	'enabled' => 1,
	'mode'    => 'enforce',
	'rules'   => array(
		$rest   => 'on',
		$author => 'on',
	),
);

$base = array(
	'rule_id'        => $rest,
	'wp_version'     => '6.9.4',
	'logged_in'      => false,
	'can_edit'       => false,
	'is_cli'         => false,
	'is_cron'        => false,
	'ip_allowlisted' => false,
	'kill_switch'    => false,
	'matched'        => true,
);

$decide = static function ( array $overrides, ?array $opts = null ) use ( $E, $base, $enforce ) {
	return $E::decide( array_merge( $base, $overrides ), null === $opts ? $enforce : $opts );
};

$expect = static function ( $action, array $overrides, $message, ?array $opts = null ) use ( $decide, $assert ) {
	$result = $decide( $overrides, $opts );
	$assert( isset( $result['reason'] ) && '' !== $result['reason'], $message . ' must return a reason.' );
	$assert( $action === $result['action'], $message . ': expected ' . $action . ', got ' . $result['action'] . ' (' . $result['reason'] . ').' );
};

// -------------------------------------------------------------------------
// Basic decisions
// -------------------------------------------------------------------------

$expect( 'block', array(), 'Anonymous batch request on an affected version' );
$expect( 'allow', array( 'matched' => false ), 'Unmatched request' );
$expect( 'allow', array( 'kill_switch' => true ), 'Kill switch' );
$expect( 'allow', array( 'is_cli' => true ), 'WP-CLI request' );
$expect( 'allow', array( 'is_cron' => true ), 'Cron request' );
$expect( 'allow', array( 'ip_allowlisted' => true ), 'Allowlisted IP' );
$expect( 'allow', array( 'kill_switch' => true, 'is_cli' => false ), 'Kill switch alone' );

// Exceptions win even when the request would otherwise be blocked.
$expect( 'allow', array( 'is_cli' => true, 'ip_allowlisted' => true ), 'CLI plus allowlisted IP' );

// -------------------------------------------------------------------------
// Version and option states
// -------------------------------------------------------------------------

$expect( 'allow', array( 'wp_version' => '6.9.5' ), 'Fixed version (not_needed)' );
$expect( 'allow', array( 'wp_version' => '7.1.2' ), 'Newer branch (not_needed)' );
$expect( 'allow', array( 'wp_version' => '6.8.5' ), 'Older than affected range (not_needed)' );
$expect( 'allow', array(), 'Firewall disabled', array( 'enabled' => 0, 'mode' => 'enforce', 'rules' => array( $rest => 'on' ) ) );
$expect( 'allow', array(), 'Rule switched off', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'off' ) ) );
$expect( 'monitor', array(), 'Monitor mode', array( 'enabled' => 1, 'mode' => 'monitor', 'rules' => array( $rest => 'on' ) ) );
$expect( 'monitor', array(), 'Rule in monitor state', array( 'enabled' => 1, 'mode' => 'enforce', 'rules' => array( $rest => 'monitor' ) ) );

// Unknown rule id is never blocked.
$expect( 'allow', array( 'rule_id' => 'not_a_rule' ), 'Unknown rule id' );

// -------------------------------------------------------------------------
// Logged-in users
// -------------------------------------------------------------------------

// The REST batch rule only applies to anonymous requests.
$expect( 'allow', array( 'logged_in' => true ), 'Logged-in subscriber on unauth-only rule' );
$expect( 'allow', array( 'logged_in' => true, 'can_edit' => true ), 'Logged-in editor on unauth-only rule' );

// Author injection applies to everyone, so a logged-in subscriber is still blocked.
$expect( 'block', array( 'rule_id' => $author, 'logged_in' => true ), 'Logged-in subscriber on author injection' );

// Editors are never blocked, only logged.
$expect( 'monitor', array( 'rule_id' => $author, 'logged_in' => true, 'can_edit' => true ), 'Logged-in editor on author injection' );

// Editor flag without login does not count as an editor.
$expect( 'block', array( 'rule_id' => $author, 'logged_in' => false, 'can_edit' => true ), 'Anonymous request with can_edit set' );

// Exceptions still win over the editor rule.
$expect( 'allow', array( 'rule_id' => $author, 'logged_in' => true, 'can_edit' => true, 'is_cron' => true ), 'Editor on cron request' );

// -------------------------------------------------------------------------
// Failure handling
// -------------------------------------------------------------------------

// A rule id whose string conversion throws must fail open.
$throwing = new class() {
	public function __toString(): string {
		throw new RuntimeException( 'boom' );
	}
};

$result = $E::decide( array_merge( $base, array( 'rule_id' => $throwing ) ), $enforce );
$assert( 'allow' === $result['action'], 'An exception inside the engine must fail open.' );
$assert( '' !== $result['reason'], 'Fail-open result must carry a reason.' );

// -------------------------------------------------------------------------
// Safe mode threshold
// -------------------------------------------------------------------------

$now = 1000000;

$assert( false === $E::should_enter_safe_mode( array(), $now ), 'No blocks must not enter safe mode.' );
$assert(
	false === $E::should_enter_safe_mode( array( $now, $now - 1, $now - 2, $now - 3 ), $now ),
	'Four blocks must not trigger safe mode with the default limit of five.'
);
$assert(
	true === $E::should_enter_safe_mode( array( $now, $now - 1, $now - 2, $now - 3, $now - 4 ), $now ),
	'Five blocks inside the window must trigger safe mode.'
);
$assert(
	false === $E::should_enter_safe_mode( array( $now - 60, $now - 1, $now - 2, $now - 3, $now - 61 ), $now ),
	'A block older than the window must not count, so only four remain.'
);
$assert(
	true === $E::should_enter_safe_mode( array( $now - 60, $now - 1, $now - 2, $now - 3, $now - 4 ), $now ),
	'A block exactly at the window edge must count.'
);
$assert(
	true === $E::should_enter_safe_mode( array( $now, $now - 1, $now - 2 ), $now, 3, 60 ),
	'Custom limit of three must trigger with three recent blocks.'
);
$assert(
	false === $E::should_enter_safe_mode( array( $now, $now - 1 ), $now, 3, 60 ),
	'Two blocks must not trigger a limit of three.'
);

// -------------------------------------------------------------------------
// Fingerprint
// -------------------------------------------------------------------------

$fp = $E::fingerprint( $rest, '1 OR 1=1' );
$assert( 1 === preg_match( '/^[0-9a-f]{16}$/', $fp ), 'Fingerprint must be 16 lowercase hex characters.' );
$assert( $fp === $E::fingerprint( $rest, '1 OR 1=1' ), 'Fingerprint must be deterministic.' );
$assert( $fp !== $E::fingerprint( $author, '1 OR 1=1' ), 'Fingerprint must depend on the rule id.' );
$assert( $fp !== $E::fingerprint( $rest, '2 OR 1=1' ), 'Fingerprint must depend on the value.' );

$long = str_repeat( 'a', 512 );
$assert(
	$E::fingerprint( $rest, $long ) === $E::fingerprint( $rest, $long . 'tail-beyond-512-bytes' ),
	'Only the first 512 bytes of a value may feed the fingerprint.'
);

echo 'Firewall engine tests passed.' . PHP_EOL;
