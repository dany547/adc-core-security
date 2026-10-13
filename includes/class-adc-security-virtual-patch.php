<?php
/**
 * ADC Security Virtual Patch Class
 *
 * @deprecated 1.13.0 Replaced by ADC_Security_Firewall_Rules (includes/class-adc-security-firewall-rules.php),
 *             which enforces the same rules through the firewall registry, engine and matchers.
 *             This class no longer registers any hooks. It stays so the rule keys, the
 *             legacy option reads and the matcher method names keep working for
 *             callers and tests; the matchers delegate to ADC_Security_Firewall_Matchers.
 *
 * Rules shipped here (now defined in the firewall registry):
 * - block_page_template_traversal  CVE-2026-87902
 * - block_rest_batch_unauth        CVE-2026-63030
 * - reject_author_query_injection  CVE-2026-60137
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

require_once dirname( __FILE__ ) . '/class-adc-security-firewall-matchers.php';

class ADC_Security_Virtual_Patch {

	const RULE_PAGE_TEMPLATE_TRAVERSAL = 'block_page_template_traversal';
	const RULE_REST_BATCH_UNAUTH       = 'block_rest_batch_unauth';
	const RULE_AUTHOR_QUERY_INJECTION  = 'reject_author_query_injection';

	/**
	 * Decode passes performed while probing for encoded path traversal.
	 *
	 * @deprecated 1.13.0 Use ADC_Security_Firewall_Matchers::MAX_DECODE_PASSES.
	 */
	const MAX_DECODE_PASSES = 4;

	/**
	 * Maximum recursion depth when walking nested request arrays.
	 *
	 * @deprecated 1.13.0 Use ADC_Security_Firewall_Matchers::MAX_ARG_DEPTH.
	 */
	const MAX_ARG_DEPTH = 5;

	/**
	 * Core REST route abused by CVE-2026-63030.
	 */
	const REST_BATCH_ROUTE = '/batch/v1';

	/**
	 * Event type recorded in the Activity log.
	 */
	const EVENT_TYPE = 'virtual_patch';

	/**
	 * Constructor. Intentionally registers no hooks: ADC_Security_Firewall_Rules owns enforcement.
	 *
	 * @deprecated 1.13.0
	 */
	public function __construct() {
	}

	// -------------------------------------------------------------------------
	// Rule definitions
	// -------------------------------------------------------------------------

	/**
	 * Return the fixed rules this module can enforce.
	 *
	 * @return array<string,array<string,string>>
	 */
	public static function get_rule_definitions() {
		return array(
			self::RULE_PAGE_TEMPLATE_TRAVERSAL => array(
				'label'       => 'Block page-template path traversal',
				'description' => 'Rejects front-end requests whose pagename contains path traversal, in any encoding depth (CVE-2026-87902: unauthenticated local file inclusion / remote code execution in page-template resolution, WordPress 4.7 - 7.1.1).',
			),
			self::RULE_REST_BATCH_UNAUTH       => array(
				'label'       => 'Block unauthenticated REST batch requests',
				'description' => 'Rejects unauthenticated POSTs to /wp-json/batch/v1 (CVE-2026-63030: REST API batch route confusion, first half of the "wp2shell" pre-authentication RCE chain, WordPress 6.9.0 - 6.9.4 and 7.0.0 - 7.0.1).',
			),
			self::RULE_AUTHOR_QUERY_INJECTION  => array(
				'label'       => 'Reject author__not_in request arguments',
				'description' => 'Rejects front-end requests that pass author__not_in / author__in over HTTP (CVE-2026-60137: WP_Query SQL injection, second half of the same "wp2shell" RCE chain). Plugins that build these arguments internally are not affected.',
			),
		);
	}

	/**
	 * @return string[] Rule keys accepted by the module.
	 */
	public static function get_rule_keys() {
		return array_keys( self::get_rule_definitions() );
	}

	/**
	 * Extract the enabled rule keys from the legacy saved options.
	 *
	 * @param array $options Saved plugin options (adc_security_options).
	 * @return string[] Enabled rule keys.
	 */
	public static function get_enabled_rules( array $options ) {
		$rules = isset( $options['virtual_patch_rules'] ) && is_array( $options['virtual_patch_rules'] )
			? $options['virtual_patch_rules']
			: array();

		$rules = array_map( 'sanitize_key', array_filter( $rules, 'is_string' ) );

		return array_values( array_intersect( self::get_rule_keys(), $rules ) );
	}

	// -------------------------------------------------------------------------
	// Pure matchers (delegating; kept for compatibility)
	// -------------------------------------------------------------------------

	/**
	 * @see ADC_Security_Firewall_Matchers::contains_traversal()
	 * @param mixed $value Raw request value.
	 * @return bool
	 */
	public static function contains_traversal( $value ) {
		return ADC_Security_Firewall_Matchers::contains_traversal( $value );
	}

	/**
	 * @see ADC_Security_Firewall_Matchers::is_author_injection_arg()
	 * @param string|int $key   Argument name.
	 * @param mixed      $value Argument value.
	 * @return bool
	 */
	public static function is_author_injection_arg( $key, $value ) {
		return ADC_Security_Firewall_Matchers::is_author_injection_arg( $key, $value );
	}

	/**
	 * @see ADC_Security_Firewall_Matchers::contains_author_injection_arg()
	 * @param mixed $args  Request array.
	 * @param int   $depth Current recursion depth.
	 * @return bool
	 */
	public static function contains_author_injection_arg( $args, $depth = 0 ) {
		return ADC_Security_Firewall_Matchers::contains_author_injection_arg( $args, $depth );
	}
}
