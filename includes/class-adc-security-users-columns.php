<?php
/**
 * ADC Security Users Columns
 *
 * Adds two read-only columns to the WordPress Users screen:
 *  - Account created (from the native user_registered field)
 *  - Last login (recorded on wp_login)
 *
 * Both columns are sortable. Sorting by last login keeps users who never
 * logged in in the list by joining the meta table with an EXISTS/NOT EXISTS
 * pair instead of the usual meta_key sort, which would silently hide them.
 *
 * Uses only native WordPress APIs and writes a single piece of user meta.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class ADC_Security_Users_Columns {

	/**
	 * User meta key holding the last successful login timestamp.
	 */
	const LAST_LOGIN_META = '_adc_last_login';

	/**
	 * Query var used as the meta query clause name for last-login sorting.
	 */
	const LAST_LOGIN_CLAUSE = 'adc_last_login';

	/**
	 * Constructor.
	 */
	public function __construct() {
		add_action( 'wp_login', array( $this, 'record_last_login' ), 10, 2 );

		add_filter( 'manage_users_columns', array( $this, 'add_columns' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'render_column' ), 10, 3 );
		add_filter( 'manage_users_sortable_columns', array( $this, 'sortable_columns' ) );
		add_action( 'pre_get_users', array( $this, 'sort_users' ) );
	}

	/**
	 * Store the timestamp of a successful login.
	 *
	 * @param string  $user_login Username (unused).
	 * @param WP_User $user       Logged-in user.
	 */
	public function record_last_login( $user_login, $user = null ) {
		if ( ! $user instanceof WP_User ) {
			return;
		}

		update_user_meta( $user->ID, self::LAST_LOGIN_META, time() );
	}

	/**
	 * Register the two columns.
	 *
	 * @param array $columns Existing columns.
	 * @return array
	 */
	public function add_columns( $columns ) {
		if ( ! current_user_can( 'list_users' ) ) {
			return $columns;
		}

		$columns['account_created'] = __( 'Account Created', 'adc-security' );
		$columns['last_login']      = __( 'Last Login', 'adc-security' );

		return $columns;
	}

	/**
	 * Render the column values. Dynamic data is escaped here; the caller prints
	 * the returned string into an already escaped table cell.
	 *
	 * @param string $output      Value for columns this plugin does not own.
	 * @param string $column_name Column being rendered.
	 * @param int    $user_id     User ID.
	 * @return string
	 */
	public function render_column( $output, $column_name, $user_id ) {
		if ( 'account_created' === $column_name ) {
			$user = get_userdata( $user_id );

			if ( ! $user ) {
				return '&mdash;';
			}

			return esc_html( $this->format_timestamp( strtotime( $user->user_registered . ' UTC' ) ) );
		}

		if ( 'last_login' === $column_name ) {
			$timestamp = (int) get_user_meta( $user_id, self::LAST_LOGIN_META, true );

			if ( $timestamp <= 0 ) {
				return '&mdash;';
			}

			return esc_html( $this->format_timestamp( $timestamp ) );
		}

		return $output;
	}

	/**
	 * Mark both columns as sortable.
	 *
	 * @param array $columns Sortable columns.
	 * @return array
	 */
	public function sortable_columns( $columns ) {
		$columns['account_created'] = 'account_created';
		$columns['last_login']      = 'last_login';

		return $columns;
	}

	/**
	 * Translate the virtual sort keys into a real user query.
	 *
	 * @param WP_User_Query $query Current user query.
	 */
	public function sort_users( $query ) {
		if ( ! $query instanceof WP_User_Query || ! is_admin() || ! current_user_can( 'list_users' ) ) {
			return;
		}

		$orderby = $query->get( 'orderby' );

		if ( 'account_created' === $orderby ) {
			$query->set( 'orderby', 'registered' );
			return;
		}

		if ( 'last_login' !== $orderby ) {
			return;
		}

		$order = 'DESC' === strtoupper( (string) $query->get( 'order' ) ) ? 'DESC' : 'ASC';

		// EXISTS | NOT EXISTS keeps users who never logged in in the result set.
		$last_login_query = array(
			'relation'                           => 'OR',
			self::LAST_LOGIN_CLAUSE              => array(
				'key'     => self::LAST_LOGIN_META,
				'compare' => 'EXISTS',
				'type'    => 'NUMERIC',
			),
			self::LAST_LOGIN_CLAUSE . '_missing' => array(
				'key'     => self::LAST_LOGIN_META,
				'compare' => 'NOT EXISTS',
			),
		);

		$existing = $query->get( 'meta_query' );
		if ( is_array( $existing ) && ! empty( $existing ) ) {
			$query->set(
				'meta_query',
				array(
					'relation' => 'AND',
					$existing,
					$last_login_query,
				)
			);
		} else {
			$query->set( 'meta_query', $last_login_query );
		}

		$query->set( 'orderby', array( self::LAST_LOGIN_CLAUSE => $order ) );
	}

	/**
	 * Format a timestamp in the site's timezone and date/time format.
	 *
	 * @param int $timestamp Unix timestamp.
	 * @return string
	 */
	private function format_timestamp( $timestamp ) {
		if ( (int) $timestamp <= 0 ) {
			return '&mdash;';
		}

		$format = trim( get_option( 'date_format', 'Y-m-d' ) . ' ' . get_option( 'time_format', 'H:i' ) );

		if ( '' === $format ) {
			$format = 'Y-m-d H:i';
		}

		return wp_date( $format, (int) $timestamp );
	}
}
