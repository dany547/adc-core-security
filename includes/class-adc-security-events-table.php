<?php
/**
 * ADC Security Events Table Class
 *
 * WP_List_Table subclass powering the Activity tab: paginated, filterable
 * (by event type / severity) view over the adc_security_events table.
 *
 * @package ADCSecurity
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'WP_List_Table' ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

class ADC_Security_Events_Table extends WP_List_Table {

	/**
	 * Human-readable severity labels.
	 *
	 * @var array
	 */
	private static $severity_labels = array(
		0 => 'Info',
		1 => 'Notice',
		2 => 'Warning',
		3 => 'Critical',
	);

	public function __construct() {
		parent::__construct(
			array(
				'singular' => 'adc_security_event',
				'plural'   => 'adc_security_events',
				'ajax'     => false,
			)
		);
	}

	/**
	 * @return array
	 */
	public function get_columns() {
		return array(
			'event_time' => __( 'Time', 'adc-security' ),
			'event_type' => __( 'Type', 'adc-security' ),
			'severity'   => __( 'Severity', 'adc-security' ),
			'username'   => __( 'User', 'adc-security' ),
			'ip'         => __( 'IP Address', 'adc-security' ),
			'object'     => __( 'Details', 'adc-security' ),
		);
	}

	/**
	 * Read the current type/severity filters from the request.
	 *
	 * @return array{type:string,severity:string}
	 */
	private function current_filters() {
		return array(
			'type'     => isset( $_GET['event_type'] ) ? sanitize_key( wp_unslash( $_GET['event_type'] ) ) : '',
			'severity' => isset( $_GET['severity'] ) && '' !== $_GET['severity'] ? (int) $_GET['severity'] : '',
		);
	}

	/**
	 * Fetch rows and set up pagination.
	 */
	public function prepare_items() {
		global $wpdb;

		$table   = ADC_Security_Install::events_table();
		$filters = $this->current_filters();

		$where  = array( '1=1' );
		$params = array();

		if ( '' !== $filters['type'] ) {
			$where[]  = 'event_type = %s';
			$params[] = $filters['type'];
		}

		if ( '' !== $filters['severity'] ) {
			$where[]  = 'severity = %d';
			$params[] = $filters['severity'];
		}

		$where_sql = implode( ' AND ', $where );

		$per_page     = 20;
		$current_page = $this->get_pagenum();

		$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
		$total_items = $params
			? (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) )
			: (int) $wpdb->get_var( $count_sql ); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared

		$list_sql = "SELECT * FROM {$table} WHERE {$where_sql} ORDER BY id DESC LIMIT %d OFFSET %d"; // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName
		$list_params = array_merge( $params, array( $per_page, ( $current_page - 1 ) * $per_page ) );

		$this->items = $wpdb->get_results( $wpdb->prepare( $list_sql, $list_params ), ARRAY_A );

		$this->_column_headers = array( $this->get_columns(), array(), array() );

		$this->set_pagination_args(
			array(
				'total_items' => $total_items,
				'per_page'    => $per_page,
				'total_pages' => (int) ceil( $total_items / $per_page ),
			)
		);
	}

	/**
	 * Render the type/severity filter dropdowns above the table.
	 *
	 * @param string $which 'top' or 'bottom'.
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}

		global $wpdb;
		$table = ADC_Security_Install::events_table();
		$types = $wpdb->get_col( "SELECT DISTINCT event_type FROM {$table} ORDER BY event_type ASC" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedTableName, WordPress.DB.PreparedSQL.NotPrepared

		$filters = $this->current_filters();
		?>
		<div class="alignleft actions">
			<label class="screen-reader-text" for="adc-filter-event-type"><?php esc_html_e( 'Filter by type', 'adc-security' ); ?></label>
			<select name="event_type" id="adc-filter-event-type">
				<option value=""><?php esc_html_e( 'All types', 'adc-security' ); ?></option>
				<?php foreach ( (array) $types as $type ) : ?>
					<option value="<?php echo esc_attr( $type ); ?>" <?php selected( $filters['type'], $type ); ?>><?php echo esc_html( $type ); ?></option>
				<?php endforeach; ?>
			</select>
			<label class="screen-reader-text" for="adc-filter-severity"><?php esc_html_e( 'Filter by severity', 'adc-security' ); ?></label>
			<select name="severity" id="adc-filter-severity">
				<option value=""><?php esc_html_e( 'All severities', 'adc-security' ); ?></option>
				<?php foreach ( self::$severity_labels as $value => $label ) : ?>
					<option value="<?php echo esc_attr( $value ); ?>" <?php selected( (string) $filters['severity'], (string) $value ); ?>><?php echo esc_html( $label ); ?></option>
				<?php endforeach; ?>
			</select>
			<?php submit_button( __( 'Filter', 'adc-security' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * Default per-column cell rendering.
	 *
	 * @param array  $item        Row data.
	 * @param string $column_name Column key.
	 * @return string
	 */
	public function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'event_time':
				return esc_html( $item['event_time'] );
			case 'event_type':
				return esc_html( $item['event_type'] );
			case 'severity':
				$severity = (int) $item['severity'];
				$label    = isset( self::$severity_labels[ $severity ] ) ? self::$severity_labels[ $severity ] : $severity;
				return '<span class="adc-severity adc-severity-' . esc_attr( $severity ) . '">' . esc_html( $label ) . '</span>';
			case 'username':
				return esc_html( $item['username'] );
			case 'ip':
				return esc_html( $item['ip'] );
			case 'object':
				return esc_html( $item['object'] );
			default:
				return '';
		}
	}

	/**
	 * Message shown when there are no rows to display.
	 */
	public function no_items() {
		esc_html_e( 'No activity recorded yet.', 'adc-security' );
	}
}
