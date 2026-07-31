view: orders {
  sql_table_name: dw.orders ;;

  dimension: order_id {
    type: number
    sql: ${TABLE}.id ;;
    primary_key: yes
  }

  dimension: country {
    type: string
    sql: ${TABLE}.country ;;
    description: "Buyer country"
  }

  dimension: channel {
    type: string
    sql: ${TABLE}.channel ;;
  }

  dimension_group: created {
    type: time
    timeframes: [date, week, month, quarter, year]
    sql: ${TABLE}.create_time ;;
  }

  measure: revenue {
    type: sum
    sql: ${TABLE}.amount ;;
    description: "Total order amount"
  }

  measure: order_count {
    type: count
    description: "Number of orders"
  }

  measure: avg_order_value {
    type: average
    sql: ${TABLE}.amount ;;
  }
}
