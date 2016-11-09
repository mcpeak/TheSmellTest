rule nosql_injection
{
  meta:
    filetype = "any"
    confidence = "low"
    severity = "high"

  strings:
    $where_clause = /\$where/

  condition:
    $where_clause
}
