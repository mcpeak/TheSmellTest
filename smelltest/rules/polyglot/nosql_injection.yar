rule nosql_injection
{
  meta:
    filetype = "any"
    confidence = "low"
    severity = "high"
    scantype = "line"
    testID = "A001"

  strings:
    $where_clause = /\$where/

  condition:
    $where_clause
}
