rule nosql_injection
{
  meta:
    filetype = "any"
    confidence = "low"
    severity = "high"
    scantype = "file"
    testID = "A001"
    name = "NoSQL Injection"

  strings:
    $where_clause = /\$where.*\n/

  condition:
    $where_clause
}
