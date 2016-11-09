rule ssh_private_key
{
  meta:
    filetype = "any"
    confidence = "high"
    severity = "high"

  strings:
    // begin private key marker, base64, end private key marker
    $private_key = /-----BEGIN RSA PRIVATE KEY-----[\w\d\/\+\n]+-----END RSA PRIVATE KEY-----/

  condition:
    $private_key
}
